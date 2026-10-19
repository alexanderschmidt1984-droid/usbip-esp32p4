/*
 * Transfer Engine - Concurrent URB Forwarding Loop
 *
 * Bridges USB/IP CMD_SUBMIT/CMD_UNLINK from the network to
 * ESP-IDF USB host transfers and sends results back.
 *
 * Uses a pending URB table to support concurrent IN+OUT transfers,
 * which is required for devices like IC programmers that send a
 * command via OUT and expect an immediate response via IN.
 */

#include "transfer_engine.h"
#include "usbip_proto.h"
#include "device_manager.h"
#include "usb_host_mgr.h"
#include "event_log.h"
#if CONFIG_CAPTURE_ENABLED
#include "capture.h"
#endif

#include "usb/usb_host.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_vfs_eventfd.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include <lwip/sockets.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

static const char *TAG = "xfer_eng";

/* Maximum transfer buffer size. Linux usb-storage submits up to 120 KiB per
 * URB (max_sectors 240); clamping IN reads below that leaves the surplus in the
 * device, which then spills into the next URB (CSW) and breaks the stream.
 * Buffers come from internal DMA RAM (PSRAM DMA broke enumeration on rev3.2). */
#define MAX_TRANSFER_SIZE   (128 * 1024)

/* Minimum transfer buffer allocation */
#define MIN_TRANSFER_SIZE   64

/* USB transfer timeout set on the transfer object (ms) */
/* USB transfer timeout - must be long enough for slow operations like
 * chip erase on IC programmers which can take 60+ seconds */
#define USB_XFER_TIMEOUT_MS 0  /* 0 = no timeout (wait indefinitely for USB completion) */

/* Pending URB timeout - how long before we force-abort a stuck transfer.
 * Set high to accommodate slow devices (IC programmer chip erase = 60+ seconds).
 * The client's own timeout (CMD_UNLINK) handles normal cancellation.
 * Only control and OUT transfers: a bulk/interrupt IN may legitimately wait
 * forever (security key waiting for a touch, serial adapter waiting for data). */
#define PENDING_URB_TIMEOUT_US  (120 * 1000 * 1000LL)

/* select() timeout for polling the socket (microseconds).
 * Short while URBs are in flight (completion latency), longer when idle so the
 * engine task doesn't spin at 1 kHz with nothing to do (saves CPU/power).
 * Incoming socket data still wakes select() immediately in both cases. */
#define SELECT_TIMEOUT_US        1000
#define SELECT_TIMEOUT_IDLE_US   20000

/* Maximum concurrent pending URBs */
#define MAX_PENDING_URBS    32

/* Upper bound for isochronous packets per URB. Linux usbip sends at most a few
 * dozen; anything larger is malformed or hostile (and would let a client force
 * huge allocations / an int overflow in the drain length). */
#define MAX_ISO_PACKETS     128

/* Large bulk OUT transfers are split into chunks that go to the device while
 * the rest is still arriving over the network (store-and-forward made the
 * network and USB times add up). The reply still comes after the last chunk. */
#define OUT_CHUNK_SIZE      (16 * 1024)     /* multiple of every bulk MPS (64/512) */
#define OUT_CHUNK_MIN       (32 * 1024)     /* smaller transfers: one USB transfer as before */
#define MAX_OUT_CHUNKS      (MAX_TRANSFER_SIZE / OUT_CHUNK_SIZE)

/* Fast read (experimental, off by default, Settings -> System): large bulk IN
 * transfers are read in chunks with two buffers; while one chunk goes out over
 * the network the next one is read from the device. Only one chunk is on the
 * bus at a time, so a short chunk can never swallow the device's next data
 * (e.g. a mass-storage CSW). The RET_SUBMIT header has to promise the full
 * length after the first chunk: if a later chunk comes back short or with an
 * error, the stream cannot be repaired and the connection is closed. */
#define IN_CHUNK_SIZE       (16 * 1024)
#define IN_FAST_MIN         (32 * 1024)
static bool s_fast_read;

/* Linux errno values (USB/IP client expects these, not ESP-IDF values) */
#define LINUX_EIO           5
#define LINUX_EINVAL        22
#define LINUX_ENODEV        19
#define LINUX_EPIPE         32
#define LINUX_EOVERFLOW     75
#define LINUX_ECONNRESET    104
#define LINUX_ETIMEDOUT     110

/* ------------------------------------------------------------------ */
/* Pending URB table                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    bool active;
    int owner_fd;   /* owning client connection fd; isolates the shared table per-connection */
    uint32_t seqnum;
    uint32_t devid;
    uint32_t direction;
    uint32_t ep;
    int32_t buflen;
    int32_t num_iso;
    int64_t submit_time_us;
    usb_transfer_t *xfer;
    SemaphoreHandle_t sem;
    usb_transfer_status_t usb_status;
    bool is_control;
    int dev_index;  // device_manager index for stats updates
    /* Set when a cancel could not confirm completion: the transfer may still be
     * in flight inside the USB stack, so xfer/sem must NOT be freed yet (the
     * completion callback still points at this slot). The slot stays reserved
     * (owner_fd = -1) and is reaped once the callback has fired. */
    bool orphaned;
    /* Chunked bulk OUT (n_chunks > 0): xfer is chunk 0, chunk[] the rest.
     * chunks_left counts submitted chunks still in flight plus a guard of 1
     * held while submitting; the slot completes when it reaches 0. */
    int n_chunks;
    usb_transfer_t *chunk[MAX_OUT_CHUNKS];
    int chunks_left;
    int32_t chunk_bytes;
    usb_transfer_status_t chunk_status;
    bool chunk_flushed;
    /* Fast read (rd_fast): two transfers alternate, xfer is the one in flight */
    bool rd_fast;
    bool rd_hdr_sent;
    bool rd_inflight;             /* a chunk is on the bus (callback pending) */
    int rd_cur;
    int32_t rd_done;              /* bytes already sent to the client */
    uint16_t rd_mps;
    usb_transfer_t *rd_x[2];
} pending_urb_t;

static pending_urb_t s_pending[MAX_PENDING_URBS];
/* Guards slot allocation in the shared table: multiple client connections run
 * concurrent transfer engines against this one array. */
static portMUX_TYPE s_pending_lock = portMUX_INITIALIZER_UNLOCKED;

/* ------------------------------------------------------------------ */
/* Transfer callback                                                   */
/* ------------------------------------------------------------------ */

/**
 * @brief USB transfer completion callback.
 * Runs in USB host task context (Core 0). Only signals the semaphore.
 */
/*
 * Wake-up of the owning connection's loop on completion. Each running engine
 * registers an eventfd for its socket; transfer_cb() writes to it so select()
 * returns at once instead of after the next poll timeout (up to 1 ms per URB
 * stage, which added up on mass-storage reads). Optional: without an eventfd
 * the poll timeouts still pick up every completion as before.
 * The mutex keeps a callback from writing to an eventfd that is being closed.
 */
#define WAKE_SLOTS 8
static struct { int sockfd; int evfd; } s_wake[WAKE_SLOTS];
static SemaphoreHandle_t s_wake_mtx;
static bool s_eventfd_ok;

static int wake_register(int sockfd)
{
    if (!s_eventfd_ok || !s_wake_mtx) return -1;
    int evfd = eventfd(0, 0);
    if (evfd < 0) return -1;
    xSemaphoreTake(s_wake_mtx, portMAX_DELAY);
    for (int i = 0; i < WAKE_SLOTS; i++) {
        if (s_wake[i].evfd < 0) {
            s_wake[i].sockfd = sockfd;
            s_wake[i].evfd = evfd;
            xSemaphoreGive(s_wake_mtx);
            return evfd;
        }
    }
    xSemaphoreGive(s_wake_mtx);
    close(evfd);
    return -1;
}

static void wake_unregister(int evfd)
{
    if (evfd < 0) return;
    xSemaphoreTake(s_wake_mtx, portMAX_DELAY);
    for (int i = 0; i < WAKE_SLOTS; i++) {
        if (s_wake[i].evfd == evfd) {
            s_wake[i].evfd = -1;
            s_wake[i].sockfd = -1;
        }
    }
    xSemaphoreGive(s_wake_mtx);
    close(evfd);
}

static void wake_owner(int owner_fd)
{
    if (owner_fd < 0 || !s_wake_mtx) return;      /* orphaned slot: nobody waits */
    xSemaphoreTake(s_wake_mtx, portMAX_DELAY);
    for (int i = 0; i < WAKE_SLOTS; i++) {
        if (s_wake[i].evfd >= 0 && s_wake[i].sockfd == owner_fd) {
            uint64_t one = 1;
            write(s_wake[i].evfd, &one, sizeof(one));
            break;
        }
    }
    xSemaphoreGive(s_wake_mtx);
}

/* One chunk (or the submit guard) of a chunked OUT is done; the last one
 * completes the slot with the summed length and the first error. */
static void chunk_settle(pending_urb_t *slot, usb_transfer_status_t st, int bytes)
{
    bool last;
    portENTER_CRITICAL(&s_pending_lock);
    slot->chunk_bytes += bytes;
    if (st != USB_TRANSFER_STATUS_COMPLETED && slot->chunk_status == USB_TRANSFER_STATUS_COMPLETED) {
        slot->chunk_status = st;
    }
    last = (--slot->chunks_left == 0);
    portEXIT_CRITICAL(&s_pending_lock);
    if (last) {
        slot->usb_status = slot->chunk_status;
        xSemaphoreGive(slot->sem);
        wake_owner(slot->owner_fd);
    }
}

static void transfer_cb(usb_transfer_t *transfer)
{
    pending_urb_t *slot = (pending_urb_t *)transfer->context;
    if (slot && slot->n_chunks > 0) {
        chunk_settle(slot, transfer->status, transfer->actual_num_bytes);
        return;
    }
    if (slot) {
        slot->usb_status = transfer->status;
        xSemaphoreGive(slot->sem);
        wake_owner(slot->owner_fd);
    }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

/**
 * @brief Map ESP-IDF USB transfer status to Linux errno.
 */
static int32_t map_usb_status(usb_transfer_status_t status)
{
    switch (status) {
    case USB_TRANSFER_STATUS_COMPLETED: return 0;
    case USB_TRANSFER_STATUS_ERROR:     return -LINUX_EIO;
    case USB_TRANSFER_STATUS_TIMED_OUT: return -LINUX_ETIMEDOUT;
    case USB_TRANSFER_STATUS_CANCELED:  return -LINUX_ECONNRESET;
    case USB_TRANSFER_STATUS_STALL:     return -LINUX_EPIPE;
    case USB_TRANSFER_STATUS_NO_DEVICE: return -LINUX_ENODEV;
    case USB_TRANSFER_STATUS_OVERFLOW:  return -LINUX_EOVERFLOW;
    default:                            return -LINUX_EIO;
    }
}

/**
 * @brief Drain (discard) bytes from socket to keep the stream in sync.
 */
static int drain_socket(int fd, int nbytes)
{
    uint8_t tmp[256];
    while (nbytes > 0) {
        int chunk = nbytes > (int)sizeof(tmp) ? (int)sizeof(tmp) : nbytes;
        int ret = usbip_net_recv(fd, tmp, chunk);
        if (ret != 0) {
            return -1;
        }
        nbytes -= chunk;
    }
    return 0;
}

/**
 * @brief Find a free slot in the pending URB table.
 * @return slot index, or -1 if full
 */
static int reserve_free_slot(int fd, uint32_t seqnum)
{
    int idx = -1;
    portENTER_CRITICAL(&s_pending_lock);
    for (int i = 0; i < MAX_PENDING_URBS; i++) {
        if (!s_pending[i].active) {
            /* Reserve under the lock so two connection tasks can't grab the same
             * slot, and stamp the owner so other connections skip it. */
            s_pending[i].active   = true;
            s_pending[i].owner_fd = fd;
            s_pending[i].seqnum   = seqnum;
            idx = i;
            break;
        }
    }
    portEXIT_CRITICAL(&s_pending_lock);
    return idx;
}

/**
 * @brief Find a pending URB by seqnum.
 * @return slot index, or -1 if not found
 */
static int find_pending_by_seqnum(uint32_t seqnum, int fd)
{
    for (int i = 0; i < MAX_PENDING_URBS; i++) {
        if (s_pending[i].active && s_pending[i].owner_fd == fd &&
            s_pending[i].seqnum == seqnum) {
            return i;
        }
    }
    return -1;
}

/**
 * @brief Look up an endpoint's max packet size from the device's config descriptor.
 * @return wMaxPacketSize for the endpoint, or 0 if not found.
 */
static uint16_t find_ep_mps(const dm_device_info_t *devinfo, uint8_t ep_addr)
{
    if (!devinfo || !devinfo->config_desc_raw || devinfo->config_desc_len == 0) {
        return 0;
    }
    const usb_config_desc_t *cfg = (const usb_config_desc_t *)devinfo->config_desc_raw;
    const usb_standard_desc_t *d = (const usb_standard_desc_t *)cfg;
    int offset = 0;
    while ((d = usb_parse_next_descriptor_of_type(
                    d, cfg->wTotalLength, USB_B_DESCRIPTOR_TYPE_ENDPOINT, &offset)) != NULL) {
        const usb_ep_desc_t *ep = (const usb_ep_desc_t *)d;
        if (ep->bEndpointAddress == ep_addr) {
            return USB_EP_DESC_GET_MPS(ep);
        }
    }
    return 0;
}

/**
 * @brief Send an error RET_SUBMIT reply (no transfer data).
 * Per spec: devid, direction, ep shall be 0 for server responses.
 * number_of_packets shall be 0xFFFFFFFF for non-ISO.
 */
static int send_error_reply(int fd, uint32_t seqnum, int32_t status)
{
    usbip_header_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.base.command   = USBIP_RET_SUBMIT;
    reply.base.seqnum    = seqnum;
    reply.base.devid     = 0;
    reply.base.direction = 0;
    reply.base.ep        = 0;
    reply.u.ret_submit.status = status;
    reply.u.ret_submit.number_of_packets = (int32_t)0xFFFFFFFF;
    usbip_pack_header(&reply, true);
    return usbip_net_send(fd, &reply, sizeof(reply));
}

/**
 * @brief Cancel a pending URB slot.
 * @param slot       The pending URB slot
 * @param dev_handle USB device handle (may be NULL if device removed)
 * @param force      If true, halt/flush/clear the endpoint (for timeouts/cleanup).
 *                   If false, just wait for the transfer to complete on its own
 *                   (for CMD_UNLINK - avoids changing endpoint state on device).
 */
static bool cancel_pending_urb(pending_urb_t *slot, usb_device_handle_t dev_handle, bool force)
{
    bool done = false;
    if (!slot->is_control && dev_handle) {
        if (!force) {
            /* Gentle cancel: wait briefly for the transfer to complete naturally.
             * This avoids halting the endpoint which could interfere with device protocol. */
            if (xSemaphoreTake(slot->sem, pdMS_TO_TICKS(500)) == pdTRUE) {
                return true; /* Transfer completed naturally */
            }
            /* Transfer didn't complete in 500ms - MUST force-cancel to prevent
             * use-after-free when we free the slot but the transfer is still in-flight. */
            ESP_LOGW(TAG, "Gentle cancel failed for seqnum=%lu, forcing halt/flush/clear",
                     (unsigned long)slot->seqnum);
        }
        uint8_t ep_addr = slot->xfer->bEndpointAddress;
        usb_host_endpoint_halt(dev_handle, ep_addr);
        usb_host_endpoint_flush(dev_handle, ep_addr);
        /* Wait for the canceled callback */
        done = (xSemaphoreTake(slot->sem, pdMS_TO_TICKS(1000)) == pdTRUE);
        usb_host_endpoint_clear(dev_handle, ep_addr);
    } else if (!slot->is_control) {
        /* No device handle (device already removed) - just wait for callback.
         * The USB host stack should fire the callback with error status. */
        done = (xSemaphoreTake(slot->sem, pdMS_TO_TICKS(2000)) == pdTRUE);
    } else {
        /* EP0 control: wait for USB stack's own timeout */
        done = (xSemaphoreTake(slot->sem, pdMS_TO_TICKS(6000)) == pdTRUE);
    }
    return done;
}

/**
 * @brief Free resources for a pending URB slot and mark it inactive.
 */
static void free_pending_slot(pending_urb_t *slot)
{
    if (slot->sem) {
        vSemaphoreDelete(slot->sem);
        slot->sem = NULL;
    }
    if (slot->rd_fast) {
        for (int i = 0; i < 2; i++) {
            if (slot->rd_x[i]) usb_host_transfer_free(slot->rd_x[i]);
            slot->rd_x[i] = NULL;
        }
        slot->xfer = NULL;          /* was one of rd_x */
        slot->rd_fast = false;
    }
    if (slot->xfer) {
        usb_host_transfer_free(slot->xfer);
        slot->xfer = NULL;
    }
    for (int i = 0; i < MAX_OUT_CHUNKS; i++) {
        if (slot->chunk[i]) {
            usb_host_transfer_free(slot->chunk[i]);
            slot->chunk[i] = NULL;
        }
    }
    slot->n_chunks = 0;
    slot->orphaned = false;
    slot->active = false;
}

/**
 * @brief Release a slot after a cancel attempt.
 *
 * If the cancel confirmed completion, the slot is freed normally. Otherwise the
 * transfer may still be in flight: freeing xfer/sem now would be a
 * use-after-free when the USB stack later completes it (transfer_cb writes to
 * slot->usb_status and gives slot->sem, and the stack still owns xfer). Park the
 * slot as an orphan instead; reap_orphans() frees it once the callback fired.
 */
static void release_after_cancel(pending_urb_t *slot, bool done)
{
    if (done) {
        free_pending_slot(slot);
        return;
    }
    ESP_LOGW(TAG, "URB seqnum=%lu still in flight after cancel; parking until completion",
             (unsigned long)slot->seqnum);
    portENTER_CRITICAL(&s_pending_lock);
    slot->orphaned = true;
    slot->owner_fd = -1;   /* no connection polls it any more */
    portEXIT_CRITICAL(&s_pending_lock);
}

/**
 * @brief Free orphaned slots whose transfer has finally completed.
 * Safe to call from any connection task.
 */
static void reap_orphans(void)
{
    for (int i = 0; i < MAX_PENDING_URBS; i++) {
        pending_urb_t *slot = &s_pending[i];
        /* Claim the orphan under the lock (owner_fd -1 -> -2) so two connection
         * tasks never touch/free the same slot concurrently. */
        bool claimed = false;
        portENTER_CRITICAL(&s_pending_lock);
        if (slot->active && slot->orphaned && slot->owner_fd == -1) {
            slot->owner_fd = -2;
            claimed = true;
        }
        portEXIT_CRITICAL(&s_pending_lock);
        if (!claimed) {
            continue;
        }
        if (slot->sem && xSemaphoreTake(slot->sem, 0) == pdTRUE) {
            ESP_LOGI(TAG, "Reaped orphaned URB seqnum=%lu", (unsigned long)slot->seqnum);
            free_pending_slot(slot);
        } else {
            portENTER_CRITICAL(&s_pending_lock);
            slot->owner_fd = -1;   /* still in flight - try again later */
            portEXIT_CRITICAL(&s_pending_lock);
        }
    }
}

/**
 * @brief Send RET_SUBMIT for a completed pending URB.
 * @return 0 on success, -1 on socket error
 */
static int send_completed_reply(int fd, pending_urb_t *slot, usb_device_handle_t dev_handle)
{
    int32_t reply_status = map_usb_status(slot->usb_status);
    int32_t actual_length = 0;
    int32_t reply_num_packets = 0;
    int32_t reply_error_count = 0;

    /* After a STALL, ESP-IDF puts the endpoint pipe into halted state.
     * We must clear it so subsequent transfers can be submitted.
     * This mirrors Linux kernel behavior: usb_clear_halt(). */
    if (slot->usb_status == USB_TRANSFER_STATUS_STALL && !slot->is_control && dev_handle) {
        uint8_t ep_addr = slot->xfer->bEndpointAddress;
        usb_host_endpoint_halt(dev_handle, ep_addr);
        usb_host_endpoint_flush(dev_handle, ep_addr);
        usb_host_endpoint_clear(dev_handle, ep_addr);
        ESP_LOGD(TAG, "Cleared STALL on ep 0x%02x", ep_addr);
    }

    if (reply_status == 0) {
        actual_length = slot->n_chunks > 0 ? slot->chunk_bytes : slot->xfer->actual_num_bytes;
        if (slot->is_control && actual_length >= 8) {
            actual_length -= 8; /* subtract setup packet */
        } else if (slot->is_control) {
            actual_length = 0;
        }
        /* IN buffers are rounded up to the MPS, so a device can return more
         * than the client asked for. vhci drops the whole connection on
         * actual_length > transfer_buffer_length; report babble instead. */
        if (actual_length > slot->buflen) {
            ESP_LOGW(TAG, "seqnum=%lu: device returned %ld bytes > requested %ld (overflow)",
                     (unsigned long)slot->seqnum, (long)actual_length, (long)slot->buflen);
            reply_status = -LINUX_EOVERFLOW;
            actual_length = 0;
        }
    }

    /* Handle ISO results */
    if (slot->num_iso > 0) {
        reply_num_packets = slot->num_iso;
        for (int i = 0; i < slot->num_iso; i++) {
            if (slot->xfer->isoc_packet_desc[i].status != USB_TRANSFER_STATUS_COMPLETED) {
                reply_error_count++;
            }
        }
    }

    /* Build RET_SUBMIT reply per USB/IP spec:
     * - devid, direction, ep: shall be 0 for server responses
     * - number_of_packets: 0xFFFFFFFF if not ISO transfer */
    usbip_header_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.base.command              = USBIP_RET_SUBMIT;
    reply.base.seqnum               = slot->seqnum;
    reply.base.devid                = 0;
    reply.base.direction            = 0;
    reply.base.ep                   = 0;
    reply.u.ret_submit.status       = reply_status;
    reply.u.ret_submit.actual_length = actual_length;
    reply.u.ret_submit.start_frame  = 0;
    reply.u.ret_submit.number_of_packets = (slot->num_iso > 0) ? reply_num_packets : (int32_t)0xFFFFFFFF;
    reply.u.ret_submit.error_count  = reply_error_count;

    /* Capture RET_SUBMIT packet (before packing to network order) */
#if CONFIG_CAPTURE_ENABLED
    {
        uint8_t *in_data = NULL;
        uint32_t in_len = 0;
        if (slot->direction == USBIP_DIR_IN && actual_length > 0 && reply_status == 0) {
            in_data = slot->is_control ? (slot->xfer->data_buffer + 8) : slot->xfer->data_buffer;
            in_len = (uint32_t)actual_length;
        }
        capture_submit_packet(CAPTURE_DIR_SERVER_TO_CLIENT,
                              &reply, sizeof(reply), in_data, in_len);
    }
#endif

    usbip_pack_header(&reply, true);

    /* Send header */
    if (usbip_net_send(fd, &reply, sizeof(reply)) != 0) {
        ESP_LOGE(TAG, "Failed to send RET_SUBMIT header");
        return -1;
    }

    /* For IN transfers with data: send the payload */
    if (slot->direction == USBIP_DIR_IN && actual_length > 0 && reply_status == 0) {
        uint8_t *src = slot->is_control ? (slot->xfer->data_buffer + 8) : slot->xfer->data_buffer;
        if (usbip_net_send(fd, src, actual_length) != 0) {
            ESP_LOGE(TAG, "Failed to send IN data");
            return -1;
        }
    }

    /* For ISO: send ISO packet descriptors */
    if (slot->num_iso > 0) {
        for (int i = 0; i < slot->num_iso; i++) {
            usbip_iso_packet_descriptor_t iso_desc;
            iso_desc.offset        = 0;
            iso_desc.length        = slot->xfer->isoc_packet_desc[i].num_bytes;
            iso_desc.actual_length = slot->xfer->isoc_packet_desc[i].actual_num_bytes;
            iso_desc.status        = (uint32_t)map_usb_status(slot->xfer->isoc_packet_desc[i].status);
            usbip_pack_iso_descriptor(&iso_desc, true); /* host -> network */
            if (usbip_net_send(fd, &iso_desc, sizeof(iso_desc)) != 0) {
                ESP_LOGE(TAG, "Failed to send ISO descriptors");
                return -1;
            }
        }
    }

    /* Log every transfer at INFO level for debugging */
    if (reply_status == 0) {
        ESP_LOGD(TAG, "URB seqnum=%lu ep=0x%02x %s len=%ld ok",
                 (unsigned long)slot->seqnum,
                 (unsigned)(slot->ep | (slot->direction == USBIP_DIR_IN ? 0x80 : 0x00)),
                 slot->direction == USBIP_DIR_IN ? "IN" : "OUT",
                 (long)actual_length);
    } else {
        ESP_LOGW(TAG, "URB seqnum=%lu ep=0x%02x %s len=%ld status=%ld",
                 (unsigned long)slot->seqnum,
                 (unsigned)(slot->ep | (slot->direction == USBIP_DIR_IN ? 0x80 : 0x00)),
                 slot->direction == USBIP_DIR_IN ? "IN" : "OUT",
                 (long)actual_length,
                 (long)reply_status);
    }

    /* Update per-device throughput / error stats for WebUI */
    device_manager_update_stats(slot->dev_index,
        (slot->direction == USBIP_DIR_IN && reply_status == 0) ? (uint32_t)actual_length : 0,
        (slot->direction == USBIP_DIR_OUT && reply_status == 0) ? (uint32_t)slot->buflen : 0,
        reply_status == 0);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Fast read (experimental)                                            */
/* ------------------------------------------------------------------ */

bool transfer_engine_get_fast_read(void) { return s_fast_read; }

esp_err_t transfer_engine_set_fast_read(bool on)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open("usb", NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = nvs_set_u8(nvs, "fastrd", on ? 1 : 0);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    if (err == ESP_OK) {
        s_fast_read = on;
        ESP_LOGI(TAG, "Fast read (experimental) %s", on ? "on" : "off");
    }
    return err;
}

static int send_ret_submit_hdr(int fd, uint32_t seqnum, int32_t status, int32_t actual)
{
    usbip_header_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.base.command = USBIP_RET_SUBMIT;
    reply.base.seqnum = seqnum;
    reply.u.ret_submit.status = status;
    reply.u.ret_submit.actual_length = actual;
    reply.u.ret_submit.number_of_packets = (int32_t)0xFFFFFFFF;
    usbip_pack_header(&reply, true);
    return usbip_net_send(fd, &reply, sizeof(reply));
}

/* Length to request for the chunk starting at byte `done` (rounded up to the
 * MPS; the device must not deliver more than the client asked for). */
static int fast_chunk_len(const pending_urb_t *slot, int32_t done, int32_t *want)
{
    int32_t rem = slot->buflen - done;
    *want = rem < IN_CHUNK_SIZE ? rem : IN_CHUNK_SIZE;
    return (*want + slot->rd_mps - 1) / slot->rd_mps * slot->rd_mps;
}

static int handle_in_fast(int fd, usbip_header_t *hdr, const dm_device_info_t *devinfo,
                          int dev_index, uint32_t ep, int32_t buflen, uint16_t mps)
{
    uint32_t seqnum = hdr->base.seqnum;
    int slot_idx = reserve_free_slot(fd, seqnum);
    if (slot_idx < 0) {
        ESP_LOGE(TAG, "Pending URB table full (%d slots)", MAX_PENDING_URBS);
        send_error_reply(fd, seqnum, -LINUX_EIO);
        return 0;
    }
    pending_urb_t *slot = &s_pending[slot_idx];
    usb_device_handle_t dev_handle = usb_host_mgr_get_handle(devinfo->dev_addr);
    SemaphoreHandle_t sem = xSemaphoreCreateBinary();
    usb_transfer_t *x[2] = { NULL, NULL };
    bool ok = dev_handle && sem &&
              usb_host_transfer_alloc(IN_CHUNK_SIZE, 0, &x[0]) == ESP_OK &&
              usb_host_transfer_alloc(IN_CHUNK_SIZE, 0, &x[1]) == ESP_OK;
    if (!ok) {
        for (int i = 0; i < 2; i++) if (x[i]) usb_host_transfer_free(x[i]);
        if (sem) vSemaphoreDelete(sem);
        free_pending_slot(slot);
        send_error_reply(fd, seqnum, dev_handle ? -LINUX_EIO : -LINUX_ENODEV);
        return 0;
    }
    for (int i = 0; i < 2; i++) {
        x[i]->device_handle    = dev_handle;
        x[i]->callback         = transfer_cb;
        x[i]->context          = slot;
        x[i]->timeout_ms       = USB_XFER_TIMEOUT_MS;
        x[i]->bEndpointAddress = (uint8_t)(ep | 0x80);
    }
    slot->devid          = hdr->base.devid;
    slot->direction      = USBIP_DIR_IN;
    slot->ep             = ep;
    slot->buflen         = buflen;
    slot->num_iso        = 0;
    slot->submit_time_us = esp_timer_get_time();
    slot->sem            = sem;
    slot->usb_status     = USB_TRANSFER_STATUS_ERROR;
    slot->is_control     = false;
    slot->dev_index      = dev_index;
    slot->rd_fast        = true;
    slot->rd_hdr_sent    = false;
    slot->rd_cur         = 0;
    slot->rd_done        = 0;
    slot->rd_mps         = mps;
    slot->rd_x[0]        = x[0];
    slot->rd_x[1]        = x[1];
    slot->xfer           = x[0];

    int32_t want;
    x[0]->num_bytes = fast_chunk_len(slot, 0, &want);
    slot->rd_inflight = true;
    if (usb_host_transfer_submit(x[0]) != ESP_OK) {
        slot->rd_inflight = false;
        ESP_LOGE(TAG, "Transfer submit failed (fast read, ep=0x%02x)", (unsigned)(ep | 0x80));
        free_pending_slot(slot);
        send_error_reply(fd, seqnum, -LINUX_EIO);
    }
    return 0;
}

/* A fast-read chunk completed. Returns 0 = more to come, 1 = finished (free
 * the slot), -1 = connection must be closed. */
static int fast_read_step(int fd, pending_urb_t *slot)
{
    usb_transfer_t *t = slot->xfer;
    slot->rd_inflight = false;                /* its callback fired */
    int32_t want;
    fast_chunk_len(slot, slot->rd_done, &want);
    int32_t got = t->actual_num_bytes;
    bool ok = slot->usb_status == USB_TRANSFER_STATUS_COMPLETED && got <= want;
    bool full = ok && got == want;
    bool more = full && slot->rd_done + got < slot->buflen;

    if (more) {                               /* read the next chunk while this one is sent */
        usb_transfer_t *nx = slot->rd_x[1 - slot->rd_cur];
        int32_t nwant;
        nx->num_bytes = fast_chunk_len(slot, slot->rd_done + got, &nwant);
        slot->usb_status = USB_TRANSFER_STATUS_ERROR;
        slot->xfer = nx;
        slot->rd_cur = 1 - slot->rd_cur;
        slot->rd_inflight = true;
        if (usb_host_transfer_submit(nx) != ESP_OK) {
            slot->rd_inflight = false;
            slot->xfer = t;
            slot->rd_cur = 1 - slot->rd_cur;
            more = false;
        }
    }

    if (!slot->rd_hdr_sent) {
        if (!more) {
            /* Nothing promised yet: plain reply with what we have. */
            int32_t status = ok ? 0 : map_usb_status(slot->usb_status);
            int32_t len = ok ? got : 0;
            if (send_ret_submit_hdr(fd, slot->seqnum, status, len) != 0 ||
                (len > 0 && usbip_net_send(fd, t->data_buffer, len) != 0)) {
                return -1;
            }
            device_manager_update_stats(slot->dev_index, status == 0 ? (uint32_t)len : 0, 0, status == 0);
            return 1;
        }
        if (send_ret_submit_hdr(fd, slot->seqnum, 0, slot->buflen) != 0) return -1;
        slot->rd_hdr_sent = true;
    }

    if (got > 0 && ok && usbip_net_send(fd, t->data_buffer, got) != 0) return -1;
    if (ok) slot->rd_done += got;

    if (slot->rd_done == slot->buflen) {
        device_manager_update_stats(slot->dev_index, (uint32_t)slot->buflen, 0, true);
        return 1;
    }
    if (!more) {
        /* Header already promised the full length but the device ended early
         * or failed: the stream cannot be repaired. */
        ESP_LOGW(TAG, "Fast read seqnum=%lu: device returned %ld of %ld bytes (status %d) - "
                 "closing connection", (unsigned long)slot->seqnum, (long)(slot->rd_done),
                 (long)slot->buflen, (int)slot->usb_status);
        event_log_add(EVENT_LOG_LEVEL_WARN, "Fast read: short read mid-stream, connection closed");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Chunked bulk OUT                                                    */
/* ------------------------------------------------------------------ */

static bool ep_is_bulk(const dm_device_info_t *devinfo, uint8_t ep_addr)
{
    if (!devinfo || !devinfo->config_desc_raw || devinfo->config_desc_len == 0) {
        return false;
    }
    const usb_config_desc_t *cfg = (const usb_config_desc_t *)devinfo->config_desc_raw;
    const usb_standard_desc_t *d = (const usb_standard_desc_t *)cfg;
    int offset = 0;
    while ((d = usb_parse_next_descriptor_of_type(
                    d, cfg->wTotalLength, USB_B_DESCRIPTOR_TYPE_ENDPOINT, &offset)) != NULL) {
        const usb_ep_desc_t *ep = (const usb_ep_desc_t *)d;
        if (ep->bEndpointAddress == ep_addr) {
            return (ep->bmAttributes & USB_BM_ATTRIBUTES_XFERTYPE_MASK) == USB_BM_ATTRIBUTES_XFER_BULK;
        }
    }
    return false;
}

/* Receive a large bulk OUT payload chunk by chunk and submit each chunk as
 * soon as it is in, so the device writes while the rest is on the wire. The
 * endpoint queue keeps the order; RET_SUBMIT is sent by the normal completion
 * path once every chunk is done. Returns -1 only on a socket error. */
static int handle_out_chunked(int fd, usbip_header_t *hdr, const dm_device_info_t *devinfo,
                              int dev_index, uint32_t ep, int32_t buflen)
{
    uint32_t seqnum = hdr->base.seqnum;
    int n = (buflen + OUT_CHUNK_SIZE - 1) / OUT_CHUNK_SIZE;

    int slot_idx = reserve_free_slot(fd, seqnum);
    if (slot_idx < 0) {
        ESP_LOGE(TAG, "Pending URB table full (%d slots)", MAX_PENDING_URBS);
        if (drain_socket(fd, buflen) != 0) return -1;
        send_error_reply(fd, seqnum, -LINUX_EIO);
        return 0;
    }
    pending_urb_t *slot = &s_pending[slot_idx];

    usb_device_handle_t dev_handle = usb_host_mgr_get_handle(devinfo->dev_addr);
    SemaphoreHandle_t sem = xSemaphoreCreateBinary();
    usb_transfer_t *x[MAX_OUT_CHUNKS] = { 0 };
    bool ok = dev_handle && sem;
    for (int i = 0; i < n && ok; i++) {
        int len = (i < n - 1) ? OUT_CHUNK_SIZE : buflen - i * OUT_CHUNK_SIZE;
        ok = usb_host_transfer_alloc(len, 0, &x[i]) == ESP_OK && x[i];
    }
    if (!ok) {
        for (int i = 0; i < n; i++) if (x[i]) usb_host_transfer_free(x[i]);
        if (sem) vSemaphoreDelete(sem);
        free_pending_slot(slot);
        if (drain_socket(fd, buflen) != 0) return -1;
        send_error_reply(fd, seqnum, dev_handle ? -LINUX_EIO : -LINUX_ENODEV);
        return 0;
    }

    slot->devid          = hdr->base.devid;
    slot->direction      = USBIP_DIR_OUT;
    slot->ep             = ep;
    slot->buflen         = buflen;
    slot->num_iso        = 0;
    slot->submit_time_us = esp_timer_get_time();
    slot->sem            = sem;
    slot->usb_status     = USB_TRANSFER_STATUS_ERROR;
    slot->is_control     = false;
    slot->dev_index      = dev_index;
    slot->chunk_bytes    = 0;
    slot->chunk_status   = USB_TRANSFER_STATUS_COMPLETED;
    slot->chunks_left    = 1;                       /* submit guard */
    slot->chunk_flushed  = false;
    slot->xfer           = x[0];
    for (int i = 1; i < n; i++) slot->chunk[i] = x[i];
    slot->n_chunks       = n;

    int32_t received = 0;
    for (int i = 0; i < n; i++) {
        usb_transfer_t *t = x[i];
        int len = (i < n - 1) ? OUT_CHUNK_SIZE : buflen - i * OUT_CHUNK_SIZE;
        t->device_handle    = dev_handle;
        t->callback         = transfer_cb;
        t->context          = slot;
        t->timeout_ms       = USB_XFER_TIMEOUT_MS;
        t->bEndpointAddress = (uint8_t)ep;
        t->num_bytes        = len;
        if (usbip_net_recv(fd, t->data_buffer, len) != 0) {
            ESP_LOGE(TAG, "Failed to recv OUT data");
            chunk_settle(slot, USB_TRANSFER_STATUS_ERROR, 0);   /* drop the guard; cleanup cancels the rest */
            return -1;
        }
        received += len;
        portENTER_CRITICAL(&s_pending_lock);
        slot->chunks_left++;
        portEXIT_CRITICAL(&s_pending_lock);
        if (usb_host_transfer_submit(t) != ESP_OK) {
            ESP_LOGE(TAG, "Transfer submit failed (chunk %d/%d, ep=0x%02x)", i + 1, n, (unsigned)ep);
            chunk_settle(slot, USB_TRANSFER_STATUS_ERROR, 0);   /* this chunk never went out */
            if (drain_socket(fd, buflen - received) != 0) {
                chunk_settle(slot, USB_TRANSFER_STATUS_ERROR, 0);
                return -1;
            }
            break;                                             /* reply -EIO once the rest is done */
        }
    }
    chunk_settle(slot, USB_TRANSFER_STATUS_COMPLETED, 0);       /* release the guard */
    return 0;
}

/* ------------------------------------------------------------------ */
/* CMD_SUBMIT handler (non-blocking: submit and store in pending)      */
/* ------------------------------------------------------------------ */

static int handle_cmd_submit(int fd, usbip_header_t *hdr, const dm_device_info_t *devinfo, int dev_index)
{
    uint32_t seqnum   = hdr->base.seqnum;
    uint32_t ep       = hdr->base.ep;
    uint32_t direction = hdr->base.direction;
    int32_t  buflen   = hdr->u.cmd_submit.transfer_buffer_length;
    int32_t  num_iso  = hdr->u.cmd_submit.number_of_packets;

    /* Per spec: number_of_packets is 0xFFFFFFFF for non-ISO transfers */
    if (num_iso == (int32_t)0xFFFFFFFF) {
        num_iso = 0;
    }

    ESP_LOGD(TAG, "CMD_SUBMIT seq=%lu ep=%lu dir=%s buflen=%ld flags=0x%08lx",
             (unsigned long)seqnum, (unsigned long)ep,
             direction == USBIP_DIR_IN ? "IN" : "OUT",
             (long)buflen, (unsigned long)hdr->u.cmd_submit.transfer_flags);

    /* Validate packet count. A bogus value can't be resynchronised reliably
     * (drain length num_iso*16 could overflow), so drop the connection. */
    if (num_iso < 0 || num_iso > MAX_ISO_PACKETS) {
        ESP_LOGE(TAG, "CMD_SUBMIT seqnum=%lu: invalid number_of_packets %ld, closing",
                 (unsigned long)seqnum, (long)num_iso);
        return -1;
    }
    if (buflen < 0) {
        ESP_LOGE(TAG, "CMD_SUBMIT seqnum=%lu: negative transfer_buffer_length, closing",
                 (unsigned long)seqnum);
        return -1;
    }
    /* OUT data longer than our buffer used to be silently truncated while the
     * surplus bytes stayed in the socket and were then parsed as the next
     * header (stream desync). Consume the payload and fail the URB instead. */
    if (direction == USBIP_DIR_OUT && buflen > MAX_TRANSFER_SIZE) {
        ESP_LOGW(TAG, "CMD_SUBMIT seqnum=%lu: OUT length %ld > %d, rejecting",
                 (unsigned long)seqnum, (long)buflen, MAX_TRANSFER_SIZE);
        if (drain_socket(fd, buflen) != 0) {
            return -1;
        }
        if (num_iso > 0 && drain_socket(fd, num_iso * 16) != 0) {
            return -1;
        }
        send_error_reply(fd, seqnum, -LINUX_EINVAL);
        return 0;
    }
    /* IN requests larger than our buffer are clamped (short read), as before. */
    if (buflen > MAX_TRANSFER_SIZE) buflen = MAX_TRANSFER_SIZE;

    /* Intercept SET_INTERFACE (bmRequestType=0x01, bRequest=0x0B). ESP-IDF brings
     * up an alternate setting's endpoints only via usb_host_interface_claim(); a
     * passed-through control transfer would switch the device but leave the host
     * side at alt 0, so isoc endpoints (UVC/UAC) never get a handle. Re-claim at
     * the requested alt and ack the client (SET_INTERFACE has no data stage). */
    if (ep == 0) {
        const uint8_t *setup = hdr->u.cmd_submit.setup;
        if (setup[0] == 0x01 && setup[1] == 0x0B) {
            uint8_t alt   = setup[2];   /* wValue low byte */
            uint8_t iface = setup[4];   /* wIndex low byte */
            esp_err_t e = usb_host_mgr_set_alt_setting(devinfo->dev_addr, iface, alt);
            ESP_LOGI(TAG, "SET_INTERFACE iface=%u alt=%u -> %s",
                     iface, alt, esp_err_to_name(e));
            send_error_reply(fd, seqnum, e == ESP_OK ? 0 : -LINUX_EIO);
            return 0;
        }
    }

    /* Large bulk IN with fast read on: double-buffered chunks (experimental) */
    if (s_fast_read && ep != 0 && direction == USBIP_DIR_IN && num_iso == 0 &&
        buflen >= IN_FAST_MIN && ep_is_bulk(devinfo, (uint8_t)(ep | 0x80))) {
        uint16_t mps = find_ep_mps(devinfo, (uint8_t)(ep | 0x80));
        if (mps > 0 && IN_CHUNK_SIZE % mps == 0) {
            return handle_in_fast(fd, hdr, devinfo, dev_index, ep, buflen, mps);
        }
    }

    /* Large bulk OUT: pipelined chunks (see handle_out_chunked) */
    if (ep != 0 && direction == USBIP_DIR_OUT && num_iso == 0 && buflen >= OUT_CHUNK_MIN &&
        ep_is_bulk(devinfo, (uint8_t)ep)) {
        return handle_out_chunked(fd, hdr, devinfo, dev_index, ep, buflen);
    }

    /* Reserve a free slot for this connection (atomic under the table lock) */
    int slot_idx = reserve_free_slot(fd, seqnum);
    if (slot_idx < 0) {
        ESP_LOGE(TAG, "Pending URB table full (%d slots)", MAX_PENDING_URBS);
        if (direction == USBIP_DIR_OUT && buflen > 0) {
            drain_socket(fd, buflen);
        }
        if (num_iso > 0) {
            drain_socket(fd, num_iso * 16);
        }
        send_error_reply(fd, seqnum, -LINUX_EIO);
        return 0; /* non-fatal */
    }

    /* Determine if this is a control transfer */
    bool is_control = (ep == 0);

    /* Compute allocation size. For non-control IN transfers, ESP-IDF requires
     * num_bytes to be a multiple of the endpoint's max packet size -- round up to
     * the ACTUAL endpoint MPS. A hardcoded 512 breaks endpoints whose MPS doesn't
     * divide 512 (e.g. an interrupt endpoint with MPS 35, or odd isoc sizes). */
    uint16_t in_mps = 0;
    size_t alloc_size = is_control ? (size_t)(buflen + 8) : (size_t)buflen;
    if (!is_control && direction == USBIP_DIR_IN && buflen > 0) {
        in_mps = find_ep_mps(devinfo, (uint8_t)(ep | 0x80));
        if (in_mps == 0) {
            in_mps = 512;  /* fallback if the descriptor lookup fails */
        }
        alloc_size = ((size_t)buflen + in_mps - 1) / in_mps * in_mps;
    }
    if (alloc_size < MIN_TRANSFER_SIZE) {
        alloc_size = MIN_TRANSFER_SIZE;
    }

    /* Allocate USB transfer */
    usb_transfer_t *xfer = NULL;
    esp_err_t err = usb_host_transfer_alloc(alloc_size, num_iso, &xfer);
    if (err != ESP_OK || !xfer) {
        ESP_LOGE(TAG, "Failed to allocate transfer: %s", esp_err_to_name(err));
        if (direction == USBIP_DIR_OUT && buflen > 0) {
            drain_socket(fd, buflen);
        }
        if (num_iso > 0) {
            drain_socket(fd, num_iso * 16);
        }
        send_error_reply(fd, seqnum, -LINUX_EIO);
        return 0; /* non-fatal */
    }

    /* Create completion semaphore */
    SemaphoreHandle_t sem = xSemaphoreCreateBinary();
    if (!sem) {
        ESP_LOGE(TAG, "Failed to create semaphore");
        usb_host_transfer_free(xfer);
        if (direction == USBIP_DIR_OUT && buflen > 0) {
            drain_socket(fd, buflen);
        }
        if (num_iso > 0) {
            drain_socket(fd, num_iso * 16);
        }
        send_error_reply(fd, seqnum, -LINUX_EIO);
        return 0;
    }

    /* Initialize the pending slot (before submit, so callback can access it) */
    pending_urb_t *slot = &s_pending[slot_idx];
    slot->active        = true;
    slot->seqnum        = seqnum;
    slot->devid         = hdr->base.devid;
    slot->direction     = direction;
    slot->ep            = ep;
    slot->buflen        = buflen;
    slot->num_iso       = num_iso;
    slot->submit_time_us = esp_timer_get_time();
    slot->xfer          = xfer;
    slot->sem           = sem;
    slot->usb_status    = USB_TRANSFER_STATUS_ERROR;
    slot->is_control    = is_control;
    slot->dev_index     = dev_index;

    /* Get device handle */
    usb_device_handle_t dev_handle = usb_host_mgr_get_handle(devinfo->dev_addr);
    if (!dev_handle) {
        ESP_LOGE(TAG, "No device handle for addr %d", devinfo->dev_addr);
        if (direction == USBIP_DIR_OUT && buflen > 0) {
            drain_socket(fd, buflen);
        }
        if (num_iso > 0) {
            drain_socket(fd, num_iso * 16);
        }
        send_error_reply(fd, seqnum, -LINUX_ENODEV);
        free_pending_slot(slot);
        return 0;
    }

    /* Configure the transfer */
    xfer->device_handle = dev_handle;
    xfer->callback      = transfer_cb;
    xfer->context       = slot;  /* callback context points to the pending slot */
    xfer->timeout_ms    = USB_XFER_TIMEOUT_MS;

    if (is_control) {
        /* Control transfer: copy setup packet to data_buffer[0..7] */
        memcpy(xfer->data_buffer, hdr->u.cmd_submit.setup, 8);
        xfer->num_bytes = buflen + 8;
        xfer->bEndpointAddress = 0;
    } else {
        /* Round IN transfers up to a multiple of the endpoint's MPS (in_mps
         * computed above); OUT transfers send exactly buflen. */
        if (direction == USBIP_DIR_IN && buflen > 0) {
            xfer->num_bytes = ((size_t)buflen + in_mps - 1) / in_mps * in_mps;
        } else {
            xfer->num_bytes = buflen;
        }
        xfer->bEndpointAddress = (uint8_t)(ep | (direction == USBIP_DIR_IN ? 0x80 : 0x00));
    }

    /* For OUT transfers: receive transfer data from socket */
    if (direction == USBIP_DIR_OUT && buflen > 0) {
        uint8_t *dest = is_control ? (xfer->data_buffer + 8) : xfer->data_buffer;
        if (usbip_net_recv(fd, dest, buflen) != 0) {
            ESP_LOGE(TAG, "Failed to recv OUT data");
            free_pending_slot(slot);
            return -1; /* socket error, fatal */
        }
    }

    /* Capture CMD_SUBMIT packet */
#if CONFIG_CAPTURE_ENABLED
    {
        uint8_t *out_data = NULL;
        uint32_t out_len = 0;
        if (direction == USBIP_DIR_OUT && buflen > 0) {
            out_data = is_control ? (xfer->data_buffer + 8) : xfer->data_buffer;
            out_len = (uint32_t)buflen;
        }
        capture_submit_packet(CAPTURE_DIR_CLIENT_TO_SERVER,
                              hdr, sizeof(*hdr), out_data, out_len);
    }
#endif

    /* For ISO: receive ISO packet descriptors from socket */
    if (num_iso > 0) {
        uint64_t iso_total = 0;   /* 64-bit: client-supplied lengths must not wrap */
        for (int i = 0; i < num_iso; i++) {
            usbip_iso_packet_descriptor_t iso_desc;
            if (usbip_net_recv(fd, &iso_desc, sizeof(iso_desc)) != 0) {
                ESP_LOGE(TAG, "Failed to recv ISO descriptors");
                free_pending_slot(slot);
                return -1;
            }
            usbip_pack_iso_descriptor(&iso_desc, false); /* network -> host */
            xfer->isoc_packet_desc[i].num_bytes = iso_desc.length;
            iso_total += iso_desc.length;
        }
        /* The per-packet lengths come from the client: never let their sum
         * exceed the buffer we actually allocated. */
        if (iso_total > xfer->data_buffer_size) {
            ESP_LOGW(TAG, "ISO seqnum=%lu: packet lengths (%" PRIu64 ") exceed buffer (%u), rejecting",
                     (unsigned long)seqnum, iso_total,
                     (unsigned)xfer->data_buffer_size);
            send_error_reply(fd, seqnum, -LINUX_EINVAL);
            free_pending_slot(slot);
            return 0;  /* stream is in sync: all descriptors were consumed */
        }
        /* ESP-IDF requires xfer->num_bytes to exactly equal the sum of all isoc
         * packet lengths ("num_bytes != num_bytes of all packets" otherwise). The
         * MPS round-up applied to IN transfers above breaks that, so set it here. */
        xfer->num_bytes = (int)iso_total;
    }

    /* Submit the transfer */
    ESP_LOGD(TAG, "Submitting: ep_addr=0x%02x num_bytes=%d timeout=%dms",
             xfer->bEndpointAddress, xfer->num_bytes, xfer->timeout_ms);
    esp_err_t submit_err;
    if (is_control) {
        usb_host_client_handle_t client_hdl = usb_host_mgr_get_client_handle();
        submit_err = usb_host_transfer_submit_control(client_hdl, xfer);
    } else {
        submit_err = usb_host_transfer_submit(xfer);
    }

    if (submit_err != ESP_OK) {
        ESP_LOGE(TAG, "Transfer submit failed: %s (ep=0x%02x)",
                 esp_err_to_name(submit_err), xfer->bEndpointAddress);
        send_error_reply(fd, seqnum, -LINUX_EIO);
        free_pending_slot(slot);
        return 0; /* non-fatal */
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* CMD_UNLINK handler                                                  */
/* ------------------------------------------------------------------ */

static int handle_cmd_unlink(int fd, usbip_header_t *hdr, const dm_device_info_t *devinfo)
{
    uint32_t seqnum = hdr->base.seqnum;
    uint32_t unlink_seqnum = hdr->u.cmd_unlink.seqnum;

    ESP_LOGD(TAG, "CMD_UNLINK seqnum=%lu unlink_seqnum=%lu",
             (unsigned long)seqnum,
             (unsigned long)unlink_seqnum);

    /* Capture CMD_UNLINK packet */
#if CONFIG_CAPTURE_ENABLED
    capture_submit_packet(CAPTURE_DIR_CLIENT_TO_SERVER, hdr, sizeof(*hdr), NULL, 0);
#endif

    int slot_idx = find_pending_by_seqnum(unlink_seqnum, fd);

    if (slot_idx >= 0) {
        /* Found the pending URB - abort it.
         * Per spec: after successful UNLINK, the unlinked URB shall NOT get
         * a RET_SUBMIT. We only send the RET_UNLINK with -ECONNRESET. */
        pending_urb_t *slot = &s_pending[slot_idx];
        usb_device_handle_t dev_handle = usb_host_mgr_get_handle(devinfo->dev_addr);

        if (slot->rd_fast && slot->rd_hdr_sent) {
            /* Part of the reply is already on the wire: a RET_UNLINK now would
             * break the stream. Close the connection; cleanup cancels the URB. */
            ESP_LOGW(TAG, "Unlink of fast read seqnum=%lu mid-stream - closing connection",
                     (unsigned long)unlink_seqnum);
            return -1;
        }

        ESP_LOGI(TAG, "Aborting pending URB seqnum=%lu ep=0x%02x",
                 (unsigned long)unlink_seqnum,
                 (unsigned)(slot->ep | (slot->direction == USBIP_DIR_IN ? 0x80 : 0x00)));

        bool done = cancel_pending_urb(slot, dev_handle, false);
        /* Do NOT send RET_SUBMIT - spec says no RET_SUBMIT after successful UNLINK */
        release_after_cancel(slot, done);
    }

    /* Send RET_UNLINK response.
     * Per spec: devid, direction, ep shall be 0 for server responses.
     * status: -ECONNRESET if UNLINK was successful (URB was still pending),
     *         0 if the URB had already completed (UNLINK came too late). */
    usbip_header_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.base.command          = USBIP_RET_UNLINK;
    reply.base.seqnum           = seqnum;
    reply.base.devid            = 0;
    reply.base.direction        = 0;
    reply.base.ep               = 0;
    reply.u.ret_unlink.status   = (slot_idx >= 0) ? -LINUX_ECONNRESET : 0;

    /* Capture RET_UNLINK packet (before packing to network order) */
#if CONFIG_CAPTURE_ENABLED
    capture_submit_packet(CAPTURE_DIR_SERVER_TO_CLIENT, &reply, sizeof(reply), NULL, 0);
#endif

    usbip_pack_header(&reply, true);

    if (usbip_net_send(fd, &reply, sizeof(reply)) != 0) {
        ESP_LOGE(TAG, "Failed to send RET_UNLINK");
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

esp_err_t transfer_engine_init(void)
{
    for (int i = 0; i < WAKE_SLOTS; i++) {
        s_wake[i].sockfd = -1;
        s_wake[i].evfd = -1;
    }
    s_wake_mtx = xSemaphoreCreateMutex();
    esp_vfs_eventfd_config_t cfg = ESP_VFS_EVENTD_CONFIG_DEFAULT();
    cfg.max_fds = WAKE_SLOTS;
    esp_err_t err = esp_vfs_eventfd_register(&cfg);
    s_eventfd_ok = s_wake_mtx && (err == ESP_OK || err == ESP_ERR_INVALID_STATE);  /* already registered = fine */
    if (!s_eventfd_ok) {
        ESP_LOGW(TAG, "eventfd unavailable (%s) - completions picked up by polling only",
                 esp_err_to_name(err));
    }
    nvs_handle_t nvs;
    uint8_t fr = 0;
    if (nvs_open("usb", NVS_READONLY, &nvs) == ESP_OK) {
        nvs_get_u8(nvs, "fastrd", &fr);
        nvs_close(nvs);
    }
    s_fast_read = fr != 0;
    ESP_LOGI(TAG, "Transfer engine initialized%s", s_fast_read ? " (fast read: experimental, on)" : "");
    return ESP_OK;
}

esp_err_t transfer_engine_stop(void)
{
    ESP_LOGI(TAG, "Transfer engine stopped");
    return ESP_OK;
}

int transfer_engine_run(int sockfd, const char *busid, bool *needs_reset)
{
    if (needs_reset) {
        *needs_reset = false;
    }
    ESP_LOGI(TAG, "Transfer engine starting: fd=%d busid=%s", sockfd, busid ? busid : "");

    /* Look up the device */
    int dev_index = -1;
    if (device_manager_lookup(busid, &dev_index) != ESP_OK) {
        ESP_LOGE(TAG, "Device not found: %s", busid ? busid : "(null)");
        return -1;
    }

    dm_device_info_t devinfo;
    if (device_manager_get(dev_index, &devinfo) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get device info for index %d", dev_index);
        return -1;
    }

    /*
     * Cache the device handle up front. Once the device is unplugged,
     * usb_host_mgr_get_handle() returns NULL because the tracked entry
     * is freed. We still need the handle for endpoint halt/flush/clear
     * during cleanup of in-flight transfers.
     */
    usb_device_handle_t cached_dev_handle = usb_host_mgr_get_handle(devinfo.dev_addr);
    if (!cached_dev_handle) {
        ESP_LOGE(TAG, "No device handle for addr %d at start", devinfo.dev_addr);
        return -1;
    }

    /* Clear any stale removal notification */
    usb_host_mgr_check_removal();

    event_log_add(EVENT_LOG_LEVEL_INFO, "Transfer engine started for %s (addr=%d)",
                  busid, devinfo.dev_addr);

    /* NOTE: the pending-URB table is shared by all client connections (slots are
     * isolated by owner_fd). It must NOT be cleared here: the former
     * memset(s_pending, 0, ...) wiped other clients' in-flight URBs (leaking
     * their transfers/semaphores and leaving USB callbacks pointing at zeroed
     * slots -> crash) whenever a second device was imported. Only reclaim
     * orphans whose transfers have since completed. */
    reap_orphans();

    /* Main concurrent URB forwarding loop */
    int ret = 0;
    bool device_removed = false;
    int wake_fd = wake_register(sockfd);     /* -1 = poll timeouts only */

    while (1) {
        /* ---- Check device removal flag (set by usb_host_mgr) ---- */
        uint8_t removed_addr = usb_host_mgr_check_removal();
        if (removed_addr == devinfo.dev_addr) {
            ESP_LOGW(TAG, "Device addr=%d removed (notified by usb_host_mgr)", devinfo.dev_addr);
            device_removed = true;
            ret = -1;
            break;
        }

        /* ---- Phase 1: Check socket for new data (non-blocking) ---- */
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        int maxfd = sockfd;
        if (wake_fd >= 0) {
            FD_SET(wake_fd, &readfds);
            if (wake_fd > maxfd) maxfd = wake_fd;
        }

        /* Poll fast only while this connection has URBs in flight. */
        bool have_pending = false;
        for (int i = 0; i < MAX_PENDING_URBS; i++) {
            if (s_pending[i].active && s_pending[i].owner_fd == sockfd) {
                have_pending = true;
                break;
            }
        }

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = have_pending ? SELECT_TIMEOUT_US : SELECT_TIMEOUT_IDLE_US;

        int sel_ret = select(maxfd + 1, &readfds, NULL, NULL, &tv);

        if (sel_ret < 0) {
            ESP_LOGE(TAG, "select() error: errno=%d", errno);
            ret = -1;
            break;
        }

        if (sel_ret > 0 && wake_fd >= 0 && FD_ISSET(wake_fd, &readfds)) {
            uint64_t cnt;
            read(wake_fd, &cnt, sizeof(cnt));        /* reset; completions are handled below */
        }

        if (sel_ret > 0 && FD_ISSET(sockfd, &readfds)) {
            /* Socket has data - read USB/IP header */
            usbip_header_t hdr;
            if (usbip_net_recv(sockfd, &hdr, sizeof(hdr)) != 0) {
                ESP_LOGI(TAG, "Client disconnected or socket error");
                ret = 0; /* clean disconnect */
                break;
            }

            /* Unpack from network byte order */
            usbip_pack_header(&hdr, false);

            /* Dispatch by command */
            int rc;
            switch (hdr.base.command) {
            case USBIP_CMD_SUBMIT:
                rc = handle_cmd_submit(sockfd, &hdr, &devinfo, dev_index);
                break;
            case USBIP_CMD_UNLINK:
                rc = handle_cmd_unlink(sockfd, &hdr, &devinfo);
                break;
            default:
                ESP_LOGE(TAG, "Unknown command: 0x%08lx", (unsigned long)hdr.base.command);
                rc = -1;
                break;
            }

            if (rc < 0) {
                ESP_LOGE(TAG, "Handler error, exiting loop");
                ret = -1;
                break;
            }
        }

        /* ---- Phase 2: Check all pending URBs for completions ---- */
        int64_t now = esp_timer_get_time();

        for (int i = 0; i < MAX_PENDING_URBS; i++) {
            pending_urb_t *slot = &s_pending[i];
            if (!slot->active || slot->owner_fd != sockfd) {
                continue;  /* only poll this connection's own URBs */
            }

            if (slot->rd_fast && xSemaphoreTake(slot->sem, 0) == pdTRUE) {
                int r = fast_read_step(sockfd, slot);
                if (r > 0) {
                    free_pending_slot(slot);
                } else if (r < 0) {
                    /* With a chunk still on the bus the cleanup below cancels
                     * it and frees the slot; otherwise free it here. */
                    if (!slot->rd_inflight) {
                        free_pending_slot(slot);
                    }
                    ret = -1;
                    goto cleanup;
                }
            } else if (!slot->rd_fast && xSemaphoreTake(slot->sem, 0) == pdTRUE) {
                /* Transfer completed! */
                if (send_completed_reply(sockfd, slot, cached_dev_handle) != 0) {
                    free_pending_slot(slot);
                    ret = -1;
                    goto cleanup;
                }
                free_pending_slot(slot);
            } else if (slot->n_chunks > 0 && !slot->chunk_flushed &&
                       slot->chunk_status != USB_TRANSFER_STATUS_COMPLETED && cached_dev_handle) {
                /* A chunk failed (e.g. STALL): the pipe halts and the queued
                 * chunks would wait for the client's unlink. Flush them now so
                 * the error is reported as fast as with a single transfer. */
                slot->chunk_flushed = true;
                uint8_t ep_addr = slot->xfer->bEndpointAddress;
                usb_host_endpoint_halt(cached_dev_handle, ep_addr);
                usb_host_endpoint_flush(cached_dev_handle, ep_addr);
                usb_host_endpoint_clear(cached_dev_handle, ep_addr);
            } else if ((slot->is_control || slot->direction != USBIP_DIR_IN) &&
                       (now - slot->submit_time_us) > PENDING_URB_TIMEOUT_US) {
                /* Timeout - abort */
                ESP_LOGE(TAG, "Transfer timeout (seqnum=%lu), aborting ep=0x%02x",
                         (unsigned long)slot->seqnum, slot->xfer->bEndpointAddress);

                bool done = cancel_pending_urb(slot, cached_dev_handle, true);

                /* Send timeout reply */
                send_error_reply(sockfd, slot->seqnum, -LINUX_ETIMEDOUT);
                release_after_cancel(slot, done);
            }
        }

        /* Free any orphaned slots whose transfers have completed meanwhile */
        reap_orphans();

        /* ---- Phase 3: Check if device still exists ---- */
        if (device_manager_get(dev_index, &devinfo) != ESP_OK || !devinfo.in_use) {
            ESP_LOGW(TAG, "Device removed during transfer session");
            device_removed = true;
            ret = -1;
            break;
        }
    }

cleanup:
    /*
     * Cleanup: abort all active pending URBs.
     * Use the cached dev_handle - it may still be valid even if the device
     * was removed from the tracked table. If the device was physically
     * unplugged, the handle is stale but endpoint ops will simply fail,
     * which is fine.
     *
     * For device removal: send -ENODEV RET_SUBMIT for each pending URB
     * so the client knows the device is gone, before freeing the slot.
     */
    {
        usb_device_handle_t cleanup_handle = device_removed ? NULL : cached_dev_handle;

        for (int i = 0; i < MAX_PENDING_URBS; i++) {
            pending_urb_t *slot = &s_pending[i];
            if (!slot->active || slot->owner_fd != sockfd) {
                continue;  /* only tear down this connection's own URBs */
            }
            ESP_LOGW(TAG, "Cleanup: aborting pending URB seqnum=%lu",
                     (unsigned long)slot->seqnum);

            bool done = cancel_pending_urb(slot, cleanup_handle, true);

            /* Send -ENODEV for each pending URB so client knows device is gone */
            send_error_reply(sockfd, slot->seqnum, -LINUX_ENODEV);

            release_after_cancel(slot, done);
        }
    }

    /* No URB in flight is not enough: a mass-storage read spans several URBs,
     * the stick can be mid-command between two of them. */
    if (needs_reset) {
        *needs_reset = !device_removed;
    }

    wake_unregister(wake_fd);

    event_log_add(EVENT_LOG_LEVEL_INFO, "Transfer engine stopped for %s", busid);
    return ret;
}
