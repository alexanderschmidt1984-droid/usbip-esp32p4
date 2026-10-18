/*
 * WebSocket Handler
 * Manages WS client connections and broadcasts real-time stats
 */

#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_private/esp_clk.h"
#include "esp_pm.h"
#if CONFIG_PM_ENABLE
#include "esp_private/pm_impl.h"
#endif
#include "freertos/FreeRTOS.h"
#include "device_manager.h"
#include "event_log.h"
#include "webui_internal.h"
#include "wg_tunnel.h"

#include <lwip/sockets.h>
#include <string.h>
#include <stdio.h>

static const char *TAG = "ws_handler";

#define WS_CLIENT_LIST_MAX 8   /* >= httpd max_open_sockets, for client enumeration */

static httpd_handle_t ws_server_handle;

void ws_handler_init(httpd_handle_t server)
{
    ws_server_handle = server;
    ESP_LOGI(TAG, "WebSocket handler initialized");
}

/* Build device JSON fragment into buf. Returns chars written. */
static int build_devices_json(char *buf, int buflen)
{
    int pos = 0;
    pos += snprintf(buf + pos, buflen - pos, "[");

    int dev_count = device_manager_get_count();
    int printed = 0;

    for (int i = 0; i < DEVICE_MANAGER_MAX_DEVICES && printed < dev_count; i++) {
        dm_device_info_t info;
        if (device_manager_get(i, &info) != ESP_OK || !info.in_use) {
            continue;
        }
        if (printed > 0) {
            pos += snprintf(buf + pos, buflen - pos, ",");
        }

        /* Escape manufacturer and product strings for JSON safety */
        char mfr_esc[128];
        char prod_esc[128];
        webui_json_escape(info.manufacturer, mfr_esc, sizeof(mfr_esc));
        webui_json_escape(info.product, prod_esc, sizeof(prod_esc));

        pos += snprintf(buf + pos, buflen - pos,
            "{\"idx\":%d,\"path\":\"%s\",\"vid\":%u,\"pid\":%u,\"speed\":%d,"
            "\"state\":%d,\"client_ip\":%lu,\"tr\":%u,"
            "\"mfr\":\"%s\",\"prod\":\"%s\","
            "\"bi\":%llu,\"bo\":%llu,\"uok\":%lu,\"ufl\":%lu,"
            "\"det\":%s,\"icl\":[",
            i,
            info.path,
            (unsigned)info.vendor_id,
            (unsigned)info.product_id,
            (int)info.speed,
            (int)info.state,
            (unsigned long)info.client_ip,
            (unsigned)info.transport,
            mfr_esc, prod_esc,
            (unsigned long long)info.bytes_in,
            (unsigned long long)info.bytes_out,
            (unsigned long)info.urbs_completed,
            (unsigned long)info.urbs_failed,
            info.config_desc_len > 0 ? "true" : "false");

        /* Interface class array */
        for (int k = 0; k < info.num_interfaces && k < DEVICE_MANAGER_MAX_INTERFACES; k++) {
            if (k > 0) pos += snprintf(buf + pos, buflen - pos, ",");
            pos += snprintf(buf + pos, buflen - pos, "%u",
                (unsigned)info.interfaces[k].bInterfaceClass);
        }

        pos += snprintf(buf + pos, buflen - pos, "]}");
        printed++;
    }

    pos += snprintf(buf + pos, buflen - pos, "]");
    return pos;
}

/* Build recent log entries JSON fragment.
 * Uses heap allocation to avoid blowing the esp_timer stack. */
static int build_logs_json(char *buf, int buflen)
{
    int pos = 0;
    #define LOG_BROADCAST_COUNT 10

    event_log_entry_t *entries = malloc(LOG_BROADCAST_COUNT * sizeof(event_log_entry_t));
    if (!entries) {
        pos += snprintf(buf + pos, buflen - pos, "[]");
        return pos;
    }

    size_t count = 0;
    event_log_get_recent(entries, LOG_BROADCAST_COUNT, &count);

    pos += snprintf(buf + pos, buflen - pos, "[");
    for (size_t i = 0; i < count; i++) {
        if (i > 0) pos += snprintf(buf + pos, buflen - pos, ",");
        char escaped[EVENT_LOG_MSG_MAX_LEN * 2];
        webui_json_escape(entries[i].message, escaped, sizeof(escaped));

        pos += snprintf(buf + pos, buflen - pos,
            "{\"ts\":%lld,\"level\":%d,\"msg\":\"%s\"}",
            entries[i].timestamp_us,
            (int)entries[i].level,
            escaped);
    }
    pos += snprintf(buf + pos, buflen - pos, "]");

    free(entries);
    return pos;

    #undef LOG_BROADCAST_COUNT
}

/* Async send context: the frame is sent from the httpd task (via httpd_queue_work),
 * not from the esp_timer task that builds the broadcast. Sending directly from the
 * timer task raced with httpd's own recv on the same socket ("socket FD invalid"). */
struct ws_async_send_ctx {
    int fd;
    size_t len;
    char *payload;
};

static void ws_async_send_cb(void *arg)
{
    struct ws_async_send_ctx *ctx = (struct ws_async_send_ctx *)arg;
    httpd_ws_frame_t frame = {
        .type = HTTPD_WS_TYPE_TEXT,
        .payload = (uint8_t *)ctx->payload,
        .len = ctx->len,
        .final = true,
    };
    esp_err_t ret = httpd_ws_send_frame_async(ws_server_handle, ctx->fd, &frame);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "WS send failed fd=%d: %s", ctx->fd, esp_err_to_name(ret));
    }
    free(ctx->payload);
    free(ctx);
}

void ws_broadcast_stats(void)
{
    if (!ws_server_handle) return;

    /* Ask httpd who is connected and keep the WebSocket clients. ESP-IDF 6.0
     * does not call the URI handler on the WS handshake (httpd_uri.c: "do not
     * call the uri->handler"), so a handshake-time fd registry is never filled
     * -- enumerate the live client list at send time instead. */
    int client_fds[WS_CLIENT_LIST_MAX];
    size_t fds_count = WS_CLIENT_LIST_MAX;
    if (httpd_get_client_list(ws_server_handle, &fds_count, client_fds) != ESP_OK) {
        return;
    }
    int ws_fds_list[WS_CLIENT_LIST_MAX];
    int ws_count = 0;
    for (size_t i = 0; i < fds_count; i++) {
        if (httpd_ws_get_fd_info(ws_server_handle, client_fds[i]) == HTTPD_WS_CLIENT_WEBSOCKET) {
            ws_fds_list[ws_count++] = client_fds[i];
        }
    }
    if (ws_count == 0) return;

    /* Build the stats JSON message on the stack */
    char *json_buf = malloc(8192);
    if (!json_buf) {
        ESP_LOGW(TAG, "ws_broadcast_stats: OOM");
        return;
    }
    int pos = 0;
    int buflen = 8192;

    uint32_t free_heap = esp_get_free_heap_size();
    uint32_t free_internal = esp_get_free_internal_heap_size();
    int64_t uptime_us = esp_timer_get_time();
    int uptime_sec = (int)(uptime_us / 1000000);
    /* CPU clock. Without power save it is fixed. With power save (DFS) a
     * running task always holds the CPU at max (FreeRTOS "rtosN" PM locks),
     * so reading the clock here would always say max. Report the mode the
     * board is in between tasks instead: full clock while a device is
     * exported (usbip_connection PM lock), otherwise the idle clock. The
     * Ethernet driver holds an APB_FREQ_MAX lock for good, so idle is the
     * APB_MAX mode, not min_freq_mhz. */
    int cpu_mhz = esp_clk_cpu_freq() / 1000000;
    bool pm_on = false;
#if CONFIG_PM_ENABLE
    esp_pm_config_t pmc;
    if (esp_pm_get_configuration(&pmc) == ESP_OK && pmc.min_freq_mhz < pmc.max_freq_mhz) {
        pm_on = true;
        bool busy = false;
        for (int i = 0; i < DEVICE_MANAGER_MAX_DEVICES && !busy; i++) {
            dm_device_info_t di;
            busy = device_manager_get(i, &di) == ESP_OK && di.in_use &&
                   di.state == DEV_STATE_EXPORTED;
        }
        cpu_mhz = esp_pm_impl_get_cpu_freq(busy ? PM_MODE_CPU_MAX : PM_MODE_APB_MAX);
    }
#endif

    pos += snprintf(json_buf + pos, buflen - pos,
        "{\"type\":\"stats\",\"free_heap\":%lu,\"free_internal\":%lu,\"uptime_sec\":%d,"
        "\"cpu_mhz\":%d,\"pm\":%s,\"bw_in\":0,\"bw_out\":0,\"devices\":",
        (unsigned long)free_heap, (unsigned long)free_internal, uptime_sec, cpu_mhz,
        pm_on ? "true" : "false");

    pos += build_devices_json(json_buf + pos, buflen - pos);

    pos += snprintf(json_buf + pos, buflen - pos, ",\"logs\":");
    pos += build_logs_json(json_buf + pos, buflen - pos);

    /* WireGuard state, plus per client whether its own connection arrived on
     * the tunnel address ("wg_self", appended per fd below). */
    wg_tunnel_status_t wst;
    wg_tunnel_get_status(&wst);
    uint32_t wg_ip = 0, wg_mask = 0;
    bool wg_up = wg_tunnel_up_addr(&wg_ip, &wg_mask);
    char wg_addr[16] = "", wg_mstr[16] = "";
    if (wg_up) {
        inet_ntoa_r(*(struct in_addr *)&wg_ip, wg_addr, sizeof(wg_addr));
        inet_ntoa_r(*(struct in_addr *)&wg_mask, wg_mstr, sizeof(wg_mstr));
    }
    bool wg_enabled = wst.state != WG_STATE_DISABLED;
    pos += snprintf(json_buf + pos, buflen - pos,
        ",\"wg\":{\"enabled\":%s,\"up\":%s,\"state\":\"%s\",\"addr\":\"%s\",\"mask\":\"%s\"}"
        ",\"wg_self\":",
        wg_enabled ? "true" : "false", wg_up ? "true" : "false",
        wg_tunnel_state_str(wst.state), wg_addr, wg_mstr);

    /* Queue the send onto the httpd task for each client (own payload copy each). */
    for (int i = 0; i < ws_count; i++) {
        bool self_wg = false;
        if (wg_ip) {
            struct sockaddr_in local;
            socklen_t llen = sizeof(local);
            if (getsockname(ws_fds_list[i], (struct sockaddr *)&local, &llen) == 0 &&
                local.sin_family == AF_INET) {
                self_wg = (local.sin_addr.s_addr == wg_ip);
            }
        }
        const char *tail = self_wg ? "true}" : "false}";
        size_t tail_len = strlen(tail);

        struct ws_async_send_ctx *ctx = malloc(sizeof(*ctx));
        char *copy = malloc(pos + tail_len);
        if (!ctx || !copy) {
            free(ctx);
            free(copy);
            continue;
        }
        memcpy(copy, json_buf, pos);
        memcpy(copy + pos, tail, tail_len);
        ctx->fd = ws_fds_list[i];
        ctx->len = pos + tail_len;
        ctx->payload = copy;
        if (httpd_queue_work(ws_server_handle, ws_async_send_cb, ctx) != ESP_OK) {
            free(ctx->payload);
            free(ctx);
        }
    }

    free(json_buf);
}

/* WebSocket handler called by esp_http_server. On ESP-IDF 6.0 the handshake is
 * handled internally, so this is invoked only for incoming frames. The frontend
 * drives all device actions over the REST API and never sends WS frames, so any
 * frame received here is simply drained. */
esp_err_t ws_handler(httpd_req_t *req)
{
    httpd_ws_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    frame.type = HTTPD_WS_TYPE_TEXT;

    esp_err_t ret = httpd_ws_recv_frame(req, &frame, 0);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "httpd_ws_recv_frame length failed: %s", esp_err_to_name(ret));
        return ret;
    }
    if (frame.len == 0) {
        return ESP_OK;
    }

    uint8_t *buf = calloc(1, frame.len + 1);
    if (!buf) {
        return ESP_ERR_NO_MEM;
    }
    frame.payload = buf;

    ret = httpd_ws_recv_frame(req, &frame, frame.len);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "httpd_ws_recv_frame data failed: %s", esp_err_to_name(ret));
        free(buf);
        return ret;
    }

    free(buf);
    return ESP_OK;
}
