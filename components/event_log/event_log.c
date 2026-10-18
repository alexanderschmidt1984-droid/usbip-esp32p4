/*
 * Event Log Component - Full Implementation
 * Ring buffer in PSRAM for system event logging
 */

#include "event_log.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_attr.h"
#include "esp_system.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdarg.h>

static const char *TAG = "event_log";

/** Ring buffer state */
static struct {
    event_log_entry_t *entries;    /**< Array of entries (allocated in PSRAM) */
    size_t capacity;               /**< Max entries */
    size_t head;                   /**< Next write index */
    size_t count;                  /**< Current number of valid entries */
    uint32_t total;                /**< Total events ever logged */
    SemaphoreHandle_t mutex;       /**< Thread safety */
    bool initialized;
} s_log = {0};

/* System log ring: raw ESP_LOG text. A spinlock (not the mutex) because the
 * log hook runs in any task, also with the scheduler busy. */
static char *s_sys;
static uint64_t s_sys_written;        /* total bytes ever written */
static portMUX_TYPE s_sys_lock = portMUX_INITIALIZER_UNLOCKED;

/* Last words: tail of the system log in RTC no-init RAM (kept over a panic or
 * software restart). Validated by two magics, since after power-on the
 * content is random. */
#define TAIL_MAGIC1 0x55534c47u   /* "USLG" */
#define TAIL_MAGIC2 0x7a11c0deu
static RTC_NOINIT_ATTR struct {
    uint32_t magic1;
    uint32_t written;
    char     buf[EVENT_LOG_TAIL_SIZE];
    uint32_t magic2;
} s_tail;

static char    *s_prev;          /* previous run's tail, linearized (PSRAM) */
static size_t   s_prev_len;
static esp_reset_reason_t s_reset_reason;
static uint32_t s_crashes;

static bool reason_is_crash(esp_reset_reason_t r)
{
    switch (r) {
    case ESP_RST_PANIC: case ESP_RST_INT_WDT: case ESP_RST_TASK_WDT: case ESP_RST_WDT:
    case ESP_RST_BROWNOUT: case ESP_RST_PWR_GLITCH: case ESP_RST_CPU_LOCKUP:
        return true;
    default:
        return false;
    }
}

const char *event_log_reset_reason_str(void)
{
    switch (s_reset_reason) {
    case ESP_RST_POWERON:    return "power on";
    case ESP_RST_EXT:        return "reset button";
    case ESP_RST_SW:         return "software restart";
    case ESP_RST_PANIC:      return "crash (panic)";
    case ESP_RST_INT_WDT:    return "crash (interrupt watchdog)";
    case ESP_RST_TASK_WDT:   return "crash (task watchdog)";
    case ESP_RST_WDT:        return "crash (watchdog)";
    case ESP_RST_BROWNOUT:   return "brownout (supply voltage too low)";
    case ESP_RST_PWR_GLITCH: return "power glitch";
    case ESP_RST_CPU_LOCKUP: return "crash (CPU lockup)";
    case ESP_RST_USB:        return "USB reset";
    case ESP_RST_JTAG:       return "JTAG reset";
    default:                 return "unknown";
    }
}

bool     event_log_last_reset_was_crash(void) { return reason_is_crash(s_reset_reason); }
uint32_t event_log_crash_count(void)          { return s_crashes; }
size_t   event_log_previous_len(void)         { return s_prev_len; }

size_t event_log_previous_read(uint64_t *pos, char *buf, size_t max)
{
    if (!pos || !buf || !s_prev || *pos >= s_prev_len) {
        return 0;
    }
    size_t n = s_prev_len - (size_t)*pos;
    if (n > max) n = max;
    memcpy(buf, s_prev + *pos, n);
    *pos += n;
    return n;
}

/* Take over the previous run's tail and count a crash (NVS write only then). */
static void crash_info_init(void)
{
    s_reset_reason = esp_reset_reason();

    bool valid = s_tail.magic1 == TAIL_MAGIC1 && s_tail.magic2 == TAIL_MAGIC2 &&
                 s_reset_reason != ESP_RST_POWERON;
    if (valid && s_tail.written > 0) {
        size_t len = s_tail.written < EVENT_LOG_TAIL_SIZE ? s_tail.written : EVENT_LOG_TAIL_SIZE;
        s_prev = heap_caps_malloc(len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (s_prev) {
            size_t start = s_tail.written < EVENT_LOG_TAIL_SIZE ? 0 : s_tail.written % EVENT_LOG_TAIL_SIZE;
            size_t first = EVENT_LOG_TAIL_SIZE - start;
            if (first > len) first = len;
            memcpy(s_prev, s_tail.buf + start, first);
            memcpy(s_prev + first, s_tail.buf, len - first);
            s_prev_len = len;
        }
    }
    s_tail.magic1 = TAIL_MAGIC1;
    s_tail.magic2 = TAIL_MAGIC2;
    s_tail.written = 0;

    nvs_handle_t nvs;
    if (nvs_open("boot", NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_get_u32(nvs, "crashes", &s_crashes);
        if (reason_is_crash(s_reset_reason)) {
            s_crashes++;
            nvs_set_u32(nvs, "crashes", s_crashes);
            nvs_commit(nvs);
        }
        nvs_close(nvs);
    }
}

esp_err_t event_log_init(void)
{
    if (s_log.initialized) {
        return ESP_OK;
    }

    s_log.capacity = EVENT_LOG_MAX_ENTRIES;
    s_log.head = 0;
    s_log.count = 0;
    s_log.total = 0;

    /* Try PSRAM first, fall back to internal */
    size_t alloc_size = sizeof(event_log_entry_t) * s_log.capacity;
    s_log.entries = heap_caps_malloc(alloc_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (s_log.entries == NULL) {
        ESP_LOGW(TAG, "PSRAM alloc failed, falling back to internal RAM");
        s_log.entries = malloc(alloc_size);
        if (s_log.entries == NULL) {
            ESP_LOGE(TAG, "Failed to allocate event log buffer");
            return ESP_ERR_NO_MEM;
        }
    } else {
        ESP_LOGI(TAG, "Event log buffer allocated in PSRAM (%u bytes)", (unsigned)alloc_size);
    }

    memset(s_log.entries, 0, alloc_size);

    s_sys = heap_caps_malloc(EVENT_LOG_SYSLOG_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (s_sys) {
        ESP_LOGI(TAG, "System log ring in PSRAM (%u KB)", (unsigned)(EVENT_LOG_SYSLOG_SIZE / 1024));
    } else {
        ESP_LOGW(TAG, "No PSRAM for the system log ring - system log export unavailable");
    }

    s_log.mutex = xSemaphoreCreateMutex();
    if (s_log.mutex == NULL) {
        free(s_log.entries);
        s_log.entries = NULL;
        return ESP_ERR_NO_MEM;
    }

    s_log.initialized = true;
    ESP_LOGI(TAG, "Event log initialized (capacity=%u entries)", (unsigned)s_log.capacity);

    crash_info_init();
    if (reason_is_crash(s_reset_reason)) {
        ESP_LOGW(TAG, "Last restart: %s (%lu crashes so far)", event_log_reset_reason_str(),
                 (unsigned long)s_crashes);
        event_log_add(EVENT_LOG_LEVEL_ERROR, "Restarted after %s - log of the previous run: "
                      "Dashboard -> Export (%u bytes)", event_log_reset_reason_str(),
                      (unsigned)s_prev_len);
    } else {
        event_log_add(EVENT_LOG_LEVEL_INFO, "Started (last restart: %s)", event_log_reset_reason_str());
    }

    return ESP_OK;
}

esp_err_t event_log_add(event_log_level_t level, const char *fmt, ...)
{
    if (!s_log.initialized || fmt == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    if (xSemaphoreTake(s_log.mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    event_log_entry_t *entry = &s_log.entries[s_log.head];
    entry->timestamp_us = esp_timer_get_time();
    entry->level = level;

    va_list args;
    va_start(args, fmt);
    vsnprintf(entry->message, EVENT_LOG_MSG_MAX_LEN, fmt, args);
    va_end(args);

    s_log.head = (s_log.head + 1) % s_log.capacity;
    if (s_log.count < s_log.capacity) {
        s_log.count++;
    }
    s_log.total++;

    xSemaphoreGive(s_log.mutex);

    return ESP_OK;
}

esp_err_t event_log_get_recent(event_log_entry_t *entries, size_t max_entries, size_t *out_count)
{
    if (!s_log.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (entries == NULL || out_count == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    if (xSemaphoreTake(s_log.mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    size_t to_copy = (max_entries < s_log.count) ? max_entries : s_log.count;

    /* Copy most recent entries (newest first) */
    for (size_t i = 0; i < to_copy; i++) {
        size_t idx = (s_log.head + s_log.capacity - 1 - i) % s_log.capacity;
        memcpy(&entries[i], &s_log.entries[idx], sizeof(event_log_entry_t));
    }

    *out_count = to_copy;

    xSemaphoreGive(s_log.mutex);

    return ESP_OK;
}

esp_err_t event_log_get_oldest(size_t skip, event_log_entry_t *entries, size_t max_entries,
                               size_t *out_count)
{
    if (!s_log.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (entries == NULL || out_count == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (xSemaphoreTake(s_log.mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    size_t oldest = (s_log.head + s_log.capacity - s_log.count) % s_log.capacity;
    size_t n = 0;
    for (size_t i = skip; i < s_log.count && n < max_entries; i++, n++) {
        memcpy(&entries[n], &s_log.entries[(oldest + i) % s_log.capacity], sizeof(event_log_entry_t));
    }
    *out_count = n;
    xSemaphoreGive(s_log.mutex);
    return ESP_OK;
}

void event_log_syslog_write(const char *text, size_t len)
{
    if (!s_sys || !text || len == 0 || s_tail.magic1 != TAIL_MAGIC1) {
        return;
    }
    if (len > EVENT_LOG_SYSLOG_SIZE) {
        text += len - EVENT_LOG_SYSLOG_SIZE;
        len = EVENT_LOG_SYSLOG_SIZE;
    }
    portENTER_CRITICAL_SAFE(&s_sys_lock);
    size_t at = (size_t)(s_sys_written % EVENT_LOG_SYSLOG_SIZE);
    size_t first = EVENT_LOG_SYSLOG_SIZE - at;
    if (first > len) first = len;
    memcpy(s_sys + at, text, first);
    memcpy(s_sys, text + first, len - first);
    s_sys_written += len;
    /* tail copy in RTC RAM (only the end matters) */
    size_t tl = len > EVENT_LOG_TAIL_SIZE ? EVENT_LOG_TAIL_SIZE : len;
    const char *tt = text + (len - tl);
    size_t ta = s_tail.written % EVENT_LOG_TAIL_SIZE;
    size_t tf = EVENT_LOG_TAIL_SIZE - ta;
    if (tf > tl) tf = tl;
    memcpy(s_tail.buf + ta, tt, tf);
    memcpy(s_tail.buf, tt + tf, tl - tf);
    s_tail.written += tl;
    portEXIT_CRITICAL_SAFE(&s_sys_lock);
}

size_t event_log_syslog_read(uint64_t *pos, char *buf, size_t max)
{
    if (!s_sys || !pos || !buf || max == 0) {
        return 0;
    }
    portENTER_CRITICAL_SAFE(&s_sys_lock);
    uint64_t oldest = s_sys_written > EVENT_LOG_SYSLOG_SIZE ? s_sys_written - EVENT_LOG_SYSLOG_SIZE : 0;
    if (*pos < oldest) {
        *pos = oldest;                 /* overwritten meanwhile: skip ahead */
    }
    size_t avail = (size_t)(s_sys_written - *pos);
    size_t n = avail < max ? avail : max;
    size_t at = (size_t)(*pos % EVENT_LOG_SYSLOG_SIZE);
    size_t first = EVENT_LOG_SYSLOG_SIZE - at;
    if (first > n) first = n;
    memcpy(buf, s_sys + at, first);
    memcpy(buf + first, s_sys, n - first);
    *pos += n;
    portEXIT_CRITICAL_SAFE(&s_sys_lock);
    return n;
}
