/*
 * USB/IP Server for ESP32-P4-Nano
 * Main application entry point
 */

#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "esp_psram.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "nvs.h"
#include "sdkconfig.h"
#if CONFIG_PM_PROFILING
#include "esp_pm.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#endif

#include "event_log.h"
#include "access_control.h"
#include "device_manager.h"
#include "network_mgr.h"
#include "usb_host_mgr.h"
#include "transfer_engine.h"
#include "usbip_server.h"
#include "webui.h"
#include "wg_tunnel.h"
#include "sec_tls.h"
#include "power_mgr.h"
#if CONFIG_CAPTURE_ENABLED
#include "capture.h"
#endif

static const char *TAG = "main";

/*
 * Custom log handler: intercepts ESP-IDF log output to detect USB hub TT errors
 * and enum failures, forwarding them to our event log for WebUI display.
 */
static vprintf_like_t s_orig_vprintf = NULL;

static int custom_vprintf(const char *fmt, va_list args)
{
    /* Keep a copy in the PSRAM system log ring (web UI export). The line is
     * formatted on the caller's stack; longer lines are cut. */
    char line[256];
    va_list copy;
    va_copy(copy, args);
    int n = vsnprintf(line, sizeof(line), fmt, copy);
    va_end(copy);
    if (n > 0) {
        event_log_syslog_write(line, n < (int)sizeof(line) ? (size_t)n : sizeof(line) - 1);
    }

    /* Call original handler */
    int ret = s_orig_vprintf(fmt, args);

    /* Check for known USB hub/enum error patterns in the format string */
    if (fmt) {
        /* esp-usb: "Connected device is FS, transaction translator (TT) is not
         * supported". Not just "TT": that also matched "HTTPS" in other lines. */
        if (strstr(fmt, "transaction translator (TT) is not supported")) {
            usb_host_mgr_note_tt_reject();
            event_log_add(EVENT_LOG_LEVEL_WARN,
                "USB hub: slow (FS/LS) device rejected, no TT support - connect it to the board directly");
        } else if (strstr(fmt, "CHECK_SHORT_DEV_DESC FAILED") ||
                   strstr(fmt, "CHECK_FULL_CONFIG_DESC FAILED")) {
            event_log_add(EVENT_LOG_LEVEL_WARN,
                "USB device enumeration failed. Try reconnecting the device.");
        }
    }

    return ret;
}

/*
 * Factory reset without the web UI: press RESET (or switch the power on)
 * RESET_TAP_COUNT times in a row, each within RESET_TAP_WINDOW_MS of the
 * previous start. Every such start bumps a counter in NVS; once the board has
 * run for RESET_TAP_WINDOW_MS the counter is cleared. Software restarts and
 * crashes are not counted, so a crash loop never wipes the settings.
 * (The BOOT button is no option: GPIO 35 is RMII TXD1 on this board.)
 */
#define RESET_TAP_COUNT     5
#define RESET_TAP_WINDOW_MS 5000

static void reset_tap_clear(void *arg)
{
    (void)arg;
    nvs_handle_t nvs;
    if (nvs_open("boot", NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_set_u8(nvs, "taps", 0);
        nvs_commit(nvs);
        nvs_close(nvs);
    }
}

static void reset_tap_check(void)
{
    esp_reset_reason_t why = esp_reset_reason();
    if (why != ESP_RST_POWERON && why != ESP_RST_EXT) {
        return;
    }

    uint8_t taps = 0;
    nvs_handle_t nvs;
    if (nvs_open("boot", NVS_READWRITE, &nvs) != ESP_OK) {
        return;
    }
    nvs_get_u8(nvs, "taps", &taps);
    taps++;
    nvs_set_u8(nvs, "taps", taps);
    nvs_commit(nvs);
    nvs_close(nvs);

    if (taps >= RESET_TAP_COUNT) {
        ESP_LOGW(TAG, "RESET pressed %d times in a row: factory reset", taps);
        nvs_flash_erase();
        esp_restart();
    }
    ESP_LOGI(TAG, "Reset tap %d/%d (factory reset after %d in a row)", taps, RESET_TAP_COUNT,
             RESET_TAP_COUNT);

    static esp_timer_handle_t s_tap_timer;
    const esp_timer_create_args_t args = { .callback = reset_tap_clear, .name = "reset_tap" };
    if (esp_timer_create(&args, &s_tap_timer) == ESP_OK) {
        esp_timer_start_once(s_tap_timer, (uint64_t)RESET_TAP_WINDOW_MS * 1000);
    }
}

void app_main(void)
{
    esp_err_t ret;

    /* Log CPU frequency */
    uint32_t cpu_freq_mhz = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ;
    ESP_LOGI(TAG, "CPU frequency: %lu MHz", (unsigned long)cpu_freq_mhz);

    /* Initialize NVS */
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partition truncated, erasing...");
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    ESP_LOGI(TAG, "NVS initialized");

    reset_tap_check();

    /* Log PSRAM info */
    size_t psram_size = esp_psram_get_size();
    ESP_LOGI(TAG, "PSRAM size: %u bytes (%.1f MB)", (unsigned)psram_size,
             (float)psram_size / (1024.0f * 1024.0f));

    /* Initialize subsystems in dependency order */
    ESP_LOGI(TAG, "Initializing subsystems...");

    ESP_ERROR_CHECK(event_log_init());
    ESP_LOGI(TAG, "Event log initialized");

    /* Install custom log handler to catch USB hub TT errors for WebUI */
    s_orig_vprintf = esp_log_set_vprintf(custom_vprintf);
    ESP_LOGI(TAG, "Custom log handler installed");

    /* Power save (DFS), switchable in the web UI; non-fatal */
    esp_err_t pm_err = power_mgr_init();
    if (pm_err != ESP_OK) {
        ESP_LOGW(TAG, "Power save init failed: %s", esp_err_to_name(pm_err));
    }

    ESP_ERROR_CHECK(access_control_init());
    ESP_LOGI(TAG, "Access control initialized");

    ESP_ERROR_CHECK(device_manager_init());
    ESP_LOGI(TAG, "Device manager initialized");

    ESP_ERROR_CHECK(network_mgr_init());
    ESP_LOGI(TAG, "Network manager initialized");

    /* WireGuard: non-fatal, stays idle until enabled in the web UI */
    esp_err_t wg_ret = wg_tunnel_init();
    if (wg_ret != ESP_OK) {
        ESP_LOGW(TAG, "WireGuard init failed: %s", esp_err_to_name(wg_ret));
    }

    ESP_ERROR_CHECK(usb_host_mgr_init());
    ESP_LOGI(TAG, "USB host manager initialized");

    ESP_ERROR_CHECK(transfer_engine_init());
    ESP_LOGI(TAG, "Transfer engine initialized");

#if CONFIG_CAPTURE_ENABLED
    /* capture_init is non-fatal if SD card is absent */
    esp_err_t cap_ret = capture_init();
    if (cap_ret == ESP_OK) {
        ESP_LOGI(TAG, "Capture subsystem initialized");
    } else {
        ESP_LOGW(TAG, "Capture init: %s (non-fatal)", esp_err_to_name(cap_ret));
    }
#endif

    /* Transport encryption (USB/IP over TLS, HTTPS cert) - before server/web UI */
    esp_err_t tls_ret = sectls_init();
    if (tls_ret != ESP_OK) {
        ESP_LOGW(TAG, "TLS init failed: %s", esp_err_to_name(tls_ret));
    }

    ESP_ERROR_CHECK(usbip_server_init());
    ESP_LOGI(TAG, "USB/IP server initialized");

    ESP_ERROR_CHECK(webui_init());
    ESP_LOGI(TAG, "Web UI initialized");

    /* Log free heap after all init */
    size_t free_heap = esp_get_free_heap_size();
    size_t free_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    ESP_LOGI(TAG, "Free heap: %u bytes (internal: %u bytes)", (unsigned)free_heap, (unsigned)free_internal);

    /* Initial event log entry */
    event_log_add(EVENT_LOG_LEVEL_INFO, "System started: CPU %lu MHz, PSRAM %.1f MB, free heap %u bytes",
                  (unsigned long)cpu_freq_mhz, (float)psram_size / (1024.0f * 1024.0f), (unsigned)free_heap);

    ESP_LOGI(TAG, "USB/IP server ready. Connect via: usbip list -r <ip>");

#if CONFIG_PM_PROFILING
    /* Test aid: time spent per clock mode and per PM lock since boot. */
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(30000));
        esp_pm_dump_locks(stdout);
    }
#endif
}
