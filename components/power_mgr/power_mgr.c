/*
 * Power save: DFS between CONFIG_USBIP_PM_MIN_FREQ_MHZ and full clock.
 * While a USB/IP device is attached, usbip_connection holds a CPU_FREQ_MAX
 * lock, so transfers always run at full speed. Turning power save off
 * reconfigures DFS with min = max, i.e. a fixed full clock.
 */
#include "power_mgr.h"
#include "esp_log.h"
#include "nvs.h"
#include "sdkconfig.h"
#if CONFIG_USBIP_POWER_SAVE
#include "esp_pm.h"
#endif

static const char *TAG = "power_mgr";

#define NVS_NAMESPACE "power"
#define NVS_KEY       "save"

static bool s_enabled = true;

#if CONFIG_USBIP_POWER_SAVE
static esp_err_t apply(bool enabled)
{
    esp_pm_config_t pm = {
        .max_freq_mhz = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ,
        .min_freq_mhz = enabled ? CONFIG_USBIP_PM_MIN_FREQ_MHZ : CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ,
        .light_sleep_enable = false,   /* board must stay reachable */
    };
    esp_err_t err = esp_pm_configure(&pm);
    ESP_LOGI(TAG, "Power save %s (DFS %d-%d MHz): %s", enabled ? "on" : "off",
             pm.min_freq_mhz, pm.max_freq_mhz, esp_err_to_name(err));
    return err;
}
#endif

esp_err_t power_mgr_init(void)
{
#if CONFIG_USBIP_POWER_SAVE
    nvs_handle_t nvs;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs) == ESP_OK) {
        uint8_t v;
        if (nvs_get_u8(nvs, NVS_KEY, &v) == ESP_OK) {
            s_enabled = (v != 0);
        }
        nvs_close(nvs);
    }
    return apply(s_enabled);
#else
    s_enabled = false;
    return ESP_OK;
#endif
}

bool power_mgr_available(void)
{
#if CONFIG_USBIP_POWER_SAVE
    return true;
#else
    return false;
#endif
}

bool power_mgr_get(void)
{
    return s_enabled;
}

esp_err_t power_mgr_set(bool enabled)
{
#if CONFIG_USBIP_POWER_SAVE
    esp_err_t err = apply(enabled);
    if (err != ESP_OK) {
        return err;
    }
    s_enabled = enabled;

    nvs_handle_t nvs;
    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_u8(nvs, NVS_KEY, enabled ? 1 : 0);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
#else
    (void)enabled;
    return ESP_ERR_NOT_SUPPORTED;
#endif
}
