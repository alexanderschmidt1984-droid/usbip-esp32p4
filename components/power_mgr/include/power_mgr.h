/*
 * Power save (dynamic CPU frequency scaling), switchable in the web UI.
 * Stored in NVS namespace "power"; on unless the user turned it off.
 * Off = the CPU stays at full clock all the time.
 */
#pragma once

#include "esp_err.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Read the stored setting and apply it. Call once at boot. */
esp_err_t power_mgr_init(void);
/* Compiled in (CONFIG_USBIP_POWER_SAVE)? false = setting not offered. */
bool      power_mgr_available(void);
/* User setting (true = power save on). */
bool      power_mgr_get(void);
/* Apply immediately and store. ESP_ERR_NOT_SUPPORTED if not compiled in. */
esp_err_t power_mgr_set(bool enabled);

#ifdef __cplusplus
}
#endif
