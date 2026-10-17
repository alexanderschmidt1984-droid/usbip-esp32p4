/*
 * Device Filter - VID:PID allowlist for exported USB devices
 *
 * When enabled, only USB devices whose VID:PID matches an entry are offered to
 * USB/IP clients; all others are ignored at enumeration time (they stay
 * physically connected but are never added to the device list).
 */
#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum number of VID:PID entries */
#define DEVICE_FILTER_MAX_ENTRIES 16

/** Maximum length of the textual list ("1050:*,0403:6001,...") */
#define DEVICE_FILTER_LIST_MAX 192

/**
 * @brief Load filter from NVS (namespace "devfilter"). If nothing is stored,
 *        CONFIG_USBIP_DEVICE_ALLOWLIST is used as factory default (empty = off).
 */
esp_err_t device_filter_init(void);

/**
 * @brief Check whether a device may be exported.
 * @return true if the filter is disabled or VID:PID matches an entry.
 */
bool device_filter_allows(uint16_t vid, uint16_t pid);

/**
 * @brief Replace the filter configuration and persist it to NVS.
 * @param enabled  true to enforce the list
 * @param list     comma/space separated "VVVV:PPPP" or "VVVV:*" (hex)
 * @return ESP_OK, or ESP_ERR_INVALID_ARG if the list cannot be parsed
 *         (configuration is left unchanged in that case)
 */
esp_err_t device_filter_set(bool enabled, const char *list);

/**
 * @brief Read the current configuration.
 * @param[out] enabled  filter state
 * @param[out] buf      normalised textual list
 */
void device_filter_get(bool *enabled, char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif
