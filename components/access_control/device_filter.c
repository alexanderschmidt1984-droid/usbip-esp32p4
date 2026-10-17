/*
 * Device Filter - VID:PID allowlist with NVS persistence
 */

#include "device_filter.h"
#include "event_log.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

#ifndef CONFIG_USBIP_DEVICE_ALLOWLIST
#define CONFIG_USBIP_DEVICE_ALLOWLIST ""
#endif

static const char *TAG = "devfilter";
static const char *NVS_NAMESPACE = "devfilter";

typedef struct {
    uint16_t vid;
    uint16_t pid;
    bool any_pid;
} filter_entry_t;

static portMUX_TYPE   s_lock = portMUX_INITIALIZER_UNLOCKED;
static bool           s_enabled = false;
static filter_entry_t s_entries[DEVICE_FILTER_MAX_ENTRIES];
static int            s_count = 0;

/* Parse one hex field of 1..4 digits. */
static bool parse_hex16(const char *s, size_t len, uint16_t *out)
{
    if (len == 0 || len > 4) return false;
    uint32_t v = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!isxdigit((unsigned char)c)) return false;
        v = (v << 4) | (uint32_t)(isdigit((unsigned char)c) ? c - '0' : (tolower((unsigned char)c) - 'a' + 10));
    }
    *out = (uint16_t)v;
    return true;
}

/* Parse "VVVV:PPPP[,VVVV:*...]" into entries. Returns -1 on syntax error. */
static int parse_list(const char *list, filter_entry_t *out, int max)
{
    int n = 0;
    const char *p = list ? list : "";
    while (*p) {
        while (*p == ',' || *p == ';' || isspace((unsigned char)*p)) p++;
        if (!*p) break;
        const char *tok = p;
        while (*p && *p != ',' && *p != ';' && !isspace((unsigned char)*p)) p++;
        size_t toklen = (size_t)(p - tok);

        const char *colon = memchr(tok, ':', toklen);
        if (!colon) return -1;
        size_t vlen = (size_t)(colon - tok);
        const char *ps = colon + 1;
        size_t plen = toklen - vlen - 1;

        if (n >= max) return -1;
        filter_entry_t e = {0};
        if (!parse_hex16(tok, vlen, &e.vid)) return -1;
        if (plen == 1 && ps[0] == '*') {
            e.any_pid = true;
        } else if (!parse_hex16(ps, plen, &e.pid)) {
            return -1;
        }
        out[n++] = e;
    }
    return n;
}

static void format_list(const filter_entry_t *e, int count, char *buf, size_t buflen)
{
    size_t pos = 0;
    if (buflen == 0) return;
    buf[0] = '\0';
    for (int i = 0; i < count && pos < buflen; i++) {
        int w;
        if (e[i].any_pid) {
            w = snprintf(buf + pos, buflen - pos, "%s%04x:*", i ? "," : "", e[i].vid);
        } else {
            w = snprintf(buf + pos, buflen - pos, "%s%04x:%04x", i ? "," : "", e[i].vid, e[i].pid);
        }
        if (w < 0) break;
        pos += (size_t)w;
    }
}

esp_err_t device_filter_init(void)
{
    bool enabled = false;
    char list[DEVICE_FILTER_LIST_MAX] = "";
    bool from_nvs = false;

    nvs_handle_t nvs;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs) == ESP_OK) {
        uint8_t en = 0;
        size_t len = sizeof(list);
        if (nvs_get_u8(nvs, "enabled", &en) == ESP_OK) {
            enabled = (en != 0);
            from_nvs = true;
            if (nvs_get_str(nvs, "list", list, &len) != ESP_OK) {
                list[0] = '\0';
            }
        }
        nvs_close(nvs);
    }
    if (!from_nvs) {
        strncpy(list, CONFIG_USBIP_DEVICE_ALLOWLIST, sizeof(list) - 1);
        enabled = (list[0] != '\0');
    }

    filter_entry_t tmp[DEVICE_FILTER_MAX_ENTRIES];
    int n = parse_list(list, tmp, DEVICE_FILTER_MAX_ENTRIES);
    if (n < 0) {
        ESP_LOGE(TAG, "Invalid stored device filter '%s' - filter disabled", list);
        n = 0;
        enabled = false;
    }

    portENTER_CRITICAL(&s_lock);
    memcpy(s_entries, tmp, sizeof(filter_entry_t) * (size_t)n);
    s_count = n;
    s_enabled = enabled && n > 0;
    portEXIT_CRITICAL(&s_lock);

    char norm[DEVICE_FILTER_LIST_MAX];
    format_list(tmp, n, norm, sizeof(norm));
    ESP_LOGI(TAG, "Device filter %s (%d entr%s)%s%s", s_enabled ? "ENABLED" : "disabled",
             n, n == 1 ? "y" : "ies", n ? ": " : "", norm);
    return ESP_OK;
}

bool device_filter_allows(uint16_t vid, uint16_t pid)
{
    bool allowed;
    portENTER_CRITICAL(&s_lock);
    if (!s_enabled) {
        allowed = true;
    } else {
        allowed = false;
        for (int i = 0; i < s_count; i++) {
            if (s_entries[i].vid == vid && (s_entries[i].any_pid || s_entries[i].pid == pid)) {
                allowed = true;
                break;
            }
        }
    }
    portEXIT_CRITICAL(&s_lock);
    return allowed;
}

esp_err_t device_filter_set(bool enabled, const char *list)
{
    filter_entry_t tmp[DEVICE_FILTER_MAX_ENTRIES];
    int n = parse_list(list, tmp, DEVICE_FILTER_MAX_ENTRIES);
    if (n < 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (enabled && n == 0) {
        /* An enabled filter with an empty list would hide every device. */
        return ESP_ERR_INVALID_ARG;
    }

    char norm[DEVICE_FILTER_LIST_MAX];
    format_list(tmp, n, norm, sizeof(norm));

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_u8(nvs, "enabled", enabled ? 1 : 0);
    if (err == ESP_OK) err = nvs_set_str(nvs, "list", norm);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    if (err != ESP_OK) {
        return err;
    }

    portENTER_CRITICAL(&s_lock);
    memcpy(s_entries, tmp, sizeof(filter_entry_t) * (size_t)n);
    s_count = n;
    s_enabled = enabled;
    portEXIT_CRITICAL(&s_lock);

    ESP_LOGI(TAG, "Device filter %s: %s", enabled ? "ENABLED" : "disabled", norm);
    event_log_add(EVENT_LOG_LEVEL_INFO, "Device filter %s: %s",
                  enabled ? "enabled" : "disabled", n ? norm : "(empty)");
    return ESP_OK;
}

void device_filter_get(bool *enabled, char *buf, size_t buflen)
{
    filter_entry_t tmp[DEVICE_FILTER_MAX_ENTRIES];
    int n;
    bool en;
    portENTER_CRITICAL(&s_lock);
    n = s_count;
    memcpy(tmp, s_entries, sizeof(filter_entry_t) * (size_t)n);
    en = s_enabled;
    portEXIT_CRITICAL(&s_lock);

    if (enabled) *enabled = en;
    if (buf) format_list(tmp, n, buf, buflen);
}
