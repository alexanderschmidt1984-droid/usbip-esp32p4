/*
 * Access Control - Full implementation with NVS persistence
 */

#include "access_control.h"
#include "device_filter.h"
#include "event_log.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"

#include <string.h>
#include <lwip/inet.h>
#include <lwip/etharp.h>
#include <lwip/priv/tcpip_priv.h>
#include "freertos/FreeRTOS.h"

static const char *TAG = "acl";
static const char *NVS_NAMESPACE = "acl";
static const char *NVS_KEY_CLOSED = "closed";
static const char *NVS_KEY_ALLOWLIST = "allowlist";   /* old firmware: uint32_t IPs only */
static const char *NVS_KEY_ENTRIES = "entries";       /* acl_entry_t[] */

static bool s_closed_mode = false;
static acl_entry_t s_entries[ACCESS_CONTROL_MAX_IPS];
static int s_count = 0;
/* Guards s_entries/s_count: checked from the USB/IP, TLS and httpd tasks. */
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

/* Format an IP (network byte order) into a dotted string */
static void ip_to_str(uint32_t ip, char *buf, size_t len)
{
    uint8_t *b = (uint8_t *)&ip;
    snprintf(buf, len, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static esp_err_t save_mode_to_nvs(void)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS for writing mode: %s", esp_err_to_name(err));
        return err;
    }

    uint8_t val = s_closed_mode ? 1 : 0;
    err = nvs_set_u8(nvs, NVS_KEY_CLOSED, val);
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to save mode to NVS: %s", esp_err_to_name(err));
    }
    return err;
}

static esp_err_t save_entries_to_nvs(void)
{
    acl_entry_t copy[ACCESS_CONTROL_MAX_IPS];
    portENTER_CRITICAL(&s_lock);
    int n = s_count;
    memcpy(copy, s_entries, sizeof(acl_entry_t) * (size_t)n);
    portEXIT_CRITICAL(&s_lock);

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS for writing allowlist: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_set_blob(nvs, NVS_KEY_ENTRIES, copy, sizeof(acl_entry_t) * (size_t)n);
    if (err == ESP_OK) {
        nvs_erase_key(nvs, NVS_KEY_ALLOWLIST);   /* migrated, drop the old format */
        err = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to save allowlist to NVS: %s", esp_err_to_name(err));
    }
    return err;
}

static esp_err_t acl_load(void)
{
    s_closed_mode = false;
    s_count = 0;
    memset(s_entries, 0, sizeof(s_entries));

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGI(TAG, "No ACL data in NVS, using defaults (open mode)");
        event_log_add(EVENT_LOG_LEVEL_INFO, "Access control initialized (open mode, no saved config)");
        return ESP_OK;
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to open NVS for reading: %s", esp_err_to_name(err));
        event_log_add(EVENT_LOG_LEVEL_WARN, "Access control init: NVS read failed, using defaults");
        return ESP_OK; /* Non-fatal: use defaults */
    }

    /* Load mode */
    uint8_t closed_val = 0;
    err = nvs_get_u8(nvs, NVS_KEY_CLOSED, &closed_val);
    if (err == ESP_OK) {
        s_closed_mode = (closed_val != 0);
    }

    /* Load allowlist: current format, else take over the old IP-only list */
    bool migrate = false;
    size_t blob_len = sizeof(s_entries);
    if (nvs_get_blob(nvs, NVS_KEY_ENTRIES, s_entries, &blob_len) == ESP_OK) {
        s_count = (int)(blob_len / sizeof(acl_entry_t));
    } else {
        uint32_t old[ACCESS_CONTROL_MAX_IPS];
        blob_len = sizeof(old);
        if (nvs_get_blob(nvs, NVS_KEY_ALLOWLIST, old, &blob_len) == ESP_OK && blob_len > 0) {
            s_count = (int)(blob_len / sizeof(uint32_t));
            for (int i = 0; i < s_count; i++) {
                s_entries[i].type = ACL_ENTRY_IP;
                s_entries[i].ip = old[i];
            }
            migrate = true;
        }
    }
    for (int i = 0; i < s_count; i++) {
        s_entries[i].comment[ACCESS_CONTROL_COMMENT_LEN - 1] = '\0';
    }

    nvs_close(nvs);
    if (migrate) {
        ESP_LOGI(TAG, "Allowlist taken over from old format (%d IPs)", s_count);
        save_entries_to_nvs();
    }

    ESP_LOGI(TAG, "Access control initialized: mode=%s, %d allowlist entries",
             s_closed_mode ? "closed" : "open", s_count);
    event_log_add(EVENT_LOG_LEVEL_INFO, "Access control initialized: %s mode, %d allowlist entries",
                  s_closed_mode ? "closed" : "open", s_count);

    return ESP_OK;
}

/* ARP lookup must run in the lwIP thread (core locking is off). */
struct arp_query {
    struct tcpip_api_call_data call;
    uint32_t ip;
    uint8_t  mac[6];
    bool     found;
};

static err_t arp_query_fn(struct tcpip_api_call_data *call)
{
    struct arp_query *q = (struct arp_query *)call;
    ip4_addr_t addr = { .addr = q->ip };
    struct eth_addr *eth = NULL;
    const ip4_addr_t *ip_ret = NULL;
    if (etharp_find_addr(NULL, &addr, &eth, &ip_ret) >= 0 && eth) {
        memcpy(q->mac, eth->addr, 6);
        q->found = true;
    }
    return ERR_OK;
}

bool access_control_lookup_mac(uint32_t client_ip, uint8_t mac_out[6])
{
    struct arp_query q = { .ip = client_ip, .found = false };
    if (tcpip_api_call(arp_query_fn, &q.call) != ERR_OK || !q.found) {
        return false;
    }
    memcpy(mac_out, q.mac, 6);
    return true;
}

/* IP entries first; the ARP lookup only when MAC entries exist. */
static bool match(uint32_t client_ip)
{
    bool has_mac = false;
    portENTER_CRITICAL(&s_lock);
    for (int i = 0; i < s_count; i++) {
        if (s_entries[i].type == ACL_ENTRY_IP && s_entries[i].ip == client_ip) {
            portEXIT_CRITICAL(&s_lock);
            return true;
        }
        has_mac |= (s_entries[i].type == ACL_ENTRY_MAC);
    }
    portEXIT_CRITICAL(&s_lock);
    if (!has_mac) {
        return false;
    }

    uint8_t mac[6];
    if (!access_control_lookup_mac(client_ip, mac)) {
        return false;
    }
    bool ok = false;
    portENTER_CRITICAL(&s_lock);
    for (int i = 0; i < s_count && !ok; i++) {
        ok = s_entries[i].type == ACL_ENTRY_MAC && memcmp(s_entries[i].mac, mac, 6) == 0;
    }
    portEXIT_CRITICAL(&s_lock);
    return ok;
}

esp_err_t access_control_init(void)
{
    esp_err_t err = acl_load();
    /* VID:PID device filter lives in this component as well */
    device_filter_init();
    return err;
}

bool access_control_check(uint32_t client_ip)
{
    if (!s_closed_mode) {
        return true;
    }
    if (match(client_ip)) {
        return true;
    }

    char ip_str[16];
    ip_to_str(client_ip, ip_str, sizeof(ip_str));
    ESP_LOGW(TAG, "Denied connection from %s (not in allowlist)", ip_str);
    event_log_add(EVENT_LOG_LEVEL_WARN, "Access denied for %s", ip_str);
    return false;
}

bool access_control_is_allowed(uint32_t client_ip)
{
    return match(client_ip);
}

bool access_control_is_closed_mode(void)
{
    return s_closed_mode;
}

void access_control_set_mode(bool closed)
{
    if (s_closed_mode == closed) {
        return; /* No change */
    }

    s_closed_mode = closed;
    save_mode_to_nvs();

    const char *mode_str = closed ? "closed" : "open";
    ESP_LOGI(TAG, "Access control mode set to %s", mode_str);
    event_log_add(EVENT_LOG_LEVEL_INFO, "Access control mode changed to %s", mode_str);
}

esp_err_t access_control_add_ip(uint32_t ip, const char *comment)
{
    char ip_str[16];
    ip_to_str(ip, ip_str, sizeof(ip_str));

    portENTER_CRITICAL(&s_lock);
    esp_err_t err = ESP_OK;
    for (int i = 0; i < s_count; i++) {
        if (s_entries[i].type == ACL_ENTRY_IP && s_entries[i].ip == ip) {
            err = ESP_ERR_INVALID_STATE;
        }
    }
    if (err == ESP_OK && s_count >= ACCESS_CONTROL_MAX_IPS) {
        err = ESP_ERR_NO_MEM;
    }
    if (err == ESP_OK) {
        acl_entry_t *e = &s_entries[s_count++];
        memset(e, 0, sizeof(*e));
        e->type = ACL_ENTRY_IP;
        e->ip = ip;
        if (comment) {
            strlcpy(e->comment, comment, sizeof(e->comment));
        }
    }
    portEXIT_CRITICAL(&s_lock);

    if (err == ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "IP %s already in allowlist", ip_str);
        return err;
    } else if (err == ESP_ERR_NO_MEM) {
        ESP_LOGE(TAG, "Allowlist full, cannot add %s", ip_str);
        return err;
    }
    save_entries_to_nvs();

    ESP_LOGI(TAG, "Added %s to allowlist", ip_str);
    event_log_add(EVENT_LOG_LEVEL_INFO, "Added %s to access allowlist", ip_str);
    return ESP_OK;
}

int access_control_get_entries(acl_entry_t *out, int max)
{
    if (out == NULL || max <= 0) {
        return 0;
    }
    portENTER_CRITICAL(&s_lock);
    int n = (s_count < max) ? s_count : max;
    memcpy(out, s_entries, sizeof(acl_entry_t) * (size_t)n);
    portEXIT_CRITICAL(&s_lock);
    return n;
}

esp_err_t access_control_set_entries(const acl_entry_t *entries, int n)
{
    if (n < 0 || n > ACCESS_CONTROL_MAX_IPS || (n > 0 && entries == NULL)) {
        return ESP_ERR_INVALID_SIZE;
    }
    portENTER_CRITICAL(&s_lock);
    memcpy(s_entries, entries, sizeof(acl_entry_t) * (size_t)n);
    for (int i = 0; i < n; i++) {
        s_entries[i].comment[ACCESS_CONTROL_COMMENT_LEN - 1] = '\0';
    }
    s_count = n;
    portEXIT_CRITICAL(&s_lock);

    ESP_LOGI(TAG, "Allowlist replaced (%d entries)", n);
    return save_entries_to_nvs();
}
