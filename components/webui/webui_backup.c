/*
 * Settings backup / restore (Settings -> System).
 *
 * All settings namespaces of NVS (including password hashes, WireGuard and
 * TLS keys, HTTPS certificate) are serialized and encrypted with a passphrase
 * chosen by the admin, so the file never holds anything in clear text:
 *
 *   "USBIPBAK" | version (1) | iterations (4, BE) | salt (16) | nonce (12)
 *   | AES-256-GCM ciphertext | tag (16)
 *
 *   key = PBKDF2-HMAC-SHA256(passphrase, salt, iterations), 32 bytes
 *
 * Plaintext: "UIPB" then entries ns_len(1) ns key_len(1) key type(1)
 * val_len(2, BE) value. The first entry is "_meta"/"fw" (firmware version
 * that made the backup, informational). A restore wipes the listed namespaces,
 * writes the entries and restarts the board. Admin only.
 *
 * Compatibility: entries are self-describing, so newer firmware reads older
 * files (settings added later keep their defaults) and entries of unknown
 * namespaces or types are skipped instead of rejecting the file. Readers
 * accept every file version up to their own BAK_VERSION.
 */
#include "webui_internal.h"
#include "webui.h"
#include "event_log.h"
#include "network_mgr.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "esp_app_desc.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "psa/crypto.h"
#include "mbedtls/base64.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "backup";

#define BAK_MAGIC        "USBIPBAK"
#define BAK_VERSION      1
#define BAK_ITERATIONS   50000
#define BAK_SALT_LEN     16
#define BAK_NONCE_LEN    12
#define BAK_TAG_LEN      16
#define BAK_HDR_LEN      (8 + 1 + 4 + BAK_SALT_LEN + BAK_NONCE_LEN)
#define BAK_PLAIN_MAX    (32 * 1024)
#define BAK_PASS_MIN     8

/* Settings namespaces; "boot" (reset counter, crash count) is device state */
static const char *const s_namespaces[] = {
    "auth", "acl", "devfilter", "network", "wg", "sectls", "usb", "power",
};
#define NUM_NS (sizeof(s_namespaces) / sizeof(s_namespaces[0]))

/* ---- crypto ---- */

/* PBKDF2-HMAC-SHA256 with one output block (32 bytes = AES-256 key) */
static bool pbkdf2_sha256(const char *pass, const uint8_t *salt, size_t salt_len,
                          uint32_t iterations, uint8_t out[32])
{
    if (psa_crypto_init() != PSA_SUCCESS) return false;
    psa_key_attributes_t at = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&at, PSA_KEY_TYPE_HMAC);
    psa_set_key_usage_flags(&at, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&at, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_key_id_t key;
    if (psa_import_key(&at, (const uint8_t *)pass, strlen(pass), &key) != PSA_SUCCESS) return false;

    uint8_t u[32], blk[BAK_SALT_LEN + 4];
    size_t len = 0;
    memcpy(blk, salt, salt_len);
    blk[salt_len] = 0; blk[salt_len + 1] = 0; blk[salt_len + 2] = 0; blk[salt_len + 3] = 1;
    bool ok = psa_mac_compute(key, PSA_ALG_HMAC(PSA_ALG_SHA_256), blk, salt_len + 4,
                              u, sizeof(u), &len) == PSA_SUCCESS;
    memcpy(out, u, 32);
    for (uint32_t i = 1; ok && i < iterations; i++) {
        ok = psa_mac_compute(key, PSA_ALG_HMAC(PSA_ALG_SHA_256), u, 32, u, sizeof(u), &len) == PSA_SUCCESS;
        for (int j = 0; j < 32; j++) out[j] ^= u[j];
        if ((i & 0x3ff) == 0) vTaskDelay(1);          /* keep the watchdog and others happy */
    }
    psa_destroy_key(key);
    memset(u, 0, sizeof(u));
    return ok;
}

static bool aes_gcm(bool encrypt, const uint8_t key[32], const uint8_t *nonce,
                    const uint8_t *in, size_t in_len, uint8_t *out, size_t out_size, size_t *out_len)
{
    psa_key_attributes_t at = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&at, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&at, 256);
    psa_set_key_usage_flags(&at, encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&at, PSA_ALG_GCM);
    psa_key_id_t k;
    if (psa_import_key(&at, key, 32, &k) != PSA_SUCCESS) return false;
    psa_status_t st = encrypt
        ? psa_aead_encrypt(k, PSA_ALG_GCM, nonce, BAK_NONCE_LEN, (const uint8_t *)BAK_MAGIC, 8,
                           in, in_len, out, out_size, out_len)
        : psa_aead_decrypt(k, PSA_ALG_GCM, nonce, BAK_NONCE_LEN, (const uint8_t *)BAK_MAGIC, 8,
                           in, in_len, out, out_size, out_len);
    psa_destroy_key(k);
    return st == PSA_SUCCESS;
}

/* ---- NVS (de)serialization ---- */

static bool put(uint8_t *buf, size_t *pos, const void *d, size_t n)
{
    if (*pos + n > BAK_PLAIN_MAX) return false;
    memcpy(buf + *pos, d, n);
    *pos += n;
    return true;
}

static size_t serialize(uint8_t *buf)
{
    size_t pos = 0;
    put(buf, &pos, "UIPB", 4);
    {   /* "_meta"/"fw": firmware version, informational */
        const char *fw = esp_app_get_description()->version;
        uint8_t nl = 5, kl = 2, ty = NVS_TYPE_STR;
        size_t fl = strlen(fw);
        uint8_t vl[2] = { (uint8_t)(fl >> 8), (uint8_t)fl };
        put(buf, &pos, &nl, 1); put(buf, &pos, "_meta", 5);
        put(buf, &pos, &kl, 1); put(buf, &pos, "fw", 2);
        put(buf, &pos, &ty, 1); put(buf, &pos, vl, 2); put(buf, &pos, fw, fl);
    }
    uint8_t *val = malloc(4096);
    if (!val) return 0;
    for (size_t n = 0; n < NUM_NS; n++) {
        nvs_handle_t h;
        if (nvs_open(s_namespaces[n], NVS_READONLY, &h) != ESP_OK) continue;
        nvs_iterator_t it = NULL;
        esp_err_t e = nvs_entry_find(NVS_DEFAULT_PART_NAME, s_namespaces[n], NVS_TYPE_ANY, &it);
        while (e == ESP_OK) {
            nvs_entry_info_t info;
            nvs_entry_info(it, &info);
            size_t vlen = 0;
            esp_err_t g = ESP_FAIL;
            switch (info.type) {
            case NVS_TYPE_U8:  { uint8_t v;  g = nvs_get_u8(h, info.key, &v);  memcpy(val, &v, vlen = 1); break; }
            case NVS_TYPE_I8:  { int8_t v;   g = nvs_get_i8(h, info.key, &v);  memcpy(val, &v, vlen = 1); break; }
            case NVS_TYPE_U16: { uint16_t v; g = nvs_get_u16(h, info.key, &v); memcpy(val, &v, vlen = 2); break; }
            case NVS_TYPE_I16: { int16_t v;  g = nvs_get_i16(h, info.key, &v); memcpy(val, &v, vlen = 2); break; }
            case NVS_TYPE_U32: { uint32_t v; g = nvs_get_u32(h, info.key, &v); memcpy(val, &v, vlen = 4); break; }
            case NVS_TYPE_I32: { int32_t v;  g = nvs_get_i32(h, info.key, &v); memcpy(val, &v, vlen = 4); break; }
            case NVS_TYPE_U64: { uint64_t v; g = nvs_get_u64(h, info.key, &v); memcpy(val, &v, vlen = 8); break; }
            case NVS_TYPE_I64: { int64_t v;  g = nvs_get_i64(h, info.key, &v); memcpy(val, &v, vlen = 8); break; }
            case NVS_TYPE_STR:  vlen = 4096; g = nvs_get_str(h, info.key, (char *)val, &vlen); break;
            case NVS_TYPE_BLOB: vlen = 4096; g = nvs_get_blob(h, info.key, val, &vlen); break;
            default: break;
            }
            if (g == ESP_OK) {
                uint8_t nl = (uint8_t)strlen(s_namespaces[n]), kl = (uint8_t)strlen(info.key);
                uint8_t ty = (uint8_t)info.type;
                uint8_t vl[2] = { (uint8_t)(vlen >> 8), (uint8_t)vlen };
                if (!(put(buf, &pos, &nl, 1) && put(buf, &pos, s_namespaces[n], nl) &&
                      put(buf, &pos, &kl, 1) && put(buf, &pos, info.key, kl) &&
                      put(buf, &pos, &ty, 1) && put(buf, &pos, vl, 2) && put(buf, &pos, val, vlen))) {
                    nvs_release_iterator(it);
                    nvs_close(h);
                    free(val);
                    return 0;                          /* too large */
                }
            }
            e = nvs_entry_next(&it);
        }
        nvs_release_iterator(it);
        nvs_close(h);
    }
    memset(val, 0, 4096);
    free(val);
    return pos;
}

static bool ns_allowed(const char *ns)
{
    for (size_t n = 0; n < NUM_NS; n++) {
        if (strcmp(ns, s_namespaces[n]) == 0) return true;
    }
    return false;
}

/* Validate the whole plaintext first, then wipe and write. */
static char s_restored_fw[32];

static bool restore(const uint8_t *p, size_t len, int *count)
{
    s_restored_fw[0] = '\0';
    if (len < 4 || memcmp(p, "UIPB", 4) != 0) return false;
    for (int pass = 0; pass < 2; pass++) {
        if (pass == 1) {
            for (size_t n = 0; n < NUM_NS; n++) {
                nvs_handle_t h;
                if (nvs_open(s_namespaces[n], NVS_READWRITE, &h) == ESP_OK) {
                    nvs_erase_all(h);
                    nvs_commit(h);
                    nvs_close(h);
                }
            }
        }
        size_t pos = 4;
        *count = 0;
        while (pos < len) {
            char ns[16] = "", key[16] = "";
            if (pos + 1 > len) return false;
            uint8_t nl = p[pos++];
            if (nl == 0 || nl >= sizeof(ns) || pos + nl + 1 > len) return false;
            memcpy(ns, p + pos, nl); pos += nl;
            uint8_t kl = p[pos++];
            if (kl == 0 || kl >= sizeof(key) || pos + kl + 3 > len) return false;
            memcpy(key, p + pos, kl); pos += kl;
            uint8_t ty = p[pos++];
            size_t vl = ((size_t)p[pos] << 8) | p[pos + 1];
            pos += 2;
            if (pos + vl > len) return false;          /* truncated: reject the file */
            const uint8_t *v = p + pos;
            pos += vl;
            if (strcmp(ns, "_meta") == 0) {
                if (strcmp(key, "fw") == 0 && ty == NVS_TYPE_STR) {
                    size_t n = vl < sizeof(s_restored_fw) - 1 ? vl : sizeof(s_restored_fw) - 1;
                    memcpy(s_restored_fw, v, n);
                    s_restored_fw[n] = '\0';
                }
                continue;
            }
            if (!ns_allowed(ns)) continue;             /* newer firmware's setting: skip */
            if (pass == 0) { (*count)++; continue; }

            nvs_handle_t h;
            if (nvs_open(ns, NVS_READWRITE, &h) != ESP_OK) return false;
            esp_err_t e = ESP_FAIL;
            switch (ty) {
            case NVS_TYPE_U8:  if (vl == 1) e = nvs_set_u8(h, key, *v); break;
            case NVS_TYPE_I8:  if (vl == 1) e = nvs_set_i8(h, key, (int8_t)*v); break;
            case NVS_TYPE_U16: { uint16_t x; if (vl == 2) { memcpy(&x, v, 2); e = nvs_set_u16(h, key, x); } break; }
            case NVS_TYPE_I16: { int16_t x;  if (vl == 2) { memcpy(&x, v, 2); e = nvs_set_i16(h, key, x); } break; }
            case NVS_TYPE_U32: { uint32_t x; if (vl == 4) { memcpy(&x, v, 4); e = nvs_set_u32(h, key, x); } break; }
            case NVS_TYPE_I32: { int32_t x;  if (vl == 4) { memcpy(&x, v, 4); e = nvs_set_i32(h, key, x); } break; }
            case NVS_TYPE_U64: { uint64_t x; if (vl == 8) { memcpy(&x, v, 8); e = nvs_set_u64(h, key, x); } break; }
            case NVS_TYPE_I64: { int64_t x;  if (vl == 8) { memcpy(&x, v, 8); e = nvs_set_i64(h, key, x); } break; }
            case NVS_TYPE_STR: {
                char *str = malloc(vl + 1);
                if (str) {
                    memcpy(str, v, vl);
                    str[vl] = '\0';
                    e = nvs_set_str(h, key, str);
                    free(str);
                }
                break;
            }
            case NVS_TYPE_BLOB: e = nvs_set_blob(h, key, v, vl); break;
            default: e = ESP_ERR_NOT_SUPPORTED; break;   /* unknown type: skip */
            }
            nvs_commit(h);
            nvs_close(h);
            if (e != ESP_OK) {
                ESP_LOGW(TAG, "restore %s/%s failed: %s", ns, key, esp_err_to_name(e));
            } else {
                (*count)++;
            }
        }
    }
    return true;
}

/* ---- HTTP ---- */

static int read_all(httpd_req_t *req, char *buf, size_t max)
{
    if (req->content_len <= 0 || req->content_len >= max) return -1;
    size_t got = 0;
    while (got < req->content_len) {
        int n = httpd_req_recv(req, buf + got, req->content_len - got);
        if (n == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (n <= 0) return -1;
        got += n;
    }
    buf[got] = '\0';
    return (int)got;
}

static esp_err_t json_err(httpd_req_t *req, const char *status, const char *msg)
{
    char b[160];
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json");
    snprintf(b, sizeof(b), "{\"ok\":false,\"error\":\"%s\"}", msg);
    return httpd_resp_sendstr(req, b);
}

/* Minimal "key":"value" reader (passphrase may contain escaped quotes) */
static bool get_str(const char *json, const char *key, char *out, size_t outlen)
{
    char pat[32];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return false;
    p = strchr(p + strlen(pat), ':');
    if (!p) return false;
    while (*++p == ' ') { }
    if (*p != '"') return false;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < outlen) {
        if (*p == '\\' && p[1]) p++;
        out[i++] = *p++;
    }
    out[i] = '\0';
    return *p == '"';
}

static esp_err_t handle_backup(httpd_req_t *req)
{
    if (!webui_check_auth(req)) return webui_reject_auth(req);

    char body[256], pass[128];
    if (read_all(req, body, sizeof(body)) < 0 || !get_str(body, "passphrase", pass, sizeof(pass))) {
        return json_err(req, "400 Bad Request", "missing passphrase");
    }
    memset(body, 0, sizeof(body));
    if (strlen(pass) < BAK_PASS_MIN) {
        memset(pass, 0, sizeof(pass));
        return json_err(req, "400 Bad Request", "passphrase too short (min 8)");
    }

    uint8_t *plain = heap_caps_malloc(BAK_PLAIN_MAX, MALLOC_CAP_SPIRAM);
    uint8_t *file = heap_caps_malloc(BAK_HDR_LEN + BAK_PLAIN_MAX + BAK_TAG_LEN, MALLOC_CAP_SPIRAM);
    size_t plen = (plain && file) ? serialize(plain) : 0;
    uint8_t key[32];
    size_t clen = 0;
    bool ok = plen > 0;
    if (ok) {
        uint8_t *h = file;
        memcpy(h, BAK_MAGIC, 8);
        h[8] = BAK_VERSION;
        uint32_t it = BAK_ITERATIONS;
        h[9] = it >> 24; h[10] = it >> 16; h[11] = it >> 8; h[12] = it;
        esp_fill_random(h + 13, BAK_SALT_LEN);
        esp_fill_random(h + 13 + BAK_SALT_LEN, BAK_NONCE_LEN);
        ok = pbkdf2_sha256(pass, h + 13, BAK_SALT_LEN, it, key) &&
             aes_gcm(true, key, h + 13 + BAK_SALT_LEN, plain, plen,
                     file + BAK_HDR_LEN, BAK_PLAIN_MAX + BAK_TAG_LEN, &clen);
    }
    memset(pass, 0, sizeof(pass));
    memset(key, 0, sizeof(key));
    if (plain) { memset(plain, 0, BAK_PLAIN_MAX); free(plain); }
    if (!ok) {
        free(file);
        return json_err(req, "500 Internal Server Error", "creating backup failed");
    }

    char host[32] = "usbip", disp[96];
    network_mgr_get_hostname(host, sizeof(host));
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s-settings.usbipbak\"", host);
    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition", disp);
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t r = httpd_resp_send(req, (const char *)file, BAK_HDR_LEN + clen);
    free(file);
    ESP_LOGI(TAG, "Settings backup created (%u bytes)", (unsigned)(BAK_HDR_LEN + clen));
    event_log_add(EVENT_LOG_LEVEL_INFO, "Settings backup downloaded");
    return r;
}

static void restart_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_restart();
}

static esp_err_t handle_restore(httpd_req_t *req)
{
    if (!webui_check_auth(req)) return webui_reject_auth(req);

    const size_t max = 96 * 1024;
    char *body = heap_caps_malloc(max, MALLOC_CAP_SPIRAM);
    if (!body) return json_err(req, "500 Internal Server Error", "out of memory");
    char pass[128];
    if (read_all(req, body, max) < 0 || !get_str(body, "passphrase", pass, sizeof(pass))) {
        free(body);
        return json_err(req, "400 Bad Request", "missing passphrase or file");
    }
    /* "data":"<base64>" */
    char *d = strstr(body, "\"data\"");
    char *q = d ? strchr(d + 6, '"') : NULL;
    char *end = q ? strchr(q + 1, '"') : NULL;
    uint8_t *file = heap_caps_malloc(max, MALLOC_CAP_SPIRAM);
    size_t flen = 0;
    bool ok = end && file &&
              mbedtls_base64_decode(file, max, &flen, (const unsigned char *)(q + 1), end - q - 1) == 0;
    free(body);

    const char *why = "not a backup file of this board type";
    uint8_t *plain = NULL;
    size_t plen = 0;
    if (ok) {
        ok = flen > BAK_HDR_LEN + BAK_TAG_LEN && memcmp(file, BAK_MAGIC, 8) == 0 &&
             file[8] >= 1 && file[8] <= BAK_VERSION;
    }
    if (ok) {
        uint32_t it = ((uint32_t)file[9] << 24) | ((uint32_t)file[10] << 16) | ((uint32_t)file[11] << 8) | file[12];
        uint8_t key[32];
        plain = heap_caps_malloc(flen, MALLOC_CAP_SPIRAM);
        ok = plain && it >= 1000 && it <= 1000000 &&
             pbkdf2_sha256(pass, file + 13, BAK_SALT_LEN, it, key);
        if (ok) {
            ok = aes_gcm(false, key, file + 13 + BAK_SALT_LEN, file + BAK_HDR_LEN, flen - BAK_HDR_LEN,
                         plain, flen, &plen);
            if (!ok) why = "wrong passphrase or damaged file";
        }
        memset(key, 0, sizeof(key));
    }
    memset(pass, 0, sizeof(pass));
    free(file);

    int count = 0;
    if (ok) {
        ok = restore(plain, plen, &count);
        if (!ok) why = "backup content invalid - nothing changed";
    }
    if (plain) { memset(plain, 0, plen); free(plain); }
    if (!ok) {
        return json_err(req, "400 Bad Request", why);
    }

    ESP_LOGW(TAG, "Settings restored from backup (%d entries) - restarting", count);
    event_log_add(EVENT_LOG_LEVEL_WARN, "Settings restored from backup (%d entries)", count);
    char b[128];
    snprintf(b, sizeof(b), "{\"ok\":true,\"entries\":%d,\"from_fw\":\"%s\"}", count, s_restored_fw);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, b);
    xTaskCreate(restart_task, "restore_rst", 2048, NULL, 5, NULL);
    return ESP_OK;
}

void webui_backup_register(httpd_handle_t server)
{
    const httpd_uri_t b = { .uri = "/api/system/backup", .method = HTTP_POST, .handler = handle_backup };
    const httpd_uri_t r = { .uri = "/api/system/restore", .method = HTTP_POST, .handler = handle_restore };
    httpd_register_uri_handler(server, &b);
    httpd_register_uri_handler(server, &r);
}
