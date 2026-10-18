/*
 * Web UI - HTTP server with embedded frontend and WebSocket support
 */

#include "webui.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "device_manager.h"
#include "event_log.h"
#include "access_control.h"
#include "network_mgr.h"
#include "psa/crypto.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mbedtls/base64.h"
#if CONFIG_CAPTURE_ENABLED
#include "capture.h"
#endif

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "esp_random.h"
#include "lwip/sockets.h"
#include "sdkconfig.h"
#include "sec_tls.h"
#include "esp_https_server.h"
#include "esp_app_desc.h"

static const char *TAG = "webui";

/* ---- Authentication ---- */

#define AUTH_NVS_NAMESPACE "auth"
#define AUTH_MAX_USERNAME 32
#define AUTH_SALT_LEN     16
/* Iterated, salted SHA-256 (cheap stand-in for PBKDF2 that only needs the PSA
 * hash API already used here). The verified Authorization header is cached so
 * the iteration cost is paid once per browser session, not per request. */
#define AUTH_HASH_ITERATIONS 4096
/* Brute-force throttling per client IP */
#define AUTH_MAX_FAILS     5
#define AUTH_LOCKOUT_US    (30LL * 1000 * 1000)
#define AUTH_TRACK_SLOTS   8

static bool s_auth_enabled = false;
static char s_auth_username[AUTH_MAX_USERNAME] = "";
static uint8_t s_auth_password_hash[32] = {0};
static uint8_t s_auth_salt[AUTH_SALT_LEN] = {0};
static bool s_auth_has_salt = false;      /* false = legacy unsalted SHA-256 */
static bool s_auth_has_password = false;

/* Cache of the last successfully verified Authorization header (as SHA-256) */
static uint8_t s_auth_cache[32];
static bool s_auth_cache_valid = false;

typedef struct {
    uint32_t ip;
    uint8_t fails;
    int64_t locked_until_us;
} auth_track_t;
static auth_track_t s_auth_track[AUTH_TRACK_SLOTS];

/* Why the last check failed (httpd runs handlers in a single task) */
typedef enum {
    REJ_AUTH = 0,       /* 401 + WWW-Authenticate */
    REJ_FORBIDDEN_IP,   /* 403: IP not in ACL allowlist */
    REJ_CSRF,           /* 403: cross-site request */
    REJ_NEED_PASSWORD,  /* 403: secure default, set a password first */
    REJ_LOCKED,         /* 429: too many failed logins */
} reject_reason_t;
static reject_reason_t s_reject_reason = REJ_AUTH;

static void auth_load_from_nvs(void)
{
    nvs_handle_t nvs;
    if (nvs_open(AUTH_NVS_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK) return;
    uint8_t en = 0;
    nvs_get_u8(nvs, "enabled", &en);
    s_auth_enabled = (en != 0);
    size_t len = sizeof(s_auth_username);
    nvs_get_str(nvs, "username", s_auth_username, &len);
    len = sizeof(s_auth_password_hash);
    if (nvs_get_blob(nvs, "pw_hash", s_auth_password_hash, &len) == ESP_OK && len == 32) {
        static const uint8_t zero[32] = {0};
        s_auth_has_password = memcmp(s_auth_password_hash, zero, 32) != 0;
    }
    len = sizeof(s_auth_salt);
    s_auth_has_salt = (nvs_get_blob(nvs, "pw_salt", s_auth_salt, &len) == ESP_OK &&
                       len == AUTH_SALT_LEN);
    nvs_close(nvs);
    if (s_auth_enabled && !s_auth_has_password) {
        /* Never run "enabled" without a real password hash */
        s_auth_enabled = false;
    }
}

/* SHA-256 via the PSA API. mbedTLS 4.x (IDF 6.0) moved mbedtls_sha256() to a
 * private header; psa_hash_compute() is the supported replacement. */
static void sha256_compute(const uint8_t *input, size_t len, uint8_t out[32])
{
    static bool psa_inited = false;
    if (!psa_inited) { psa_crypto_init(); psa_inited = true; }
    size_t olen = 0;
    psa_hash_compute(PSA_ALG_SHA_256, input, len, out, 32, &olen);
}

/* Constant-time comparison (no early exit) */
static bool ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

/* h0 = SHA256(salt || password); h(i) = SHA256(salt || h(i-1)) */
static void hash_password_salted(const char *password, const uint8_t salt[AUTH_SALT_LEN],
                                 uint8_t out[32])
{
    size_t plen = strlen(password);
    uint8_t buf[AUTH_SALT_LEN + 64];
    if (plen > 64) plen = 64;
    memcpy(buf, salt, AUTH_SALT_LEN);
    memcpy(buf + AUTH_SALT_LEN, password, plen);
    sha256_compute(buf, AUTH_SALT_LEN + plen, out);
    for (int i = 1; i < AUTH_HASH_ITERATIONS; i++) {
        memcpy(buf + AUTH_SALT_LEN, out, 32);
        sha256_compute(buf, AUTH_SALT_LEN + 32, out);
    }
    memset(buf, 0, sizeof(buf));
}

static void auth_store_nvs(void)
{
    nvs_handle_t nvs;
    if (nvs_open(AUTH_NVS_NAMESPACE, NVS_READWRITE, &nvs) != ESP_OK) return;
    nvs_set_u8(nvs, "enabled", s_auth_enabled ? 1 : 0);
    nvs_set_str(nvs, "username", s_auth_username);
    nvs_set_blob(nvs, "pw_hash", s_auth_password_hash, 32);
    if (s_auth_has_salt) {
        nvs_set_blob(nvs, "pw_salt", s_auth_salt, AUTH_SALT_LEN);
    }
    nvs_commit(nvs);
    nvs_close(nvs);
}

static void auth_set_password(const char *password)
{
    esp_fill_random(s_auth_salt, sizeof(s_auth_salt));
    hash_password_salted(password, s_auth_salt, s_auth_password_hash);
    s_auth_has_salt = true;
    s_auth_has_password = true;
}

esp_err_t webui_auth_save(bool enabled, const char *username, const char *password)
{
    /* Empty password field = "keep the current password". Previously an empty
     * field overwrote the stored hash with SHA-256(""), silently enabling
     * login with an empty password. */
    bool new_pw = (password && password[0] != '\0');
    if (enabled && !new_pw && !s_auth_has_password) {
        return ESP_ERR_INVALID_ARG;   /* cannot enable auth without a password */
    }
    if (username && username[0] != '\0') {
        strncpy(s_auth_username, username, AUTH_MAX_USERNAME - 1);
        s_auth_username[AUTH_MAX_USERNAME - 1] = '\0';
    }
    if (new_pw) {
        auth_set_password(password);
    }
    s_auth_enabled = enabled;
    s_auth_cache_valid = false;           /* force re-verification */
    memset(s_auth_track, 0, sizeof(s_auth_track));
    auth_store_nvs();
    return ESP_OK;
}

bool webui_auth_enabled(void)
{
    return s_auth_enabled;
}

bool webui_auth_has_password(void)
{
    return s_auth_has_password;
}

const char *webui_auth_username(void)
{
    return s_auth_username;
}

/* Client IPv4 of a request (network byte order); 0 if unknown.
 * The HTTP server listens on an IPv6 socket when IPv6 is enabled, so IPv4
 * peers show up as v4-mapped addresses (::ffff:a.b.c.d). */
uint32_t webui_req_client_ip(httpd_req_t *req)
{
    int fd = httpd_req_to_sockfd(req);
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    if (fd < 0 || getpeername(fd, (struct sockaddr *)&addr, &len) != 0) {
        return 0;
    }
    if (addr.ss_family == AF_INET) {
        return ((struct sockaddr_in *)&addr)->sin_addr.s_addr;
    }
#if CONFIG_LWIP_IPV6
    if (addr.ss_family == AF_INET6) {
        const uint8_t *b = ((struct sockaddr_in6 *)&addr)->sin6_addr.s6_addr;
        uint32_t v4;
        memcpy(&v4, b + 12, 4);
        return v4;
    }
#endif
    return 0;
}

static auth_track_t *auth_track_get(uint32_t ip, bool create)
{
    auth_track_t *free_slot = NULL, *oldest = &s_auth_track[0];
    for (int i = 0; i < AUTH_TRACK_SLOTS; i++) {
        if (s_auth_track[i].ip == ip && ip != 0) return &s_auth_track[i];
        if (s_auth_track[i].ip == 0 && !free_slot) free_slot = &s_auth_track[i];
        if (s_auth_track[i].locked_until_us < oldest->locked_until_us) oldest = &s_auth_track[i];
    }
    if (!create) return NULL;
    auth_track_t *t = free_slot ? free_slot : oldest;
    memset(t, 0, sizeof(*t));
    t->ip = ip;
    return t;
}

/* Cross-site request forgery guard for state-changing requests.
 * Browsers cannot add custom headers to cross-origin requests without a CORS
 * preflight (which this server never approves), so requiring X-USBIP-CSRF
 * blocks forms/fetches from foreign web pages. Origin, when sent, must match. */
static bool csrf_ok(httpd_req_t *req)
{
    if (httpd_req_get_hdr_value_len(req, "X-USBIP-CSRF") == 0) {
        return false;
    }
    char origin[96];
    if (httpd_req_get_hdr_value_str(req, "Origin", origin, sizeof(origin)) == ESP_OK) {
        char host[96] = "";
        httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host));
        const char *o = strstr(origin, "://");
        o = o ? o + 3 : origin;
        if (strcmp(o, host) != 0) {
            return false;
        }
    }
    return true;
}

static bool auth_check_request(httpd_req_t *req)
{
    s_reject_reason = REJ_AUTH;
    uint32_t ip = webui_req_client_ip(req);

    /* 1. IP allowlist also protects the Web UI (closed mode) */
    if (access_control_is_closed_mode() && !access_control_is_allowed(ip)) {
        s_reject_reason = REJ_FORBIDDEN_IP;
        return false;
    }

    bool is_write = (req->method != HTTP_GET);

    /* 2. CSRF protection for every state-changing request */
    if (is_write && !csrf_ok(req)) {
        s_reject_reason = REJ_CSRF;
        return false;
    }

    /* 3. No password configured */
    if (!s_auth_enabled) {
#if CONFIG_USBIP_WEBUI_REQUIRE_PASSWORD
        if (is_write && strcmp(req->uri, "/api/settings/auth") != 0) {
            s_reject_reason = REJ_NEED_PASSWORD;
            return false;
        }
#endif
        return true;
    }

    /* 4. Brute-force lockout */
    int64_t now = esp_timer_get_time();
    auth_track_t *t = auth_track_get(ip, false);
    if (t && t->locked_until_us > now) {
        s_reject_reason = REJ_LOCKED;
        return false;
    }

    char auth_buf[256];
    if (httpd_req_get_hdr_value_str(req, "Authorization", auth_buf, sizeof(auth_buf)) != ESP_OK) {
        return false;
    }

    /* 5. Fast path: same header as the last verified one */
    uint8_t hdr_hash[32];
    sha256_compute((const uint8_t *)auth_buf, strlen(auth_buf), hdr_hash);
    if (s_auth_cache_valid && ct_equal(hdr_hash, s_auth_cache, 32)) {
        return true;
    }

    bool ok = false;
    if (strncmp(auth_buf, "Basic ", 6) == 0) {
        unsigned char decoded[128];
        size_t decoded_len = 0;
        if (mbedtls_base64_decode(decoded, sizeof(decoded) - 1, &decoded_len,
                                  (const unsigned char *)(auth_buf + 6),
                                  strlen(auth_buf + 6)) == 0) {
            decoded[decoded_len] = '\0';
            char *colon = strchr((char *)decoded, ':');
            if (colon) {
                *colon = '\0';
                const char *user = (const char *)decoded;
                const char *pass = colon + 1;
                bool user_ok = (strcmp(user, s_auth_username) == 0);
                uint8_t hash[32];
                if (s_auth_has_salt) {
                    hash_password_salted(pass, s_auth_salt, hash);
                } else {
                    sha256_compute((const uint8_t *)pass, strlen(pass), hash);  /* legacy */
                }
                ok = user_ok && s_auth_has_password && ct_equal(hash, s_auth_password_hash, 32);
                if (ok && !s_auth_has_salt) {
                    /* Transparently upgrade a legacy unsalted hash */
                    auth_set_password(pass);
                    auth_store_nvs();
                    ESP_LOGI(TAG, "Upgraded stored password hash to salted format");
                }
            }
            memset(decoded, 0, sizeof(decoded));
        }
    }

    if (ok) {
        memcpy(s_auth_cache, hdr_hash, 32);
        s_auth_cache_valid = true;
        if (t) memset(t, 0, sizeof(*t));
        return true;
    }

    t = auth_track_get(ip, true);
    if (++t->fails >= AUTH_MAX_FAILS) {
        t->fails = 0;
        t->locked_until_us = now + AUTH_LOCKOUT_US;
        char ip_str[16];
        const uint8_t *b = (const uint8_t *)&ip;
        snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
        ESP_LOGW(TAG, "Too many failed Web UI logins from %s - locked for 30 s", ip_str);
        event_log_add(EVENT_LOG_LEVEL_WARN, "Web UI login locked for 30 s: %s", ip_str);
        s_reject_reason = REJ_LOCKED;
    }
    return false;
}

static esp_err_t auth_reject(httpd_req_t *req)
{
    switch (s_reject_reason) {
    case REJ_FORBIDDEN_IP:
        httpd_resp_set_status(req, "403 Forbidden");
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"IP address not in access-control allowlist\"}");
    case REJ_CSRF:
        httpd_resp_set_status(req, "403 Forbidden");
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"Cross-site request rejected\"}");
    case REJ_NEED_PASSWORD:
        httpd_resp_set_status(req, "403 Forbidden");
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"Set a Web UI password first (Settings -> Authentication)\"}");
    case REJ_LOCKED:
        httpd_resp_set_status(req, "429 Too Many Requests");
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"Too many failed logins - try again in 30 s\"}");
    case REJ_AUTH:
    default:
        httpd_resp_set_status(req, "401 Unauthorized");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"USB/IP Server\"");
        return httpd_resp_send(req, "Unauthorized", HTTPD_RESP_USE_STRLEN);
    }
}

/* Public auth wrappers for use by webui_api.c */
bool webui_check_auth(httpd_req_t *req)
{
    return auth_check_request(req);
}

esp_err_t webui_reject_auth(httpd_req_t *req)
{
    return auth_reject(req);
}

/* External symbols for embedded frontend files */
extern const uint8_t index_html_start[] asm("_binary_index_html_start");
extern const uint8_t index_html_end[]   asm("_binary_index_html_end");
extern const uint8_t style_css_start[] asm("_binary_style_css_start");
extern const uint8_t style_css_end[]   asm("_binary_style_css_end");
extern const uint8_t app_js_start[] asm("_binary_app_js_start");
extern const uint8_t app_js_end[]   asm("_binary_app_js_end");
extern const uint8_t lang_de_start[] asm("_binary_de_json_start");
extern const uint8_t lang_de_end[]   asm("_binary_de_json_end");
extern const uint8_t lang_en_start[] asm("_binary_en_json_start");
extern const uint8_t lang_en_end[]   asm("_binary_en_json_end");
extern const uint8_t lang_fr_start[] asm("_binary_fr_json_start");
extern const uint8_t lang_fr_end[]   asm("_binary_fr_json_end");
extern const uint8_t lang_es_start[] asm("_binary_es_json_start");
extern const uint8_t lang_es_end[]   asm("_binary_es_json_end");
extern const uint8_t lang_it_start[] asm("_binary_it_json_start");
extern const uint8_t lang_it_end[]   asm("_binary_it_json_end");
extern const uint8_t lang_pt_start[] asm("_binary_pt_json_start");
extern const uint8_t lang_pt_end[]   asm("_binary_pt_json_end");
extern const uint8_t lang_da_start[] asm("_binary_da_json_start");
extern const uint8_t lang_da_end[]   asm("_binary_da_json_end");
extern const uint8_t lang_sv_start[] asm("_binary_sv_json_start");
extern const uint8_t lang_sv_end[]   asm("_binary_sv_json_end");
extern const uint8_t lang_ru_start[] asm("_binary_ru_json_start");
extern const uint8_t lang_ru_end[]   asm("_binary_ru_json_end");
extern const uint8_t lang_uk_start[] asm("_binary_uk_json_start");
extern const uint8_t lang_uk_end[]   asm("_binary_uk_json_end");
extern const uint8_t lang_tr_start[] asm("_binary_tr_json_start");
extern const uint8_t lang_tr_end[]   asm("_binary_tr_json_end");
extern const uint8_t lang_ar_start[] asm("_binary_ar_json_start");
extern const uint8_t lang_ar_end[]   asm("_binary_ar_json_end");

/* Declarations from ws_handler.c */
extern void ws_handler_init(httpd_handle_t server);
extern esp_err_t ws_handler(httpd_req_t *req);
extern void ws_broadcast_stats(void);

static httpd_handle_t s_server = NULL;
static httpd_handle_t s_redirect_server = NULL;   /* port 80 -> https while HTTPS is on */
static esp_timer_handle_t s_stats_timer = NULL;

/* ---- Embedded file serving handlers ---- */

static esp_err_t handle_index(httpd_req_t *req)
{
    if (!auth_check_request(req)) return auth_reject(req);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, (const char *)index_html_start,
                    index_html_end - index_html_start);
    return ESP_OK;
}

static esp_err_t handle_settings(httpd_req_t *req)
{
    /* Redirect /settings to /#settings (SPA) */
    if (!auth_check_request(req)) return auth_reject(req);
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/#settings");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t handle_style_css(httpd_req_t *req)
{
    if (!auth_check_request(req)) return auth_reject(req);
    httpd_resp_set_type(req, "text/css");
    httpd_resp_send(req, (const char *)style_css_start,
                    style_css_end - style_css_start);
    return ESP_OK;
}

static esp_err_t handle_app_js(httpd_req_t *req)
{
    if (!auth_check_request(req)) return auth_reject(req);
    httpd_resp_set_type(req, "application/javascript");
    httpd_resp_send(req, (const char *)app_js_start,
                    app_js_end - app_js_start);
    return ESP_OK;
}

/* UI language files (frontend/lang/xx.json), fetched by the page on demand */
static const struct { const char *code; const uint8_t *start, *end; } s_langs[] = {
    { "de", lang_de_start, lang_de_end },
    { "en", lang_en_start, lang_en_end },
    { "fr", lang_fr_start, lang_fr_end },
    { "es", lang_es_start, lang_es_end },
    { "it", lang_it_start, lang_it_end },
    { "pt", lang_pt_start, lang_pt_end },
    { "da", lang_da_start, lang_da_end },
    { "sv", lang_sv_start, lang_sv_end },
    { "ru", lang_ru_start, lang_ru_end },
    { "uk", lang_uk_start, lang_uk_end },
    { "tr", lang_tr_start, lang_tr_end },
    { "ar", lang_ar_start, lang_ar_end },
};

static esp_err_t handle_lang(httpd_req_t *req)
{
    if (!auth_check_request(req)) return auth_reject(req);
    char q[16], code[4] = "";
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        httpd_query_key_value(q, "l", code, sizeof(code));
    }
    for (size_t i = 0; i < sizeof(s_langs) / sizeof(s_langs[0]); i++) {
        if (strcmp(code, s_langs[i].code) == 0) {
            httpd_resp_set_type(req, "application/json; charset=utf-8");
            httpd_resp_set_hdr(req, "Cache-Control", "no-cache");   /* new firmware = new texts */
            return httpd_resp_send(req, (const char *)s_langs[i].start,
                                   s_langs[i].end - s_langs[i].start);
        }
    }
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "unknown language");
    return ESP_FAIL;
}

/* ---- JSON API handlers ---- */

static esp_err_t handle_api_devices(httpd_req_t *req)
{
    if (!auth_check_request(req)) return auth_reject(req);
    httpd_resp_set_type(req, "application/json");

    /* Build JSON array of devices */
    char json_buf[2048];
    int pos = 0;
    int buflen = sizeof(json_buf);

    pos += snprintf(json_buf + pos, buflen - pos, "[");
    int dev_count = device_manager_get_count();
    int printed = 0;

    for (int i = 0; i < DEVICE_MANAGER_MAX_DEVICES && printed < dev_count; i++) {
        dm_device_info_t info;
        if (device_manager_get(i, &info) != ESP_OK || !info.in_use) continue;

        if (printed > 0) pos += snprintf(json_buf + pos, buflen - pos, ",");

        pos += snprintf(json_buf + pos, buflen - pos,
            "{\"index\":%d,\"path\":\"%s\",\"vid\":%u,\"pid\":%u,"
            "\"speed\":%d,\"state\":%d,\"client_ip\":%lu,"
            "\"class\":%u,\"subclass\":%u,\"protocol\":%u}",
            i, info.path,
            (unsigned)info.vendor_id, (unsigned)info.product_id,
            (int)info.speed, (int)info.state,
            (unsigned long)info.client_ip,
            (unsigned)info.dev_class, (unsigned)info.dev_subclass,
            (unsigned)info.dev_protocol);
        printed++;
    }

    pos += snprintf(json_buf + pos, buflen - pos, "]");
    httpd_resp_send(req, json_buf, pos);
    return ESP_OK;
}

static esp_err_t handle_api_stats(httpd_req_t *req)
{
    if (!auth_check_request(req)) return auth_reject(req);
    httpd_resp_set_type(req, "application/json");

    char json_buf[256];
    uint32_t free_heap = esp_get_free_heap_size();
    int64_t uptime_us = esp_timer_get_time();
    int uptime_sec = (int)(uptime_us / 1000000);
    int dev_count = device_manager_get_count();

    char ip_str[20] = "0.0.0.0";
    network_mgr_get_ip_str(ip_str, sizeof(ip_str));

    int len = snprintf(json_buf, sizeof(json_buf),
        "{\"free_heap\":%lu,\"uptime_sec\":%d,\"device_count\":%d,"
        "\"ip\":\"%s\",\"idf_version\":\"%s\"}",
        (unsigned long)free_heap, uptime_sec, dev_count,
        ip_str, esp_get_idf_version());

    httpd_resp_send(req, json_buf, len);
    return ESP_OK;
}

static esp_err_t handle_api_logs(httpd_req_t *req)
{
    if (!auth_check_request(req)) return auth_reject(req);
    httpd_resp_set_type(req, "application/json");

    char json_buf[4096];
    int pos = 0;
    int buflen = sizeof(json_buf);

    event_log_entry_t entries[50];
    size_t count = 0;
    event_log_get_recent(entries, 50, &count);

    pos += snprintf(json_buf + pos, buflen - pos, "[");
    for (size_t i = 0; i < count; i++) {
        if (i > 0) pos += snprintf(json_buf + pos, buflen - pos, ",");

        /* Escape message for JSON */
        char escaped[EVENT_LOG_MSG_MAX_LEN * 2];
        int ep = 0;
        for (int j = 0; entries[i].message[j] && ep < (int)sizeof(escaped) - 2; j++) {
            char c = entries[i].message[j];
            if (c == '"' || c == '\\') escaped[ep++] = '\\';
            if (c == '\n') { escaped[ep++] = '\\'; escaped[ep++] = 'n'; continue; }
            escaped[ep++] = c;
        }
        escaped[ep] = '\0';

        pos += snprintf(json_buf + pos, buflen - pos,
            "{\"ts\":%lld,\"level\":%d,\"msg\":\"%s\"}",
            entries[i].timestamp_us,
            (int)entries[i].level,
            escaped);
    }
    pos += snprintf(json_buf + pos, buflen - pos, "]");

    httpd_resp_send(req, json_buf, pos);
    return ESP_OK;
}

/* ---- Log export (download as .txt) ---- */

/* Drop ANSI colour sequences (ESC [ ... m) from the system log; the state
 * carries over chunk borders. Returns the new length. */
static size_t strip_ansi(char *buf, size_t len, int *state)
{
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        char c = buf[i];
        if (*state == 0) {
            if (c == 0x1b) { *state = 1; continue; }
            buf[o++] = c;
        } else if (*state == 1) {
            *state = (c == '[') ? 2 : 0;
        } else if (c >= 0x40 && c <= 0x7e) {
            *state = 0;                      /* final byte of the sequence */
        }
    }
    return o;
}

/* type=events (default) | system | previous (log tail before the last restart) */
static esp_err_t handle_api_logs_export(httpd_req_t *req)
{
    if (!auth_check_request(req)) return auth_reject(req);

    char type[12] = "events";
    char q[32];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        httpd_query_key_value(q, "type", type, sizeof(type));
    }
    bool system = strcmp(type, "system") == 0;
    bool previous = strcmp(type, "previous") == 0;
    const char *kind = system ? "system" : previous ? "before-restart" : "events";

    char host[32] = "usbip";
    network_mgr_get_hostname(host, sizeof(host));
    int64_t up = esp_timer_get_time() / 1000000;
    char disp[112];
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s-%s-log-%llds.txt\"",
             host, kind, (long long)up);
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_set_hdr(req, "Content-Disposition", disp);
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");

    const size_t bufsz = 4096;
    char *buf = malloc(bufsz);
    if (!buf) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory");
        return ESP_FAIL;
    }
    int n = snprintf(buf, bufsz,
        "# %s %s log - firmware %s, ESP-IDF %s\n"
        "# uptime %lld s, free heap %lu bytes, last restart: %s\n"
        "# Timestamps: time since boot%s.\n\n",
        host, kind, esp_app_get_description()->version, esp_get_idf_version(),
        (long long)up, (unsigned long)esp_get_free_heap_size(), event_log_reset_reason_str(),
        previous ? " of the previous run" : "");
    esp_err_t err = httpd_resp_send_chunk(req, buf, n);

    if (system || previous) {
        uint64_t pos = 0;
        int ansi = 0;
        size_t got;
        while (err == ESP_OK &&
               (got = previous ? event_log_previous_read(&pos, buf, bufsz)
                               : event_log_syslog_read(&pos, buf, bufsz)) > 0) {
            size_t len = strip_ansi(buf, got, &ansi);
            if (len) err = httpd_resp_send_chunk(req, buf, len);
        }
    } else {
        static const char *lvl[] = { "DEBUG", "INFO ", "WARN ", "ERROR" };
        event_log_entry_t *e = malloc(sizeof(event_log_entry_t) * 16);
        size_t skip = 0, cnt = 0;
        while (e && err == ESP_OK && event_log_get_oldest(skip, e, 16, &cnt) == ESP_OK && cnt > 0) {
            size_t o = 0;
            for (size_t i = 0; i < cnt; i++) {
                int64_t ms = e[i].timestamp_us / 1000;
                o += snprintf(buf + o, bufsz - o, "%6lld.%03lld  %s  %s\n",
                              (long long)(ms / 1000), (long long)(ms % 1000),
                              lvl[e[i].level & 3], e[i].message);
            }
            err = httpd_resp_send_chunk(req, buf, o);
            skip += cnt;
        }
        free(e);
    }
    free(buf);
    if (err == ESP_OK) {
        httpd_resp_send_chunk(req, NULL, 0);
    }
    return err;
}

#if !CONFIG_CAPTURE_ENABLED
/* Capture not compiled in: answer the UI's status check instead of a 404
 * (which logged a warning on every page load). */
static esp_err_t handle_capture_unavailable(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"available\":false}");
}
#endif

static esp_err_t handle_api_restart(httpd_req_t *req)
{
    if (!auth_check_request(req)) return auth_reject(req);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"status\":\"restarting\"}", -1);

    /* Delay slightly to allow response to be sent */
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();

    return ESP_OK; /* unreachable */
}

/* ---- WebSocket handler wrapper ---- */

static esp_err_t handle_ws(httpd_req_t *req)
{
    if (!auth_check_request(req)) return auth_reject(req);
    return ws_handler(req);
}

/* ---- Stats broadcast timer callback ---- */

static void stats_timer_cb(void *arg)
{
    ws_broadcast_stats();
}

static bool s_https_active;

/* Port 80 while HTTPS is on: send every request to the same path on https://.
 * The Host header is only reused when it looks like a host name or IP
 * (no header injection, no redirect to elsewhere via odd characters);
 * otherwise the board's own IP is used. */
static esp_err_t handle_https_redirect(httpd_req_t *req)
{
    char host[72] = "";
    if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) == ESP_OK) {
        char *colon = strchr(host, ':');
        if (colon) *colon = '\0';                       /* drop :80 */
        for (const char *c = host; *c; c++) {
            if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
                  (*c >= '0' && *c <= '9') || *c == '.' || *c == '-')) {
                host[0] = '\0';
                break;
            }
        }
    }
    if (!host[0]) {
        network_mgr_get_ip_str(host, sizeof(host));
    }

    char location[sizeof(host) + 256];
    const char *uri = req->uri[0] == '/' ? req->uri : "/";
    int n = snprintf(location, sizeof(location), "https://%s%s", host, uri);
    if (n < 0 || n >= (int)sizeof(location)) {
        snprintf(location, sizeof(location), "https://%s/", host);
    }
    httpd_resp_set_status(req, "301 Moved Permanently");
    httpd_resp_set_hdr(req, "Location", location);
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");   /* switching HTTPS off must work again */
    httpd_resp_set_type(req, "text/plain");
    return httpd_resp_sendstr(req, "Moved to HTTPS\n");
}

static void start_https_redirect(void)
{
    httpd_config_t rc = HTTPD_DEFAULT_CONFIG();
    rc.server_port = 80;
    rc.ctrl_port = ESP_HTTPD_DEF_CTRL_PORT + 2;   /* +0 is free, +1 is the HTTPS server */
    rc.core_id = 1;
    rc.stack_size = 4096;
    rc.max_open_sockets = 2;
    rc.max_uri_handlers = 1;
    rc.lru_purge_enable = true;
    rc.recv_wait_timeout = 5;
    rc.send_wait_timeout = 5;
    rc.uri_match_fn = httpd_uri_match_wildcard;
    if (httpd_start(&s_redirect_server, &rc) != ESP_OK) {
        ESP_LOGW(TAG, "HTTP->HTTPS redirect on port 80 not started");
        s_redirect_server = NULL;
        return;
    }
    const httpd_uri_t any = { .uri = "/*", .method = HTTP_GET, .handler = handle_https_redirect };
    httpd_register_uri_handler(s_redirect_server, &any);
    ESP_LOGI(TAG, "Port 80 redirects to HTTPS");
}

bool webui_https_active(void)
{
    return s_https_active;
}

/* ---- Public API ---- */

esp_err_t webui_init(void)
{
    auth_load_from_nvs();

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.core_id = 1;
    config.task_priority = 5;
    config.stack_size = 8192;
    config.max_uri_handlers = 48;     /* 32 was exhausted with all features enabled */
    config.max_open_sockets = 7;      /* was 4; starved slots wedged the server (LWIP_MAX_SOCKETS raised to 16) */
    config.lru_purge_enable = true;   /* reclaim the oldest socket instead of refusing new connections when full */
    config.recv_wait_timeout = 10;    /* seconds; don't let a stalled peer pin a slot indefinitely */
    config.send_wait_timeout = 10;

    esp_err_t ret = ESP_FAIL;
    s_https_active = false;
    const char *cert = NULL, *key = NULL;
    size_t cert_len = 0, key_len = 0;
    if (sectls_https_enabled() &&
        sectls_get_https_cert(&cert, &cert_len, &key, &key_len) == ESP_OK) {
        httpd_ssl_config_t ssl = HTTPD_SSL_CONFIG_DEFAULT();
        ssl.httpd = config;
        ssl.httpd.max_open_sockets = 4;   /* each TLS session holds ~35 KB */
        ssl.servercert = (const uint8_t *)cert;
        ssl.servercert_len = cert_len;
        ssl.prvtkey_pem = (const uint8_t *)key;
        ssl.prvtkey_len = key_len;
        ssl.port_secure = 443;
        ret = httpd_ssl_start(&s_server, &ssl);
        if (ret == ESP_OK) {
            s_https_active = true;
            ESP_LOGI(TAG, "Web UI: HTTPS on port 443");
        } else {
            ESP_LOGE(TAG, "HTTPS start failed (%s) - falling back to HTTP", esp_err_to_name(ret));
            event_log_add(EVENT_LOG_LEVEL_WARN, "HTTPS failed - web UI on plain HTTP");
        }
    }
    if (ret != ESP_OK) {
        ret = httpd_start(&s_server, &config);
    }
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server: %s", esp_err_to_name(ret));
        return ret;
    }

    /* Initialize WebSocket handler */
    ws_handler_init(s_server);

    /* Register URI handlers */

    /* Static file routes */
    const httpd_uri_t uri_index = {
        .uri = "/", .method = HTTP_GET,
        .handler = handle_index, .user_ctx = NULL
    };
    httpd_register_uri_handler(s_server, &uri_index);

    const httpd_uri_t uri_settings = {
        .uri = "/settings", .method = HTTP_GET,
        .handler = handle_settings, .user_ctx = NULL
    };
    httpd_register_uri_handler(s_server, &uri_settings);

    const httpd_uri_t uri_css = {
        .uri = "/style.css", .method = HTTP_GET,
        .handler = handle_style_css, .user_ctx = NULL
    };
    httpd_register_uri_handler(s_server, &uri_css);

    const httpd_uri_t uri_lang = {
        .uri = "/lang", .method = HTTP_GET,
        .handler = handle_lang, .user_ctx = NULL
    };
    httpd_register_uri_handler(s_server, &uri_lang);

    const httpd_uri_t uri_app_js = {
        .uri = "/app.js", .method = HTTP_GET,
        .handler = handle_app_js, .user_ctx = NULL
    };
    httpd_register_uri_handler(s_server, &uri_app_js);

    /* API routes */
    const httpd_uri_t uri_api_devices = {
        .uri = "/api/devices", .method = HTTP_GET,
        .handler = handle_api_devices, .user_ctx = NULL
    };
    httpd_register_uri_handler(s_server, &uri_api_devices);

    const httpd_uri_t uri_api_stats = {
        .uri = "/api/stats", .method = HTTP_GET,
        .handler = handle_api_stats, .user_ctx = NULL
    };
    httpd_register_uri_handler(s_server, &uri_api_stats);

    const httpd_uri_t uri_api_logs = {
        .uri = "/api/logs", .method = HTTP_GET,
        .handler = handle_api_logs, .user_ctx = NULL
    };
    httpd_register_uri_handler(s_server, &uri_api_logs);

    const httpd_uri_t uri_api_logs_export = {
        .uri = "/api/logs/export", .method = HTTP_GET,
        .handler = handle_api_logs_export, .user_ctx = NULL
    };
    httpd_register_uri_handler(s_server, &uri_api_logs_export);

    const httpd_uri_t uri_api_restart = {
        .uri = "/api/restart", .method = HTTP_POST,
        .handler = handle_api_restart, .user_ctx = NULL
    };
    httpd_register_uri_handler(s_server, &uri_api_restart);

    /* WebSocket route */
    const httpd_uri_t uri_ws = {
        .uri = "/ws", .method = HTTP_GET,
        .handler = handle_ws, .user_ctx = NULL,
        .is_websocket = true,
    };
    httpd_register_uri_handler(s_server, &uri_ws);

    /* Register REST API endpoints */
    webui_api_register(s_server);

#if !CONFIG_CAPTURE_ENABLED
    const httpd_uri_t uri_cap_status = {
        .uri = "/api/capture/status", .method = HTTP_GET,
        .handler = handle_capture_unavailable, .user_ctx = NULL
    };
    httpd_register_uri_handler(s_server, &uri_cap_status);
#endif
#if CONFIG_CAPTURE_ENABLED
    /* Register capture API endpoints */
    capture_api_register(s_server);
#endif

    /* Create stats broadcast timer (500ms interval) */
    const esp_timer_create_args_t timer_args = {
        .callback = stats_timer_cb,
        .name = "ws_stats",
    };
    ret = esp_timer_create(&timer_args, &s_stats_timer);
    if (ret == ESP_OK) {
        esp_timer_start_periodic(s_stats_timer, 500 * 1000); /* 500ms in us */
    }

    if (s_https_active) {
        start_https_redirect();
    }
    ESP_LOGI(TAG, "Web UI initialized on port %d", s_https_active ? 443 : 80);
    return ESP_OK;
}

esp_err_t webui_stop(void)
{
    if (s_stats_timer) {
        esp_timer_stop(s_stats_timer);
        esp_timer_delete(s_stats_timer);
        s_stats_timer = NULL;
    }

    if (s_server) {
        httpd_stop(s_server);
        s_server = NULL;
    }
    if (s_redirect_server) {
        httpd_stop(s_redirect_server);
        s_redirect_server = NULL;
    }

    ESP_LOGI(TAG, "Web UI stopped");
    return ESP_OK;
}

void webui_notify_device_change(void)
{
    /* Trigger an immediate stats broadcast when devices change */
    ws_broadcast_stats();
}
