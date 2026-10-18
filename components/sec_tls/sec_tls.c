/*
 * Transport encryption: USB/IP over TLS-PSK (proxy) and HTTPS certificate.
 * See sec_tls.h for the overview.
 */
#include "sec_tls.h"
#include "event_log.h"
#include "access_control.h"

#include "esp_log.h"
#include "esp_random.h"
#include "nvs.h"
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "psa/crypto.h"

#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#ifndef CONFIG_USBIP_TLS_PORT
#define CONFIG_USBIP_TLS_PORT 3241
#endif
#ifndef CONFIG_USBIP_TCP_PORT
#define CONFIG_USBIP_TCP_PORT 3240
#endif
#ifndef CONFIG_USBIP_MAX_CLIENTS
#define CONFIG_USBIP_MAX_CLIENTS 4
#endif

static const char *TAG = "sectls";
static const char *NVS_NS = "sectls";

#define HANDSHAKE_TIMEOUT_MS  10000
#define PUMP_BUF              4096
#define CERT_PEM_MAX          1024
#define KEY_PEM_MAX           512

static SemaphoreHandle_t s_mtx;
static volatile sectls_usbip_mode_t s_mode = SECTLS_USBIP_OFF;
static char              s_psk[SECTLS_PSK_LEN + 1];
static bool              s_https;
static char             *s_cert_pem;      /* PSRAM/heap, kept for the server's lifetime */
static char             *s_key_pem;
static char              s_fp[SECTLS_FP_LEN];
static volatile int      s_sessions;
static TaskHandle_t      s_listener;
static mbedtls_ssl_config s_conf;
static bool              s_conf_ready;

/* =============================================================== helpers */

static esp_err_t nvs_put_str(const char *key, const char *val)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (e) return e;
    e = nvs_set_str(h, key, val);
    if (!e) e = nvs_commit(h);
    nvs_close(h);
    return e;
}

static esp_err_t nvs_put_u8(const char *key, uint8_t val)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (e) return e;
    e = nvs_set_u8(h, key, val);
    if (!e) e = nvs_commit(h);
    nvs_close(h);
    return e;
}

static char *nvs_get_alloc(nvs_handle_t h, const char *key)
{
    size_t len = 0;
    if (nvs_get_str(h, key, NULL, &len) != ESP_OK || len == 0) return NULL;
    char *p = malloc(len);
    if (p && nvs_get_str(h, key, p, &len) != ESP_OK) { free(p); p = NULL; }
    return p;
}

static void gen_psk(char *out)
{
    static const char abc[] = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";  /* no 0/O/1/l/I */
    const unsigned n = sizeof(abc) - 1;          /* 57 */
    int i = 0;
    while (i < SECTLS_PSK_LEN) {
        uint8_t r = (uint8_t)(esp_random() & 0xFF);
        if (r >= 228) continue;                   /* 228 = 4*57: unbiased */
        out[i++] = abc[r % n];
    }
    out[SECTLS_PSK_LEN] = '\0';
}

/* ======================================================= TLS-PSK proxy */

static int psk_cb(void *p, mbedtls_ssl_context *ssl, const unsigned char *id, size_t id_len)
{
    (void)p;
    if (id_len != strlen(SECTLS_PSK_IDENTITY) || memcmp(id, SECTLS_PSK_IDENTITY, id_len) != 0) {
        return -1;
    }
    char psk[SECTLS_PSK_LEN + 1];
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    memcpy(psk, s_psk, sizeof(psk));
    xSemaphoreGive(s_mtx);
    int r = mbedtls_ssl_set_hs_psk(ssl, (const unsigned char *)psk, strlen(psk));
    mbedtls_platform_zeroize(psk, sizeof(psk));
    return r;
}

static const int s_suites[] = {
    MBEDTLS_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,   /* forward secrecy */
    MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,         /* forward secrecy, HW AES */
    MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
    0
};

static esp_err_t conf_init(void)
{
    if (s_conf_ready) return ESP_OK;
    if (psa_crypto_init() != PSA_SUCCESS) return ESP_FAIL;
    mbedtls_ssl_config_init(&s_conf);
    if (mbedtls_ssl_config_defaults(&s_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        return ESP_FAIL;
    }
    mbedtls_ssl_conf_min_tls_version(&s_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&s_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_ciphersuites(&s_conf, s_suites);
    mbedtls_ssl_conf_psk_cb(&s_conf, psk_cb, NULL);
    s_conf_ready = true;
    return ESP_OK;
}

static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    int r = send((int)(intptr_t)ctx, buf, len, 0);
    if (r < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? MBEDTLS_ERR_SSL_WANT_WRITE
                                                         : MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return r;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    int r = recv((int)(intptr_t)ctx, buf, len, 0);
    if (r < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? MBEDTLS_ERR_SSL_WANT_READ
                                                         : MBEDTLS_ERR_NET_RECV_FAILED;
    }
    return r;   /* 0 = EOF */
}

static void set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

/* Detect a vanished client (power loss, cable pulled, standby) the same way
 * the plaintext server does: probe after 10 s idle, 3 probes 5 s apart, so
 * the device is released after ~25 s instead of staying blocked forever. */
static void set_keepalive(int fd)
{
    int v = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &v, sizeof(v));
    v = 10; setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &v, sizeof(v));
    v = 5;  setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &v, sizeof(v));
    v = 3;  setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &v, sizeof(v));
}

static bool wait_fd(int fd, bool for_write, int ms)
{
    fd_set s;
    FD_ZERO(&s);
    FD_SET(fd, &s);
    struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
    return select(fd + 1, for_write ? NULL : &s, for_write ? &s : NULL, NULL, &tv) > 0;
}

typedef struct {
    int      fd;
    uint32_t ip;
} session_arg_t;

static void session_task(void *arg)
{
    session_arg_t a = *(session_arg_t *)arg;
    free(arg);

    char ip_str[16];
    inet_ntoa_r(*(struct in_addr *)&a.ip, ip_str, sizeof(ip_str));

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);
    int local = -1;
    uint8_t *up = malloc(PUMP_BUF), *down = malloc(PUMP_BUF);   /* TLS->local, local->TLS */
    if (!up || !down || mbedtls_ssl_setup(&ssl, &s_conf) != 0) goto out;

    set_nonblock(a.fd);
    set_keepalive(a.fd);
    mbedtls_ssl_set_bio(&ssl, (void *)(intptr_t)a.fd, bio_send, bio_recv, NULL);

    /* Handshake with timeout */
    TickType_t t0 = xTaskGetTickCount();
    int r;
    while ((r = mbedtls_ssl_handshake(&ssl)) != 0) {
        if ((r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE) ||
            (xTaskGetTickCount() - t0) > pdMS_TO_TICKS(HANDSHAKE_TIMEOUT_MS)) {
            ESP_LOGW(TAG, "TLS handshake with %s failed: -0x%04x", ip_str, (unsigned)-r);
            event_log_add(EVENT_LOG_LEVEL_WARN, "USB/IP TLS: handshake from %s failed (wrong key?)", ip_str);
            goto out;
        }
        wait_fd(a.fd, r == MBEDTLS_ERR_SSL_WANT_WRITE, 200);
    }
    ESP_LOGI(TAG, "TLS session from %s (%s)", ip_str, mbedtls_ssl_get_ciphersuite(&ssl));
    event_log_add(EVENT_LOG_LEVEL_INFO, "USB/IP TLS session from %s", ip_str);

    /* Forward to the plaintext USB/IP server via loopback */
    local = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in la = { .sin_family = AF_INET, .sin_port = htons(CONFIG_USBIP_TCP_PORT),
                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (local < 0 || connect(local, (struct sockaddr *)&la, sizeof(la)) != 0) {
        ESP_LOGE(TAG, "loopback connect failed: errno %d", errno);
        goto out;
    }
    set_nonblock(local);

    size_t up_len = 0, up_off = 0, dn_len = 0, dn_off = 0;
    for (;;) {
        if (s_mode == SECTLS_USBIP_OFF) break;

        fd_set rs, ws;
        FD_ZERO(&rs);
        FD_ZERO(&ws);
        if (up_len == 0) FD_SET(a.fd, &rs); else FD_SET(local, &ws);
        if (dn_len == 0) FD_SET(local, &rs); else FD_SET(a.fd, &ws);
        bool buffered = up_len == 0 && mbedtls_ssl_get_bytes_avail(&ssl) > 0;
        struct timeval tv = { .tv_sec = buffered ? 0 : 1, .tv_usec = 0 };
        int maxfd = (a.fd > local ? a.fd : local) + 1;
        if (select(maxfd, &rs, &ws, NULL, &tv) < 0 && errno != EINTR) break;

        /* TLS -> local */
        if (up_len == 0 && (buffered || FD_ISSET(a.fd, &rs))) {
            r = mbedtls_ssl_read(&ssl, up, PUMP_BUF);
            if (r > 0) { up_len = (size_t)r; up_off = 0; }
            else if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE) break;
        }
        if (up_len) {
            int s = send(local, up + up_off, up_len - up_off, 0);
            if (s > 0) { up_off += (size_t)s; if (up_off == up_len) up_len = 0; }
            else if (s < 0 && errno != EAGAIN && errno != EWOULDBLOCK) break;
        }

        /* local -> TLS */
        if (dn_len == 0 && FD_ISSET(local, &rs)) {
            int n = recv(local, down, PUMP_BUF, 0);
            if (n > 0) { dn_len = (size_t)n; dn_off = 0; }
            else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) break;
        }
        if (dn_len) {
            r = mbedtls_ssl_write(&ssl, down + dn_off, dn_len - dn_off);
            if (r > 0) { dn_off += (size_t)r; if (dn_off == dn_len) dn_len = 0; }
            else if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE) break;
        }
    }
    mbedtls_ssl_close_notify(&ssl);
    ESP_LOGI(TAG, "TLS session from %s closed", ip_str);

out:
    if (local >= 0) close(local);
    close(a.fd);
    mbedtls_ssl_free(&ssl);
    free(up);
    free(down);
    __atomic_sub_fetch(&s_sessions, 1, __ATOMIC_SEQ_CST);
    vTaskDelete(NULL);
}

static void listener_task(void *arg)
{
    (void)arg;
    int lfd = -1;
    for (;;) {
        if (s_mode == SECTLS_USBIP_OFF) {
            if (lfd >= 0) { close(lfd); lfd = -1; ESP_LOGI(TAG, "TLS listener stopped"); }
            ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
            continue;
        }
        if (lfd < 0) {
            lfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            int one = 1;
            setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(CONFIG_USBIP_TLS_PORT),
                                      .sin_addr.s_addr = htonl(INADDR_ANY) };
            if (lfd < 0 || bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(lfd, 4) != 0) {
                ESP_LOGE(TAG, "cannot listen on %d: errno %d", CONFIG_USBIP_TLS_PORT, errno);
                if (lfd >= 0) close(lfd);
                lfd = -1;
                vTaskDelay(pdMS_TO_TICKS(5000));
                continue;
            }
            ESP_LOGI(TAG, "USB/IP TLS listening on port %d", CONFIG_USBIP_TLS_PORT);
        }
        if (!wait_fd(lfd, false, 1000)) continue;

        struct sockaddr_in ca;
        socklen_t cl = sizeof(ca);
        int fd = accept(lfd, (struct sockaddr *)&ca, &cl);
        if (fd < 0) continue;
        uint32_t ip = ca.sin_addr.s_addr;

        if (!access_control_check(ip)) { close(fd); continue; }
        if (s_sessions >= CONFIG_USBIP_MAX_CLIENTS) {
            ESP_LOGW(TAG, "TLS session limit reached");
            close(fd);
            continue;
        }
        session_arg_t *sa = malloc(sizeof(*sa));
        if (!sa) { close(fd); continue; }
        sa->fd = fd;
        sa->ip = ip;
        __atomic_add_fetch(&s_sessions, 1, __ATOMIC_SEQ_CST);
        if (xTaskCreate(session_task, "usbip_tls", 8192, sa, 6, NULL) != pdPASS) {
            __atomic_sub_fetch(&s_sessions, 1, __ATOMIC_SEQ_CST);
            free(sa);
            close(fd);
        }
    }
}

/* ======================================================== certificate */

static void compute_fingerprint(void)
{
    s_fp[0] = '\0';
    if (!s_cert_pem) return;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    if (mbedtls_x509_crt_parse(&crt, (const unsigned char *)s_cert_pem, strlen(s_cert_pem) + 1) == 0) {
        uint8_t h[32];
        size_t hl = 0;
        if (psa_hash_compute(PSA_ALG_SHA_256, crt.raw.p, crt.raw.len, h, sizeof(h), &hl) == PSA_SUCCESS) {
            for (int i = 0; i < 32; i++) {
                snprintf(s_fp + i * 3, sizeof(s_fp) - i * 3, i < 31 ? "%02X:" : "%02X", h[i]);
            }
        }
    }
    mbedtls_x509_crt_free(&crt);
}

static esp_err_t generate_cert(void)
{
    esp_err_t ret = ESP_FAIL;
    mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
    mbedtls_pk_context pk;
    mbedtls_x509write_cert crt;
    mbedtls_pk_init(&pk);
    mbedtls_x509write_crt_init(&crt);
    char *cert = calloc(1, CERT_PEM_MAX), *key = calloc(1, KEY_PEM_MAX);
    if (!cert || !key || psa_crypto_init() != PSA_SUCCESS) goto out;

    psa_key_attributes_t at = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&at, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&at, 256);
    psa_set_key_usage_flags(&at, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&at, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    if (psa_generate_key(&at, &kid) != PSA_SUCCESS) goto out;
    if (mbedtls_pk_copy_from_psa(kid, &pk) != 0) goto out;
    if (mbedtls_pk_write_key_pem(&pk, (unsigned char *)key, KEY_PEM_MAX) != 0) goto out;

    uint8_t serial[16];
    esp_fill_random(serial, sizeof(serial));
    serial[0] &= 0x7F;                       /* positive */
    serial[0] |= 0x01;                       /* no leading zero byte */

    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt, &pk);
    mbedtls_x509write_crt_set_issuer_key(&crt, &pk);
    if (mbedtls_x509write_crt_set_subject_name(&crt, "CN=usbip-esp32p4,O=usbip-esp32p4") ||
        mbedtls_x509write_crt_set_issuer_name(&crt, "CN=usbip-esp32p4,O=usbip-esp32p4") ||
        mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial)) ||
        mbedtls_x509write_crt_set_validity(&crt, "20250101000000", "20491231235959") ||
        mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1) ||
        mbedtls_x509write_crt_pem(&crt, (unsigned char *)cert, CERT_PEM_MAX) != 0) {
        goto out;
    }

    if (nvs_put_str("cert", cert) || nvs_put_str("key", key)) goto out;

    xSemaphoreTake(s_mtx, portMAX_DELAY);
    char *oc = s_cert_pem, *ok = s_key_pem;
    s_cert_pem = cert;
    s_key_pem = key;
    cert = oc;                               /* old buffers freed below */
    key = ok;
    xSemaphoreGive(s_mtx);
    compute_fingerprint();
    ESP_LOGI(TAG, "New HTTPS certificate, SHA-256 %s", s_fp);
    event_log_add(EVENT_LOG_LEVEL_INFO, "New HTTPS certificate generated");
    ret = ESP_OK;

out:
    if (ret != ESP_OK) ESP_LOGE(TAG, "certificate generation failed");
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&pk);
    if (!mbedtls_svc_key_id_is_null(kid)) psa_destroy_key(kid);
    if (key) { mbedtls_platform_zeroize(key, strlen(key)); free(key); }   /* may be an old, shorter buffer */
    free(cert);
    return ret;
}

/* ============================================================ public API */

esp_err_t sectls_init(void)
{
    s_mtx = xSemaphoreCreateMutex();
    if (!s_mtx) return ESP_ERR_NO_MEM;
    psa_crypto_init();

    nvs_handle_t h;
    uint8_t mode = 0, https = 0;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        size_t l = sizeof(s_psk);
        if (nvs_get_str(h, "psk", s_psk, &l) != ESP_OK) s_psk[0] = '\0';
        nvs_get_u8(h, "mode", &mode);
        nvs_get_u8(h, "https", &https);
        s_cert_pem = nvs_get_alloc(h, "cert");
        s_key_pem = nvs_get_alloc(h, "key");
        nvs_close(h);
    }
    if (strlen(s_psk) != SECTLS_PSK_LEN) {     /* first boot: create a key so enabling is one click */
        gen_psk(s_psk);
        nvs_put_str("psk", s_psk);
    }
    s_mode = (mode <= SECTLS_USBIP_ONLY) ? (sectls_usbip_mode_t)mode : SECTLS_USBIP_OFF;
    s_https = https != 0;
    if (s_https && (!s_cert_pem || !s_key_pem)) {
        generate_cert();
    }
    compute_fingerprint();

    if (conf_init() != ESP_OK) {
        ESP_LOGE(TAG, "TLS config init failed - USB/IP TLS unavailable");
    } else if (xTaskCreate(listener_task, "usbip_tls_l", 4096, NULL, 5, &s_listener) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    static const char *names[] = { "off", "additional", "TLS only" };
    ESP_LOGI(TAG, "USB/IP TLS: %s (port %d), HTTPS: %s", names[s_mode], CONFIG_USBIP_TLS_PORT,
             s_https ? "on" : "off");
    return ESP_OK;
}

sectls_usbip_mode_t sectls_usbip_mode(void) { return s_mode; }
uint16_t sectls_tls_port(void) { return CONFIG_USBIP_TLS_PORT; }
int sectls_active_sessions(void) { return s_sessions; }

bool sectls_is_proxy_peer(uint32_t ip_nbo)
{
    return ip_nbo == htonl(INADDR_LOOPBACK);
}

esp_err_t sectls_set_usbip_mode(sectls_usbip_mode_t mode)
{
    if (mode > SECTLS_USBIP_ONLY) return ESP_ERR_INVALID_ARG;
    esp_err_t e = nvs_put_u8("mode", (uint8_t)mode);
    if (e) return e;
    s_mode = mode;
    if (s_listener) xTaskNotifyGive(s_listener);
    static const char *names[] = { "off", "additional", "TLS only" };
    event_log_add(EVENT_LOG_LEVEL_INFO, "USB/IP TLS mode: %s", names[mode]);
    return ESP_OK;
}

void sectls_get_psk(char *out, size_t len)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    strlcpy(out, s_psk, len);
    xSemaphoreGive(s_mtx);
}

esp_err_t sectls_regenerate_psk(void)
{
    char n[SECTLS_PSK_LEN + 1];
    gen_psk(n);
    esp_err_t e = nvs_put_str("psk", n);
    if (e == ESP_OK) {
        xSemaphoreTake(s_mtx, portMAX_DELAY);
        memcpy(s_psk, n, sizeof(s_psk));
        xSemaphoreGive(s_mtx);
        event_log_add(EVENT_LOG_LEVEL_INFO, "USB/IP TLS key regenerated");
    }
    mbedtls_platform_zeroize(n, sizeof(n));
    return e;
}

bool sectls_https_enabled(void) { return s_https; }

esp_err_t sectls_set_https(bool on)
{
    if (on && (!s_cert_pem || !s_key_pem) && generate_cert() != ESP_OK) {
        return ESP_FAIL;
    }
    esp_err_t e = nvs_put_u8("https", on ? 1 : 0);
    if (e == ESP_OK) {
        s_https = on;
        event_log_add(EVENT_LOG_LEVEL_INFO, "HTTPS %s (active after restart)", on ? "enabled" : "disabled");
    }
    return e;
}

esp_err_t sectls_get_https_cert(const char **cert, size_t *cert_len, const char **key, size_t *key_len)
{
    if (!s_cert_pem || !s_key_pem) {
        if (generate_cert() != ESP_OK) return ESP_FAIL;
    }
    *cert = s_cert_pem;
    *cert_len = strlen(s_cert_pem) + 1;
    *key = s_key_pem;
    *key_len = strlen(s_key_pem) + 1;
    return ESP_OK;
}

esp_err_t sectls_regenerate_cert(void)
{
    /* The running HTTPS server keeps using the old buffers until restart, so
     * they are intentionally leaked here (a few hundred bytes, once). */
    s_cert_pem = NULL;
    s_key_pem = NULL;
    return generate_cert();
}

void sectls_cert_fingerprint(char *out, size_t len)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    strlcpy(out, s_fp, len);
    xSemaphoreGive(s_mtx);
}
