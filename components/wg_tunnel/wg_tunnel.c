/*
 * WireGuard tunnel manager
 *
 * Built on esphome/wireguard (fork of trombik/esp_wireguard, supports
 * ESP-IDF 6 / mbedTLS 4). All calls into the library run in the lwIP tcpip
 * thread (esp_netif_tcpip_exec) because it adds netifs and lwIP timers.
 *
 * Flow: wait for Ethernet IP -> SNTP time sync (WireGuard handshakes carry a
 * TAI64N timestamp; peers reject a clock that went backwards) -> init ->
 * connect (retry while the endpoint name resolves) -> monitor. If the peer
 * stays silent (no handshake for WG_DEAD_S) the tunnel is rebuilt, which also
 * re-resolves a dynamic-DNS endpoint.
 */
#include "wg_tunnel.h"
#include "event_log.h"

#include "esp_wireguard.h"
#include "wireguard.h"          /* wireguard_base64_encode/decode */
#include "sodium.h"

#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_event.h"
#include "esp_random.h"
#include "nvs.h"
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/event_groups.h"
#include "lwip/ip4_addr.h"

#include <string.h>
#include <stdio.h>
#include <sys/time.h>

#ifndef CONFIG_USBIP_WG_NTP_SERVER
#define CONFIG_USBIP_WG_NTP_SERVER "pool.ntp.org"
#endif

static const char *TAG = "wg";
static const char *NVS_NS = "wg";

#define BIT_NET        BIT0
#define BIT_RECONF     BIT1
#define WG_DEAD_S      300      /* no handshake for 5 min -> rebuild (only with keepalive) */
#define WG_FIRST_S     120      /* first handshake must happen within 2 min */
#define WG_RETRY_S     30
#define TIME_VALID     1700000000

static SemaphoreHandle_t  s_mtx;
static EventGroupHandle_t s_ev;
static wg_tunnel_config_t s_cfg;           /* persisted configuration */
static wg_tunnel_status_t s_st;

/* Copies handed to the library; must stay valid while the tunnel exists. */
static wg_tunnel_config_t s_active;
static wireguard_config_t s_wgcfg;
static wireguard_ctx_t    s_ctx;

/* ------------------------------------------------------------------ helpers */

static void set_state(wg_tunnel_state_t st, const char *err)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    s_st.state = st;
    if (err) {
        strlcpy(s_st.last_error, err, sizeof(s_st.last_error));
    } else if (st == WG_STATE_UP) {
        s_st.last_error[0] = '\0';
    }
    xSemaphoreGive(s_mtx);
}

static bool key_decode(const char *b64, uint8_t out[32])
{
    size_t len = 32;
    if (!b64 || strlen(b64) != 44) return false;
    return wireguard_base64_decode(b64, out, &len) && len == 32;
}

static bool key_encode(const uint8_t in[32], char *out, size_t outlen)
{
    size_t len = outlen;
    return wireguard_base64_encode(in, 32, out, &len);
}

static void derive_public(const char *priv_b64, char *pub_out, size_t len)
{
    uint8_t sk[32], pk[32];
    pub_out[0] = '\0';
    if (key_decode(priv_b64, sk) && crypto_scalarmult_curve25519_base(pk, sk) == 0) {
        key_encode(pk, pub_out, len);
    }
    sodium_memzero(sk, sizeof(sk));
}

static bool ip4_valid(const char *s)
{
    ip4_addr_t a;
    return s && s[0] && ip4addr_aton(s, &a);
}

/* ---------------------------------------------------------------------- NVS */

static void nvs_load(void)
{
    memset(&s_cfg, 0, sizeof(s_cfg));
    s_cfg.port = 51820;
    s_cfg.keepalive = 25;
    strcpy(s_cfg.netmask, "255.255.255.0");

    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    uint8_t en = 0;
    size_t l;
    nvs_get_u8(h, "en", &en);
    s_cfg.enabled = en != 0;
    l = sizeof(s_cfg.private_key);     nvs_get_str(h, "priv", s_cfg.private_key, &l);
    l = sizeof(s_cfg.peer_public_key); nvs_get_str(h, "peer", s_cfg.peer_public_key, &l);
    l = sizeof(s_cfg.preshared_key);   nvs_get_str(h, "psk",  s_cfg.preshared_key, &l);
    l = sizeof(s_cfg.address);         nvs_get_str(h, "addr", s_cfg.address, &l);
    l = sizeof(s_cfg.netmask);         nvs_get_str(h, "mask", s_cfg.netmask, &l);
    l = sizeof(s_cfg.endpoint);        nvs_get_str(h, "host", s_cfg.endpoint, &l);
    nvs_get_u16(h, "port", &s_cfg.port);
    nvs_get_u16(h, "ka", &s_cfg.keepalive);
    nvs_close(h);
}

static esp_err_t nvs_save(const wg_tunnel_config_t *c)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (e != ESP_OK) return e;
    e = nvs_set_u8(h, "en", c->enabled ? 1 : 0);
    if (!e) e = nvs_set_str(h, "priv", c->private_key);
    if (!e) e = nvs_set_str(h, "peer", c->peer_public_key);
    if (!e) e = nvs_set_str(h, "psk",  c->preshared_key);
    if (!e) e = nvs_set_str(h, "addr", c->address);
    if (!e) e = nvs_set_str(h, "mask", c->netmask);
    if (!e) e = nvs_set_str(h, "host", c->endpoint);
    if (!e) e = nvs_set_u16(h, "port", c->port);
    if (!e) e = nvs_set_u16(h, "ka", c->keepalive);
    if (!e) e = nvs_commit(h);
    nvs_close(h);
    return e;
}

/* ------------------------------------------------- calls in tcpip context */

typedef enum { OP_INIT, OP_CONNECT, OP_ALLOW, OP_STATUS, OP_DISCONNECT } wg_op_t;

typedef struct {
    wg_op_t   op;
    esp_err_t ret;
    bool      up;
    time_t    handshake;
    char      net[16];
    char      mask[16];
} wg_call_t;

static esp_err_t tcpip_fn(void *arg)
{
    wg_call_t *c = (wg_call_t *)arg;
    switch (c->op) {
    case OP_INIT:
        c->ret = esp_wireguard_init(&s_wgcfg, &s_ctx);
        break;
    case OP_CONNECT:
        c->ret = esp_wireguard_connect(&s_ctx);
        break;
    case OP_ALLOW:
        c->ret = esp_wireguard_add_allowed_ip(&s_ctx, c->net, c->mask);
        break;
    case OP_STATUS:
        c->up = false;
        c->handshake = 0;
        if (s_ctx.netif) {
            c->up = esp_wireguard_peer_is_up(&s_ctx) == ESP_OK;
            esp_wireguard_latest_handshake(&s_ctx, &c->handshake);
        }
        c->ret = ESP_OK;
        break;
    case OP_DISCONNECT:
        c->ret = ESP_OK;
        if (s_ctx.netif) c->ret = esp_wireguard_disconnect(&s_ctx);
        break;
    }
    return ESP_OK;
}

static esp_err_t wg_call(wg_call_t *c)
{
    esp_err_t e = esp_netif_tcpip_exec(tcpip_fn, c);
    return e != ESP_OK ? e : c->ret;
}

/* ------------------------------------------------------------ tunnel logic */

static void tunnel_down(void)
{
    wg_call_t c = { .op = OP_DISCONNECT };
    wg_call(&c);
}

static bool tunnel_up(void)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    s_active = s_cfg;
    xSemaphoreGive(s_mtx);

    wireguard_config_t def = ESP_WIREGUARD_CONFIG_DEFAULT();
    s_wgcfg = def;
    s_wgcfg.private_key   = s_active.private_key;
    s_wgcfg.public_key    = s_active.peer_public_key;
    s_wgcfg.preshared_key = s_active.preshared_key[0] ? s_active.preshared_key : NULL;
    s_wgcfg.address       = s_active.address;
    s_wgcfg.netmask       = s_active.netmask;
    s_wgcfg.endpoint      = s_active.endpoint;
    s_wgcfg.port          = s_active.port;
    s_wgcfg.persistent_keepalive = s_active.keepalive;

    /* init is required again after every disconnect (library contract) */
    wg_call_t c = { .op = OP_INIT };
    if (wg_call(&c) != ESP_OK) {
        set_state(WG_STATE_ERROR, "init failed (endpoint/DNS?)");
        return false;
    }

    set_state(WG_STATE_CONNECTING, NULL);
    esp_err_t e = ESP_FAIL;
    for (int i = 0; i < 30; i++) {     /* DNS resolution of the endpoint may take a moment */
        c.op = OP_CONNECT;
        e = wg_call(&c);
        if (e != ESP_ERR_RETRY) break;
        if (xEventGroupGetBits(s_ev) & BIT_RECONF) break;
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    if (e != ESP_OK) {
        tunnel_down();
        set_state(WG_STATE_ERROR, e == ESP_ERR_RETRY ? "endpoint name not resolvable"
                                                     : "connect failed");
        return false;
    }

    /* Accept packets from the whole tunnel subnet (other peers relayed by the
     * server), not just the server's own address. */
    ip4_addr_t a, m, n;
    ip4addr_aton(s_active.address, &a);
    ip4addr_aton(s_active.netmask, &m);
    n.addr = a.addr & m.addr;
    c.op = OP_ALLOW;
    ip4addr_ntoa_r(&n, c.net, sizeof(c.net));
    strlcpy(c.mask, s_active.netmask, sizeof(c.mask));
    if (wg_call(&c) != ESP_OK) {
        ESP_LOGW(TAG, "adding allowed subnet %s/%s failed", c.net, c.mask);
    }

    ESP_LOGI(TAG, "Tunnel %s/%s -> %s:%u started", s_active.address, s_active.netmask,
             s_active.endpoint, s_active.port);
    event_log_add(EVENT_LOG_LEVEL_INFO, "WireGuard: connecting to %s:%u",
                  s_active.endpoint, s_active.port);
    return true;
}

static bool config_complete(const wg_tunnel_config_t *c)
{
    uint8_t k[32];
    return key_decode(c->private_key, k) && key_decode(c->peer_public_key, k) &&
           ip4_valid(c->address) && ip4_valid(c->netmask) && c->endpoint[0] && c->port;
}

static bool wait_time_sync(void)
{
    static bool sntp_started;
    if (time(NULL) > TIME_VALID) return true;
    if (!sntp_started) {
        esp_sntp_config_t cfg = ESP_NETIF_SNTP_DEFAULT_CONFIG(CONFIG_USBIP_WG_NTP_SERVER);
        if (esp_netif_sntp_init(&cfg) == ESP_OK) sntp_started = true;
    }
    set_state(WG_STATE_WAIT_TIME, NULL);
    for (int i = 0; i < 30; i++) {
        if (time(NULL) > TIME_VALID) return true;
        if (xEventGroupGetBits(s_ev) & BIT_RECONF) return false;
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    set_state(WG_STATE_WAIT_TIME, "no time from " CONFIG_USBIP_WG_NTP_SERVER);
    return false;
}

static bool eth_has_ip(void)
{
    esp_netif_t *n = esp_netif_get_handle_from_ifkey("ETH_DEF");
    esp_netif_ip_info_t ip;
    return n && esp_netif_get_ip_info(n, &ip) == ESP_OK && ip.ip.addr != 0;
}

static void wg_task(void *arg)
{
    (void)arg;
    for (;;) {
        xEventGroupClearBits(s_ev, BIT_RECONF);

        xSemaphoreTake(s_mtx, portMAX_DELAY);
        bool enabled = s_cfg.enabled;
        bool complete = config_complete(&s_cfg);
        xSemaphoreGive(s_mtx);

        if (!enabled || !complete) {
            set_state(enabled ? WG_STATE_NOT_CONFIGURED : WG_STATE_DISABLED, NULL);
            xEventGroupWaitBits(s_ev, BIT_RECONF, pdTRUE, pdFALSE, portMAX_DELAY);
            continue;
        }
        if (eth_has_ip()) xEventGroupSetBits(s_ev, BIT_NET);
        if (!(xEventGroupGetBits(s_ev) & BIT_NET)) {
            set_state(WG_STATE_WAIT_NETWORK, NULL);
            xEventGroupWaitBits(s_ev, BIT_NET | BIT_RECONF, pdFALSE, pdFALSE, portMAX_DELAY);
            continue;
        }
        if (!wait_time_sync()) {
            xEventGroupWaitBits(s_ev, BIT_RECONF, pdTRUE, pdFALSE, pdMS_TO_TICKS(WG_RETRY_S * 1000));
            continue;
        }
        if (!tunnel_up()) {
            xEventGroupWaitBits(s_ev, BIT_RECONF, pdTRUE, pdFALSE, pdMS_TO_TICKS(WG_RETRY_S * 1000));
            continue;
        }

        /* Monitor */
        int64_t started = esp_log_timestamp() / 1000;
        bool was_up = false;
        for (;;) {
            EventBits_t b = xEventGroupWaitBits(s_ev, BIT_RECONF, pdFALSE, pdFALSE,
                                                pdMS_TO_TICKS(5000));
            if (b & BIT_RECONF) break;
            if (!(b & BIT_NET)) break;

            wg_call_t c = { .op = OP_STATUS };
            wg_call(&c);
            xSemaphoreTake(s_mtx, portMAX_DELAY);
            s_st.last_handshake = c.handshake;
            xSemaphoreGive(s_mtx);
            set_state(c.up ? WG_STATE_UP : WG_STATE_CONNECTING, NULL);

            if (c.up != was_up) {
                event_log_add(c.up ? EVENT_LOG_LEVEL_INFO : EVENT_LOG_LEVEL_WARN,
                              "WireGuard peer %s", c.up ? "up" : "down");
                ESP_LOGI(TAG, "peer %s", c.up ? "up" : "down");
                was_up = c.up;
            }

            int64_t now_s = esp_log_timestamp() / 1000;
            time_t wall = time(NULL);
            bool never = c.handshake == 0 && (now_s - started) > WG_FIRST_S;
            bool dead = s_active.keepalive && c.handshake && (wall - c.handshake) > WG_DEAD_S;
            if (never || dead) {
                ESP_LOGW(TAG, "no handshake %s - rebuilding tunnel", never ? "yet" : "for too long");
                set_state(WG_STATE_CONNECTING, never ? "no handshake - check keys/endpoint/firewall"
                                                     : "peer silent - reconnecting");
                break;
            }
        }
        tunnel_down();
        xSemaphoreTake(s_mtx, portMAX_DELAY);
        s_st.last_handshake = 0;
        xSemaphoreGive(s_mtx);
        vTaskDelay(pdMS_TO_TICKS(2000));
    }
}

static void on_ip_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (id == IP_EVENT_ETH_GOT_IP) {
        xEventGroupSetBits(s_ev, BIT_NET);
    } else if (id == IP_EVENT_ETH_LOST_IP) {
        xEventGroupClearBits(s_ev, BIT_NET);
        xEventGroupSetBits(s_ev, BIT_RECONF);
    }
}

/* -------------------------------------------------------------- public API */

esp_err_t wg_tunnel_init(void)
{
    s_mtx = xSemaphoreCreateMutex();
    s_ev = xEventGroupCreate();
    if (!s_mtx || !s_ev) return ESP_ERR_NO_MEM;
    if (sodium_init() < 0) return ESP_FAIL;

    nvs_load();
    derive_public(s_cfg.private_key, s_st.public_key, sizeof(s_st.public_key));

    esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, on_ip_event, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_LOST_IP, on_ip_event, NULL);

    if (xTaskCreate(wg_task, "wg_tunnel", 4096, NULL, 5, NULL) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "WireGuard %s%s", s_cfg.enabled ? "enabled" : "disabled",
             s_st.public_key[0] ? "" : " (no key yet)");
    return ESP_OK;
}

void wg_tunnel_get_config(wg_tunnel_config_t *out)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    *out = s_cfg;
    xSemaphoreGive(s_mtx);
}

esp_err_t wg_tunnel_set_config(const wg_tunnel_config_t *in, const char **err_msg)
{
    const char *dummy;
    if (!err_msg) err_msg = &dummy;
    *err_msg = NULL;

    wg_tunnel_config_t n;
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    n = s_cfg;
    xSemaphoreGive(s_mtx);

    n.enabled = in->enabled;
    if (in->private_key[0]) strlcpy(n.private_key, in->private_key, sizeof(n.private_key));
    if (strcmp(in->preshared_key, "-") == 0) n.preshared_key[0] = '\0';
    else if (in->preshared_key[0]) strlcpy(n.preshared_key, in->preshared_key, sizeof(n.preshared_key));
    strlcpy(n.peer_public_key, in->peer_public_key, sizeof(n.peer_public_key));
    strlcpy(n.address, in->address, sizeof(n.address));
    strlcpy(n.netmask, in->netmask, sizeof(n.netmask));
    strlcpy(n.endpoint, in->endpoint, sizeof(n.endpoint));
    n.port = in->port ? in->port : 51820;
    n.keepalive = in->keepalive;

    uint8_t k[32];
    if (n.private_key[0] && !key_decode(n.private_key, k))       *err_msg = "private key invalid (base64, 44 chars)";
    else if (n.peer_public_key[0] && !key_decode(n.peer_public_key, k)) *err_msg = "peer public key invalid (base64, 44 chars)";
    else if (n.preshared_key[0] && !key_decode(n.preshared_key, k))     *err_msg = "preshared key invalid";
    else if (n.address[0] && !ip4_valid(n.address))               *err_msg = "tunnel address invalid";
    else if (n.netmask[0] && !ip4_valid(n.netmask))               *err_msg = "netmask invalid";
    else if (n.enabled && !config_complete(&n))
        *err_msg = "to enable: key pair, peer public key, tunnel address and endpoint are required";
    sodium_memzero(k, sizeof(k));
    if (*err_msg) return ESP_ERR_INVALID_ARG;

    esp_err_t e = nvs_save(&n);
    if (e != ESP_OK) { *err_msg = "saving to NVS failed"; return e; }

    xSemaphoreTake(s_mtx, portMAX_DELAY);
    s_cfg = n;
    derive_public(s_cfg.private_key, s_st.public_key, sizeof(s_st.public_key));
    xSemaphoreGive(s_mtx);
    sodium_memzero(&n, sizeof(n));

    event_log_add(EVENT_LOG_LEVEL_INFO, "WireGuard settings saved (%s)",
                  in->enabled ? "enabled" : "disabled");
    xEventGroupSetBits(s_ev, BIT_RECONF);
    return ESP_OK;
}

esp_err_t wg_tunnel_generate_key(char *public_key_out, size_t len)
{
    uint8_t sk[32], pk[32];
    esp_fill_random(sk, sizeof(sk));
    sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;     /* X25519 clamping */
    if (crypto_scalarmult_curve25519_base(pk, sk) != 0) return ESP_FAIL;

    wg_tunnel_config_t n;
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    n = s_cfg;
    xSemaphoreGive(s_mtx);
    key_encode(sk, n.private_key, sizeof(n.private_key));
    sodium_memzero(sk, sizeof(sk));

    esp_err_t e = nvs_save(&n);
    if (e == ESP_OK) {
        xSemaphoreTake(s_mtx, portMAX_DELAY);
        s_cfg = n;
        key_encode(pk, s_st.public_key, sizeof(s_st.public_key));
        if (public_key_out) strlcpy(public_key_out, s_st.public_key, len);
        xSemaphoreGive(s_mtx);
        event_log_add(EVENT_LOG_LEVEL_INFO, "WireGuard: new key pair generated");
        xEventGroupSetBits(s_ev, BIT_RECONF);
    }
    sodium_memzero(&n, sizeof(n));
    return e;
}

void wg_tunnel_get_status(wg_tunnel_status_t *out)
{
    xSemaphoreTake(s_mtx, portMAX_DELAY);
    *out = s_st;
    xSemaphoreGive(s_mtx);
}

const char *wg_tunnel_state_str(wg_tunnel_state_t s)
{
    switch (s) {
    case WG_STATE_DISABLED:       return "disabled";
    case WG_STATE_NOT_CONFIGURED: return "not configured";
    case WG_STATE_WAIT_NETWORK:   return "waiting for network";
    case WG_STATE_WAIT_TIME:      return "waiting for time sync";
    case WG_STATE_CONNECTING:     return "connecting";
    case WG_STATE_UP:             return "connected";
    case WG_STATE_ERROR:          return "error";
    }
    return "?";
}
