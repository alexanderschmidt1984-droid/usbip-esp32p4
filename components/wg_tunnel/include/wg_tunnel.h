/*
 * WireGuard tunnel - lets the board dial out to a WireGuard peer (own server,
 * router, ...) so it is reachable through the tunnel from anywhere, without
 * port forwarding at the board's site. Configured via the web UI, stored in
 * NVS namespace "wg". The USB/IP server and web UI listen on all interfaces,
 * so they are reachable on the tunnel address as well.
 */
#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WG_KEY_LEN      45   /* base64 of 32 bytes incl. NUL */
#define WG_ADDR_LEN     16
#define WG_HOST_LEN     64

typedef struct {
    bool     enabled;
    char     private_key[WG_KEY_LEN];      /* never returned by the web API */
    char     peer_public_key[WG_KEY_LEN];
    char     preshared_key[WG_KEY_LEN];    /* optional, never returned */
    char     address[WG_ADDR_LEN];         /* tunnel IP of this board, e.g. 10.8.0.2 */
    char     netmask[WG_ADDR_LEN];         /* tunnel subnet, e.g. 255.255.255.0 */
    char     endpoint[WG_HOST_LEN];        /* peer host name or IP */
    uint16_t port;                         /* peer UDP port (51820) */
    uint16_t keepalive;                    /* seconds, 0 = off (25 recommended) */
} wg_tunnel_config_t;

typedef enum {
    WG_STATE_DISABLED = 0,
    WG_STATE_NOT_CONFIGURED,
    WG_STATE_WAIT_NETWORK,
    WG_STATE_WAIT_TIME,
    WG_STATE_CONNECTING,
    WG_STATE_UP,
    WG_STATE_ERROR,
} wg_tunnel_state_t;

typedef struct {
    wg_tunnel_state_t state;
    time_t   last_handshake;               /* 0 = never */
    char     public_key[WG_KEY_LEN];       /* this board's public key ("" if no key) */
    char     last_error[64];
} wg_tunnel_status_t;

esp_err_t   wg_tunnel_init(void);
void        wg_tunnel_get_config(wg_tunnel_config_t *out);
/* Empty private_key / preshared_key in cfg = keep the stored value.
 * preshared_key "-" = remove it. Applies immediately (tunnel restarts). */
esp_err_t   wg_tunnel_set_config(const wg_tunnel_config_t *cfg, const char **err_msg);
/* Create a new key pair on the device; private key never leaves it. */
esp_err_t   wg_tunnel_generate_key(char *public_key_out, size_t len);
void        wg_tunnel_get_status(wg_tunnel_status_t *out);
/* Tunnel address/netmask (network byte order) while the tunnel is up;
 * false otherwise. Cheap, no key material involved. */
bool        wg_tunnel_up_addr(uint32_t *ip_nbo, uint32_t *mask_nbo);
const char *wg_tunnel_state_str(wg_tunnel_state_t s);

#ifdef __cplusplus
}
#endif
