/*
 * Transport encryption for the local network
 *
 *  - USB/IP over TLS (TLS 1.2 with pre-shared key) on CONFIG_USBIP_TLS_PORT.
 *    The Linux usbip client has no TLS support, so the PC runs stunnel which
 *    wraps the connection; on the board a proxy terminates TLS and forwards to
 *    the normal USB/IP server via loopback. Modes: off / additional / TLS only.
 *  - HTTPS for the web UI with a self-signed ECDSA P-256 certificate that is
 *    generated on the device (never shared between boards).
 *
 * Settings live in NVS namespace "sectls" and are switched in the web UI.
 */
#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SECTLS_USBIP_OFF = 0,      /* plaintext only (stock behaviour) */
    SECTLS_USBIP_ALSO = 1,     /* plaintext on 3240 + TLS on CONFIG_USBIP_TLS_PORT */
    SECTLS_USBIP_ONLY = 2,     /* TLS only - plaintext port refuses remote clients */
} sectls_usbip_mode_t;

#define SECTLS_PSK_LEN       32          /* printable characters */
#define SECTLS_PSK_IDENTITY  "usbip"
#define SECTLS_FP_LEN        96          /* "AB:CD:..." SHA-256 */

esp_err_t            sectls_init(void);

sectls_usbip_mode_t  sectls_usbip_mode(void);
esp_err_t            sectls_set_usbip_mode(sectls_usbip_mode_t mode);   /* live */
void                 sectls_get_psk(char *out, size_t len);            /* secret! */
esp_err_t            sectls_regenerate_psk(void);
uint16_t             sectls_tls_port(void);
int                  sectls_active_sessions(void);

/* true for connections the TLS proxy forwards via loopback */
bool                 sectls_is_proxy_peer(uint32_t ip_nbo);

bool                 sectls_https_enabled(void);                       /* setting */
esp_err_t            sectls_set_https(bool on);                         /* after restart */
/* PEM cert/key incl. terminating NUL; generated on first use. Pointers stay valid. */
esp_err_t            sectls_get_https_cert(const char **cert, size_t *cert_len,
                                           const char **key, size_t *key_len);
esp_err_t            sectls_regenerate_cert(void);                     /* after restart */
void                 sectls_cert_fingerprint(char *out, size_t len);

#ifdef __cplusplus
}
#endif
