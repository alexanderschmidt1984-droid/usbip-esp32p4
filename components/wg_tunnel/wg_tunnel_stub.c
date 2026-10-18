/* WireGuard support compiled out (CONFIG_USBIP_WIREGUARD=n) */
#include "wg_tunnel.h"
#include <string.h>
esp_err_t wg_tunnel_init(void) { return ESP_OK; }
void wg_tunnel_get_config(wg_tunnel_config_t *out) { memset(out, 0, sizeof(*out)); }
esp_err_t wg_tunnel_set_config(const wg_tunnel_config_t *cfg, const char **e) { (void)cfg; if (e) *e = "WireGuard not compiled in"; return ESP_ERR_NOT_SUPPORTED; }
esp_err_t wg_tunnel_generate_key(char *o, size_t l) { (void)o; (void)l; return ESP_ERR_NOT_SUPPORTED; }
void wg_tunnel_get_status(wg_tunnel_status_t *out) { memset(out, 0, sizeof(*out)); }
const char *wg_tunnel_state_str(wg_tunnel_state_t s) { (void)s; return "unsupported"; }
