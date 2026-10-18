# WireGuard tunnel (outbound) - uses esphome/wireguard (ESP Component Registry).
# Requirements must be unconditional (Kconfig is not loaded during dependency
# resolution); only the sources depend on CONFIG_USBIP_WIREGUARD.
if(CONFIG_USBIP_WIREGUARD)
    set(srcs "wg_tunnel.c")
else()
    set(srcs "wg_tunnel_stub.c")
endif()
idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    PRIV_REQUIRES wireguard esphome__libsodium esp_netif esp_event nvs_flash lwip
                  event_log esp_hw_support
)
