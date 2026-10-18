idf_component_register(
    SRCS "usb_host_mgr.c"
    INCLUDE_DIRS "include"
    REQUIRES usb
    PRIV_REQUIRES nvs_flash esp_hal_usb device_manager event_log network_mgr webui access_control
)
