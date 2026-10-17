# Capture code is only compiled when CONFIG_CAPTURE_ENABLED is set (default off);
# all callers are guarded with #if CONFIG_CAPTURE_ENABLED.
if(CONFIG_CAPTURE_ENABLED)
    set(srcs "capture.c" "capture_api.c")
else()
    set(srcs "")
endif()
idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    REQUIRES esp_http_server
    PRIV_REQUIRES sdmmc fatfs esp_timer vfs esp_driver_sdmmc esp_hw_support webui event_log usbip_proto
)
