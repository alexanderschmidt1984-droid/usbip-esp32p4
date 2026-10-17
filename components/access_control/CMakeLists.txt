idf_component_register(
    SRCS "access_control.c" "device_filter.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES nvs_flash event_log
)
