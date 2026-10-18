idf_component_register(
    SRCS "sec_tls.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES mbedtls nvs_flash lwip esp_hw_support event_log access_control freertos
)
