idf_component_register(
    SRCS "power_mgr.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES esp_pm nvs_flash
)
