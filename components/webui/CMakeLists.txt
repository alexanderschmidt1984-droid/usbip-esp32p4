idf_component_register(
    SRCS "webui.c" "ws_handler.c" "webui_api.c" "webui_backup.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_http_server
    PRIV_REQUIRES esp_timer transfer_engine esp_pm power_mgr esp_app_format device_manager event_log access_control network_mgr mbedtls nvs_flash usb_host_mgr capture wg_tunnel sec_tls esp_https_server
    EMBED_FILES
        "frontend/index.html"
        "frontend/style.css"
        "frontend/app.js"
        "frontend/lang/de.json"
        "frontend/lang/en.json"
        "frontend/lang/fr.json"
        "frontend/lang/es.json"
        "frontend/lang/it.json"
        "frontend/lang/pt.json"
        "frontend/lang/da.json"
        "frontend/lang/sv.json"
        "frontend/lang/ru.json"
        "frontend/lang/uk.json"
        "frontend/lang/tr.json"
        "frontend/lang/ar.json"
)

# Versions of the managed components (dependencies.lock) for /api/system/components
idf_build_get_property(project_dir PROJECT_DIR)
if(EXISTS "${project_dir}/dependencies.lock")
    file(READ "${project_dir}/dependencies.lock" lockfile)
    foreach(dep "espressif/usb:USB" "espressif/mdns:MDNS" "espressif/ip101:IP101" "esphome/libsodium:SODIUM")
        string(REPLACE ":" ";" parts "${dep}")
        list(GET parts 0 dep_name)
        list(GET parts 1 dep_macro)
        # the first "    version:" line after the "  <name>:" entry
        string(FIND "${lockfile}" "  ${dep_name}:" pos)
        if(pos GREATER -1)
            string(SUBSTRING "${lockfile}" ${pos} -1 rest)
            string(REGEX MATCH "\n    version: ([^\n]+)" _m "${rest}")
            if(CMAKE_MATCH_1)
                target_compile_definitions(${COMPONENT_LIB} PRIVATE "VER_${dep_macro}=\"${CMAKE_MATCH_1}\"")
            endif()
        endif()
    endforeach()
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${project_dir}/dependencies.lock")
endif()
