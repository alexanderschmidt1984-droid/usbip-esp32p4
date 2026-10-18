# USB/IP Server for ESP32-P4-Nano
# ESP-IDF v6.0.2 project
cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/components")

# Firmware version shown in the web UI: base version + git state, e.g. "1.1.0-plus.5b62fdc".
set(USBIP_BASE_VERSION "1.1.0-plus")
execute_process(COMMAND git describe --always --dirty
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                OUTPUT_VARIABLE USBIP_GIT_REV OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
if(USBIP_GIT_REV)
    set(PROJECT_VER "${USBIP_BASE_VERSION}.${USBIP_GIT_REV}")
else()
    set(PROJECT_VER "${USBIP_BASE_VERSION}")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(usbip-esp32p4)
