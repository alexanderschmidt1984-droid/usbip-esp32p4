/*
 * Web UI Component
 * HTTP server with embedded frontend
 */
#pragma once

#include "esp_err.h"
#include "esp_http_server.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize and start the web UI server
 * @return ESP_OK on success
 */
esp_err_t webui_init(void);

/**
 * @brief Stop the web UI server
 * @return ESP_OK on success
 */
esp_err_t webui_stop(void);

/**
 * @brief Notify the web UI that the device list has changed
 *
 * This can be used to push updates to connected WebSocket clients.
 */
void webui_notify_device_change(void);

/**
 * @brief Save authentication settings to NVS
 * @param enabled  Whether auth is enabled
 * @param username Username (NULL to keep current)
 * @param password Plaintext password - stored as salted, iterated SHA-256
 *                 (NULL or "" to keep current)
 * @return ESP_OK, or ESP_ERR_INVALID_ARG when enabling auth without any password
 */
esp_err_t webui_auth_save(bool enabled, const char *username, const char *password);

/**
 * @brief Whether a Web UI password has been configured
 */
bool webui_auth_has_password(void);

/**
 * @brief Client IPv4 address of a request (network byte order), 0 if unknown
 */
uint32_t webui_req_client_ip(httpd_req_t *req);

/**
 * @brief Check if authentication is currently enabled
 */
bool webui_auth_enabled(void);

/**
 * @brief Get the current auth username
 */
const char *webui_auth_username(void);

/**
 * @brief Register REST API endpoint handlers
 * @param server HTTP server handle
 */
void webui_api_register(httpd_handle_t server);

/**
 * @brief Check if a request passes authentication
 * @param req HTTP request
 * @return true if authenticated (or auth disabled)
 */
bool webui_check_auth(httpd_req_t *req);

/**
 * @brief Send a 401 Unauthorized response
 * @param req HTTP request
 * @return ESP_OK
 */
esp_err_t webui_reject_auth(httpd_req_t *req);

/** true if the web UI is currently served over HTTPS */
bool webui_https_active(void);

#ifdef __cplusplus
}
#endif
