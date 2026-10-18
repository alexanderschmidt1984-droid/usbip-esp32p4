/*
 * Transfer Engine Component
 * Handles USB transfer submission and completion
 */
#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the transfer engine
 * @return ESP_OK on success
 */
esp_err_t transfer_engine_init(void);

/**
 * @brief Stop the transfer engine
 * @return ESP_OK on success
 */
esp_err_t transfer_engine_stop(void);

/**
 * @brief Run the URB transfer loop for an imported device
 * Blocks until the connection is closed or an error occurs.
 * @param sockfd Client socket file descriptor
 * @param busid  Bus ID string of the imported device
 * @param[out] needs_reset set to true when the session ended while the device
 *             is still attached (client detach, network loss): for the client
 *             that was an unplug, but the device kept its power and may be
 *             stuck mid-command (a stick between two URBs of one read), so it
 *             should be re-enumerated before the next client gets it. False
 *             if the device itself was unplugged. May be NULL.
 * @return 0 on clean disconnect, -1 on error
 */
int transfer_engine_run(int sockfd, const char *busid, bool *needs_reset);

#ifdef __cplusplus
}
#endif
