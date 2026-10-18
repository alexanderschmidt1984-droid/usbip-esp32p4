/*
 * Access Control Component
 * IP- and MAC-based access control with NVS persistence
 */
#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum number of allowlist entries (IP and MAC together) */
#define ACCESS_CONTROL_MAX_IPS 32
#define ACCESS_CONTROL_COMMENT_LEN 32   /* incl. NUL */

typedef enum {
    ACL_ENTRY_IP  = 0,   /**< match the client IP */
    ACL_ENTRY_MAC = 1,   /**< match the client MAC (ARP table; same LAN only) */
} acl_entry_type_t;

/** Allowlist entry; comment names who was given access. */
typedef struct {
    uint8_t  type;                                /**< acl_entry_type_t */
    uint8_t  mac[6];                              /**< ACL_ENTRY_MAC */
    uint32_t ip;                                  /**< ACL_ENTRY_IP, network byte order */
    char     comment[ACCESS_CONTROL_COMMENT_LEN];
} acl_entry_t;

/**
 * @brief Initialize access control subsystem
 * Loads mode and allowlist from NVS. Defaults to open mode if nothing saved.
 * An allowlist stored by older firmware (IPs only) is taken over.
 * @return ESP_OK on success
 */
esp_err_t access_control_init(void);

/**
 * @brief Check if a client is allowed (logs denials)
 * In open mode, always returns true. In closed mode the client passes when its
 * IP is listed, or when its MAC (looked up in the ARP table) is listed.
 * @param client_ip Client IP address (network byte order)
 * @return true if allowed
 */
bool access_control_check(uint32_t client_ip);

/**
 * @brief Silent allowlist lookup (no logging) - for frequent checks such as
 *        Web UI requests. Returns true if the client is in the allowlist.
 * @param client_ip Client IP address (network byte order)
 */
bool access_control_is_allowed(uint32_t client_ip);

/**
 * @brief Check if access control is in closed mode
 * @return true if closed mode is active
 */
bool access_control_is_closed_mode(void);

/**
 * @brief Set access control mode
 * @param closed true for closed mode, false for open mode
 */
void access_control_set_mode(bool closed);

/**
 * @brief Add an IP entry to the allowlist (no-op if the IP is already listed)
 * @param ip IP address to add (network byte order)
 * @param comment optional note, may be NULL
 * @return ESP_OK on success, ESP_ERR_NO_MEM if list full, ESP_ERR_INVALID_STATE if duplicate
 */
esp_err_t access_control_add_ip(uint32_t ip, const char *comment);

/**
 * @brief Get the allowlist
 * @return Number of entries written to out
 */
int access_control_get_entries(acl_entry_t *out, int max);

/**
 * @brief Replace the whole allowlist and save it
 * @return ESP_OK, ESP_ERR_INVALID_SIZE if n > ACCESS_CONTROL_MAX_IPS
 */
esp_err_t access_control_set_entries(const acl_entry_t *entries, int n);

/**
 * @brief MAC address of a client on the local network (from the ARP table)
 * @return true if found
 */
bool access_control_lookup_mac(uint32_t client_ip, uint8_t mac_out[6]);

#ifdef __cplusplus
}
#endif
