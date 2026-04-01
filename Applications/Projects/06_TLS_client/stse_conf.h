/******************************************************************************
 * \file        stse_conf.h
 * \brief       STSecureElement library configuration file – TLS client example
 * \author      STMicroelectronics - CS application team
 *
 ******************************************************************************
 * \attention
 *
 * <h2><center>&copy; COPYRIGHT 2022 STMicroelectronics</center></h2>
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef STSE_CONF_H
#define STSE_CONF_H

#ifdef __cplusplus
extern "C" {
#endif

#include "stse_platform_generic.h"

/************************************************************
 *                STSELIB DEVICE SUPPORT
 ************************************************************/
#define STSE_CONF_STSAFE_A_SUPPORT

/************************************************************
 *                STSAFE-A API/SERVICE SETTINGS
 ************************************************************/
#ifdef STSE_CONF_STSAFE_A_SUPPORT

/* STSAFE-A ECC services – NIST P-256 is used for TLS 1.2/1.3 client auth */
#define STSE_CONF_ECC_NIST_P_256
/* Uncomment to also support P-384 keys */
// #define STSE_CONF_ECC_NIST_P_384

/* STSAFE-A HASH services */
#define STSE_CONF_HASH_SHA_256
/* SHA-384 is used with P-384 keys */
// #define STSE_CONF_HASH_SHA_384

/* STSAFE-A STATIC PERSONALIZATION INFORMATIONS */
/* Uncomment and set the value if the device has static perso info (SPL05) */
// #define STSE_CONF_USE_STATIC_PERSONALIZATION_INFORMATIONS

/* STSAFE-A HOST KEY MANAGEMENT – not required for TLS client example */
// #define STSE_CONF_USE_HOST_SESSION
// #define STSE_CONF_USE_HOST_KEY_ESTABLISHMENT
// #define STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED
// #define STSE_CONF_USE_HOST_KEY_PROVISIONING_WRAPPED_AUTHENTICATED

/* STSAFE-A SYMMETRIC KEY MANAGEMENT – not required for TLS client example */
// #define STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT
// #define STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT_AUTHENTICATED
// #define STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED
// #define STSE_CONF_USE_SYMMETRIC_KEY_PROVISIONING_WRAPPED_AUTHENTICATED

#endif /* STSE_CONF_STSAFE_A_SUPPORT */

/* -------------------------------------------------------------------------
 * TLS CLIENT EXAMPLE CONFIGURATION
 * -------------------------------------------------------------------------
 * Adjust these defines to match the target deployment.
 */

/**
 * @defgroup TLS_Client_Config TLS Client Configuration
 * @{
 */

/**
 * @defgroup STSE_Polling STSELib Polling Parameters
 * @{
 */

/** Maximum number of I2C polling retries waiting for STSAFE response. */
#define STSE_MAX_POLLING_RETRY       100

/** Delay in milliseconds between consecutive polling retries. */
#define STSE_POLLING_RETRY_INTERVAL  10

/** @} */

/** I2C bus number where the STSAFE-A120 is connected.
 *  On STM32MP157-DK2, the Arduino-connector I2C bus is typically i2c-5. */
#define STSAFE_I2C_BUS        1

/** I2C speed in kHz (100 or 400) */
#define STSAFE_I2C_SPEED_KHZ  400

/** STSAFE data zone index holding the leaf device certificate (DER format). */
#define STSAFE_CERT_ZONE      0

/** STSAFE private key slot associated with the leaf certificate. */
#define STSAFE_KEY_SLOT       0

/** TLS server hostname or IP address.
 *  Default: public HTTPS server used to verify the TLS stack integration.
 *  For a mutual-TLS test, replace with your own server that requests a
 *  client certificate. */
#define TLS_SERVER_HOST       "example.com"

/** TLS server port */
#define TLS_SERVER_PORT       "443"

/** HTTP request path (used for the HTTP/1.1 GET after TLS handshake) */
#define TLS_SERVER_PATH       "/"

/** Optional: path to a PEM file containing the server CA trust bundle.
 *  Set to NULL to use the system default CA store. */
#define TLS_CA_BUNDLE         NULL

/* -------------------------------------------------------------------------
 * DYNAMIC ENGINE OPTION
 * -------------------------------------------------------------------------
 * Define STSAFE_USE_DYNAMIC_ENGINE to use the dynamically-loaded engine
 * (build/libstsafe_engine.so) instead of the statically-linked engine.
 *
 * In dynamic mode the application does NOT initialise the stse_Handler_t
 * itself; the engine does it internally.  The TLS example will:
 *   1. Try ENGINE_by_id("stsafe") – succeeds if OPENSSL_CONF already loaded
 *      the engine.
 *   2. Fall back to loading the .so explicitly from STSAFE_ENGINE_SO_PATH.
 *   3. Call ENGINE_ctrl_cmd to load the cert (LOAD_CERT command).
 *   4. Call ENGINE_load_private_key for the engine-backed EVP_PKEY.
 *
 * Build command (relative to repo root):
 *   make engine
 *   make EXAMPLE=06_TLS_client \
 *     CFLAGS="-DSTSAFE_USE_DYNAMIC_ENGINE \
 *             -DSTSAFE_ENGINE_SO_PATH=\\\"build/libstsafe_engine.so\\\""
 *
 * Run command:
 *   export OPENSSL_CONF=Engine/openssl-stsafe.cnf
 *   ./build/06_TLS_client
 */
// #define STSAFE_USE_DYNAMIC_ENGINE

/** Path to the engine shared library for fallback loading.
 *  Only used when STSAFE_USE_DYNAMIC_ENGINE is defined. */
#ifndef STSAFE_ENGINE_SO_PATH
#define STSAFE_ENGINE_SO_PATH "build/libstsafe_engine.so"
#endif

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* STSE_CONF_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
