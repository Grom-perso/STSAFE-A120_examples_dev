/******************************************************************************
 * \file    stsafe_engine.h
 * \brief   STSAFE-A OpenSSL dynamic engine API.
 *
 *          The engine exposes:
 *           - Certificate loading from STSAFE data zones.
 *           - ECDSA-P256 private key operations delegated to the STSAFE
 *             device (raw key never leaves the secure element).
 *
 *          Engine ID: "stsafe"
 *
 *          Engine control commands:
 *           - I2C_BUS    (string) : Linux I2C bus device path (e.g. /dev/i2c-1)
 *           - I2C_SPEED  (int)   : I2C bus speed in kHz (default: 400)
 *           - CERT_ZONE  (int)   : STSAFE data zone holding the certificate
 *           - KEY_SLOT   (int)   : STSAFE key slot holding the private key
 *           - LOAD_CERT  (ptr)   : Load cert into an X509* (p = X509**)
 *
 *          Key ID format for ENGINE_load_private_key():
 *           "slot:<slot_number>"  e.g. "slot:0"
 *
 * \author  STMicroelectronics - CS application team
 *
 ******************************************************************************
 * \attention
 *
 * <h2><center>&copy; COPYRIGHT 2024 STMicroelectronics</center></h2>
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

#ifndef STSAFE_ENGINE_H
#define STSAFE_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/engine.h>

/** Unique identifier string for the STSAFE engine. */
#define STSAFE_ENGINE_ID   "stsafe"

/** Human-readable engine name. */
#define STSAFE_ENGINE_NAME "STSAFE-A OpenSSL Engine"

/* Control command IDs */
#define STSAFE_CMD_I2C_BUS   ENGINE_CMD_BASE
#define STSAFE_CMD_I2C_SPEED (ENGINE_CMD_BASE + 1)
#define STSAFE_CMD_CERT_ZONE (ENGINE_CMD_BASE + 2)
#define STSAFE_CMD_KEY_SLOT  (ENGINE_CMD_BASE + 3)
#define STSAFE_CMD_LOAD_CERT (ENGINE_CMD_BASE + 4)

/**
 * @brief  Entry point called by OpenSSL when the engine is loaded dynamically.
 *
 * When loaded via ENGINE_by_id("stsafe") or ENGINE_load_dynamic() this
 * function registers all engine operations.
 *
 * @param e        Engine handle provided by OpenSSL.
 * @param id       Expected engine ID string (must equal STSAFE_ENGINE_ID).
 * @return 1 on success, 0 on failure.
 */
int bind_engine(ENGINE *e, const char *id);

#ifdef __cplusplus
}
#endif

#endif /* STSAFE_ENGINE_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
