/******************************************************************************
 * \file        stse_conf.h
 * \brief       STSecureElement library configuration for the dynamic engine SO
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

/* ECC curves exposed by the dynamic engine */
#define STSE_CONF_ECC_NIST_P_256
/* Uncomment to add P-384 and P-521 support */
// #define STSE_CONF_ECC_NIST_P_384
// #define STSE_CONF_ECC_NIST_P_521

/* Hash algorithms used for certificate parsing */
#define STSE_CONF_HASH_SHA_256
// #define STSE_CONF_HASH_SHA_384

/* Host key / session features are not required for signing-only engine */
// #define STSE_CONF_USE_HOST_SESSION
// #define STSE_CONF_USE_HOST_KEY_ESTABLISHMENT
// #define STSE_CONF_USE_SYMMETRIC_KEY_ESTABLISHMENT

#endif /* STSE_CONF_STSAFE_A_SUPPORT */

/************************************************************
 *                POLLING PARAMETERS
 ************************************************************/
/** Maximum I2C polling retries while waiting for STSAFE response. */
#define STSE_MAX_POLLING_RETRY       100

/** Delay in milliseconds between consecutive I2C polling retries. */
#define STSE_POLLING_RETRY_INTERVAL  10

#ifdef __cplusplus
}
#endif

#endif /* STSE_CONF_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
