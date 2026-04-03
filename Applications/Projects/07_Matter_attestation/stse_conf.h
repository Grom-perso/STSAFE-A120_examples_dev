/******************************************************************************
 * \file    stse_conf.h
 * \brief   STSecureElement library configuration for the Matter attestation
 *          example.
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

/* Matter device attestation uses NIST-P256 */
#define STSE_CONF_ECC_NIST_P_256

/* SHA-256 required for attestation message digest */
#define STSE_CONF_HASH_SHA_256

#endif /* STSE_CONF_STSAFE_A_SUPPORT */

/*********************************************************
 *                COMMUNICATION SETTINGS
 *********************************************************/
#define STSE_USE_RSP_POLLING
#define STSE_MAX_POLLING_RETRY      100
#define STSE_FIRST_POLLING_INTERVAL  10
#define STSE_POLLING_RETRY_INTERVAL  10

#ifdef __cplusplus
}
#endif

#endif /* STSE_CONF_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
