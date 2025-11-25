/******************************************************************************
 * \file	stse_platform_crypto_init.c
 * \brief   STSecureElement cryptographic platform file
 * \author  STMicroelectronics - CS application team
 *
 ******************************************************************************
 * \attention
 *
 * <h2><center>&copy; COPYRIGHT 2022 STMicroelectronics</center></h2>
 *
 * This software is licensed under terms that can be found in the LICENSE file in
 * the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/random.h>
#include "stse_conf.h"
#include "stselib.h"
#include "stse_platform_generic.h"

/* Global WC_RNG instance */
static WC_RNG stse_platform_rng;
static int rng_initialized = 0;

WC_RNG* stse_platform_get_rng(void) {
    return &stse_platform_rng;
}

stse_ReturnCode_t stse_platform_crypto_init(void) {
    stse_ReturnCode_t ret = STSE_OK;

    /* - Initialize wolfCrypt library */
    if (wolfCrypt_Init() != 0) {
        ret = STSE_PLATFORM_CRYPTO_INIT_ERROR;
        return ret;
    }

    /* Initialize WC_RNG with custom seed function */
    if (wc_InitRng(&stse_platform_rng) != 0) {
        ret = STSE_PLATFORM_CRYPTO_INIT_ERROR;
        return ret;
    }
    
    rng_initialized = 1;

    return ret;
}
