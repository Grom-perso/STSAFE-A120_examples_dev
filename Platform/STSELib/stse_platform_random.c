/******************************************************************************
 * \file	stse_platform_random.c
 * \brief   STSecureElement random number generator platform file
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

#include "Drivers/rng/rng.h"
#include "stse_conf.h"
#include "stselib.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>

stse_ReturnCode_t stse_platform_generate_random_init(void) {
    rng_start();

    return (STSE_OK);
}

PLAT_UI32 stse_platform_generate_random(void) {
    return rng_generate_random_number();
}

/* wolfCrypt-compatible RNG function */
int stse_platform_wolfcrypt_rng(void *p_rng, unsigned char *output, size_t output_len) {
    size_t i;
    PLAT_UI32 random_val;
    
    (void)p_rng; /* Unused parameter */
    
    /* Generate random bytes using platform RNG */
    for (i = 0; i < output_len; i += 4) {
        random_val = stse_platform_generate_random();
        
        /* Copy up to 4 bytes or remaining bytes */
        size_t bytes_to_copy = (output_len - i) < 4 ? (output_len - i) : 4;
        memcpy(output + i, &random_val, bytes_to_copy);
    }
    
    return 0; /* Success */
}
