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

stse_ReturnCode_t stse_platform_generate_random_init(void) {
    rng_start();

    return (STSE_OK);
}

PLAT_UI32 stse_platform_generate_random(void) {
    return rng_generate_random_number();
}

/**
 * \brief MbedTLS-compatible RNG callback function
 * \param p_rng Context pointer (not used)
 * \param output Output buffer for random bytes
 * \param output_len Number of random bytes to generate
 * \return 0 on success
 */
int stse_platform_mbedtls_rng(void *p_rng, unsigned char *output, size_t output_len) {
    (void)p_rng;  /* Unused parameter */
    
    size_t i;
    PLAT_UI32 random_word;
    
    /* Generate random bytes in 4-byte chunks */
    for (i = 0; i < output_len; i += 4) {
        random_word = stse_platform_generate_random();
        
        /* Copy up to 4 bytes */
        size_t bytes_to_copy = (output_len - i) < 4 ? (output_len - i) : 4;
        for (size_t j = 0; j < bytes_to_copy; j++) {
            output[i + j] = (unsigned char)((random_word >> (j * 8)) & 0xFF);
        }
    }
    
    return 0;
}
