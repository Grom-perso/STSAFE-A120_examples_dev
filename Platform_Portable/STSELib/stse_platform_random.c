/******************************************************************************
 * \file    stse_platform_random.c
 * \brief   Portable STSecureElement random number generator platform
 *          implementation.  Routes RNG calls through the optional function
 *          pointer registered via stse_platform_set_io().  If no RNG
 *          function pointer is registered the platform returns 0, which is
 *          acceptable because the STSAFE device itself supplies the entropy
 *          needed for cryptographic operations.
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

#include "../stse_platform_portable.h"
#include "stse_conf.h"
#include "stselib.h"

stse_ReturnCode_t stse_platform_generate_random_init(void)
{
    return STSE_OK;
}

PLAT_UI32 stse_platform_generate_random(void)
{
    const stse_portable_io_t *io = stse_platform_get_io();
    PLAT_UI32 rand_val = 0;

    if (io != NULL && io->rng != NULL) {
        stse_portable_rng_t rng_fn = io->rng;
        rng_fn((uint8_t *)&rand_val, sizeof(rand_val));
    }

    return rand_val;
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
