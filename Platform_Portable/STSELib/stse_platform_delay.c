/******************************************************************************
 * \file    stse_platform_delay.c
 * \brief   Portable STSecureElement delay platform implementation.
 *          Routes delay calls through the function pointer registered via
 *          stse_platform_set_io().
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

stse_ReturnCode_t stse_platform_delay_init(void)
{
    /* No hardware initialisation needed; delay is provided by function ptr. */
    return STSE_OK;
}

void stse_platform_Delay_ms(PLAT_UI32 delay_val)
{
    const stse_portable_io_t *io = stse_platform_get_io();
    if (io != NULL && io->delay_ms != NULL) {
        io->delay_ms(delay_val);
    }
}

void stse_platform_timeout_ms_start(PLAT_UI16 timeout_val)
{
    /* Timeout tracking is not required for the portable platform.
     * Hosts that need it should implement polling themselves. */
    (void)timeout_val;
}

PLAT_UI8 stse_platform_timeout_ms_get_status(void)
{
    /* Always report "not timed out" – the library's polling loop will rely
     * on STSE_MAX_POLLING_RETRY instead. */
    return 0;
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
