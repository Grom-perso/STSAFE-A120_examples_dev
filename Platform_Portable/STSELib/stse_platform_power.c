/******************************************************************************
 * \file    stse_platform_power.c
 * \brief   Portable STSecureElement power platform stub.
 *          Power-line management is host-specific and outside the scope of
 *          the portable layer; applications that need it should control the
 *          STSAFE power supply directly.
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

#include "stse_conf.h"
#include "stselib.h"

stse_ReturnCode_t stse_platform_power_init(void)
{
    return STSE_OK;
}

stse_ReturnCode_t stse_platform_power_on(PLAT_UI8 bus, PLAT_UI8 devAddr)
{
    (void)bus;
    (void)devAddr;
    return STSE_OK;
}

stse_ReturnCode_t stse_platform_power_off(PLAT_UI8 bus, PLAT_UI8 devAddr)
{
    (void)bus;
    (void)devAddr;
    return STSE_OK;
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
