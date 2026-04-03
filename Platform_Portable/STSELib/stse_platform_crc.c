/******************************************************************************
 * \file    stse_platform_crc.c
 * \brief   Portable CRC-16/CCITT-FALSE software implementation for
 *          STSecureElement portable platform.
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

/* Running accumulator for multi-call CRC computation */
static PLAT_UI16 g_crc_accumulator = 0xFFFFU;

static PLAT_UI16 crc16_compute(PLAT_UI16 crc, const PLAT_UI8 *p_buf,
                                PLAT_UI16 length)
{
    for (PLAT_UI16 i = 0; i < length; i++) {
        crc ^= ((PLAT_UI16)p_buf[i]) << 8;
        for (uint8_t bit = 0; bit < 8U; bit++) {
            if (crc & 0x8000U) {
                crc = (crc << 1) ^ 0x1021U;
            } else {
                crc <<= 1;
            }
        }
    }
    return crc;
}

stse_ReturnCode_t stse_platform_crc16_init(void)
{
    g_crc_accumulator = 0xFFFFU;
    return STSE_OK;
}

PLAT_UI16 stse_platform_Crc16_Calculate(PLAT_UI8 *p_buffer, PLAT_UI16 length)
{
    return crc16_compute(0xFFFFU, p_buffer, length);
}

PLAT_UI16 stse_platform_Crc16_Accumulate(PLAT_UI8 *p_buffer, PLAT_UI16 length)
{
    g_crc_accumulator = crc16_compute(g_crc_accumulator, p_buffer, length);
    return g_crc_accumulator;
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
