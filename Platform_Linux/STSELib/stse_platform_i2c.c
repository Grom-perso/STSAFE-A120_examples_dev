/******************************************************************************
 * \file    stse_platform_i2c.c
 * \brief   STSecureElement I2C platform for Linux (STM32MP1)
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

#include "stse_conf.h"
#include "stselib.h"
#include "Drivers/i2c/I2C.h"
#include <string.h>

static PLAT_UI8  I2c_buffer[755U]; /* A120 max input buffer size + 2 bytes response length + 1 header */
static PLAT_UI16 i2c_frame_size;
static PLAT_UI16 i2c_frame_offset;

stse_ReturnCode_t stse_platform_i2c_init(PLAT_UI8 busID) {
    return (stse_ReturnCode_t)i2c_init((I2C_TypeDef)busID);
}

stse_ReturnCode_t stse_platform_i2c_wake(PLAT_UI8 busID,
                                         PLAT_UI8 devAddr,
                                         PLAT_UI16 speed) {
    (void)speed;
    i2c_wake((I2C_TypeDef)busID, devAddr);
    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send_start(
    PLAT_UI8  busID,
    PLAT_UI8  devAddr,
    PLAT_UI16 speed,
    PLAT_UI16 FrameLength) {
    (void)busID;
    (void)devAddr;
    (void)speed;

    if (FrameLength > sizeof(I2c_buffer) / sizeof(I2c_buffer[0])) {
        return STSE_PLATFORM_BUFFER_ERR;
    }

    i2c_frame_size   = FrameLength;
    i2c_frame_offset = 0;

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send_continue(
    PLAT_UI8  busID,
    PLAT_UI8  devAddr,
    PLAT_UI16 speed,
    PLAT_UI8 *pData,
    PLAT_UI16 data_size) {
    (void)busID;
    (void)devAddr;
    (void)speed;

    if (data_size != 0) {
        if (pData == NULL) {
            memset((I2c_buffer + i2c_frame_offset), 0x00, data_size);
        } else {
            memcpy((I2c_buffer + i2c_frame_offset), pData, data_size);
        }
        i2c_frame_offset += data_size;
    }

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send_stop(
    PLAT_UI8  busID,
    PLAT_UI8  devAddr,
    PLAT_UI16 speed,
    PLAT_UI8 *pData,
    PLAT_UI16 data_size) {
    stse_ReturnCode_t ret;

    ret = stse_platform_i2c_send_continue(busID, devAddr, speed, pData, data_size);

    if (ret == STSE_OK) {
        ret = (stse_ReturnCode_t)i2c_write((I2C_TypeDef)busID, devAddr, speed, I2c_buffer, i2c_frame_size);
    }

    if (ret != STSE_OK) {
        ret = STSE_PLATFORM_BUS_ACK_ERROR;
    }

    return ret;
}

stse_ReturnCode_t stse_platform_i2c_receive_start(
    PLAT_UI8  busID,
    PLAT_UI8  devAddr,
    PLAT_UI16 speed,
    PLAT_UI16 frameLength) {
    PLAT_I8 ret = 1;

    i2c_frame_size = frameLength;

    ret = i2c_read((I2C_TypeDef)busID, devAddr, speed, I2c_buffer, i2c_frame_size);
    if (ret != 0) {
        return STSE_PLATFORM_BUS_ACK_ERROR;
    }

    i2c_frame_offset = 0;

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_receive_continue(
    PLAT_UI8  busID,
    PLAT_UI8  devAddr,
    PLAT_UI16 speed,
    PLAT_UI8 *pData,
    PLAT_UI16 data_size) {
    (void)busID;
    (void)devAddr;
    (void)speed;

    if (pData != NULL) {
        if ((i2c_frame_size - i2c_frame_offset) < data_size) {
            return STSE_PLATFORM_BUFFER_ERR;
        }
        memcpy(pData, (I2c_buffer + i2c_frame_offset), data_size);
    }

    i2c_frame_offset += data_size;

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_receive_stop(
    PLAT_UI8  busID,
    PLAT_UI8  devAddr,
    PLAT_UI16 speed,
    PLAT_UI8 *pData,
    PLAT_UI16 data_size) {
    stse_ReturnCode_t ret;

    ret              = stse_platform_i2c_receive_continue(busID, devAddr, speed, pData, data_size);
    i2c_frame_offset = 0;

    return ret;
}
