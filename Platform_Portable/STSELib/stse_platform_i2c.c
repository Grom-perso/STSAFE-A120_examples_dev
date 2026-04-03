/******************************************************************************
 * \file    stse_platform_i2c.c
 * \brief   Portable STSecureElement I2C platform implementation.
 *          Routes all I2C operations through the function pointers registered
 *          via stse_platform_set_io(), enabling the library to operate on any
 *          host architecture (Linux, ESP32, Nordic, …).
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
#include "core/stse_platform.h"
#include <stdlib.h>
#include <string.h>

/* Maximum I2C frame size (A120 max input buffer + 3 bytes overhead) */
#define PORTABLE_I2C_BUF_SIZE 758U

static uint8_t  i2c_buffer[PORTABLE_I2C_BUF_SIZE];
static uint16_t i2c_frame_size;
static uint16_t i2c_frame_offset;

stse_ReturnCode_t stse_platform_i2c_init(PLAT_UI8 busID)
{
    (void)busID;
    /* Nothing to initialise at the platform level; the caller has already
     * opened the I2C bus and registered the function pointers. */
    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_wake(PLAT_UI8 busID,
                                         PLAT_UI8 devAddr,
                                         PLAT_UI16 speed)
{
    (void)busID;
    (void)speed;

    const stse_portable_io_t *io = stse_platform_get_io();
    if (io == NULL) {
        return STSE_PLATFORM_BUS_ACK_ERROR;
    }

    /* Send a zero-length write to wake the device */
    io->i2c_write(devAddr, NULL, 0);

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send_start(PLAT_UI8  busID,
                                               PLAT_UI8  devAddr,
                                               PLAT_UI16 speed,
                                               PLAT_UI16 FrameLength)
{
    (void)busID;
    (void)devAddr;
    (void)speed;

    if (FrameLength > PORTABLE_I2C_BUF_SIZE) {
        return STSE_PLATFORM_BUFFER_ERR;
    }

    i2c_frame_size   = FrameLength;
    i2c_frame_offset = 0;

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send_continue(PLAT_UI8  busID,
                                                  PLAT_UI8  devAddr,
                                                  PLAT_UI16 speed,
                                                  PLAT_UI8 *pData,
                                                  PLAT_UI16 data_size)
{
    (void)busID;
    (void)devAddr;
    (void)speed;

    if (data_size == 0) {
        return STSE_OK;
    }

    if ((i2c_frame_offset + data_size) > i2c_frame_size) {
        return STSE_PLATFORM_BUFFER_ERR;
    }

    if (pData == NULL) {
        memset(i2c_buffer + i2c_frame_offset, 0x00, data_size);
    } else {
        memcpy(i2c_buffer + i2c_frame_offset, pData, data_size);
    }
    i2c_frame_offset += data_size;

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_send_stop(PLAT_UI8  busID,
                                              PLAT_UI8  devAddr,
                                              PLAT_UI16 speed,
                                              PLAT_UI8 *pData,
                                              PLAT_UI16 data_size)
{
    stse_ReturnCode_t ret;

    ret = stse_platform_i2c_send_continue(busID, devAddr, speed,
                                          pData, data_size);
    if (ret != STSE_OK) {
        return ret;
    }

    const stse_portable_io_t *io = stse_platform_get_io();
    if (io == NULL) {
        return STSE_PLATFORM_BUS_ACK_ERROR;
    }

    if (io->i2c_write(devAddr, i2c_buffer, i2c_frame_size) != 0) {
        return STSE_PLATFORM_BUS_ACK_ERROR;
    }

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_receive_start(PLAT_UI8  busID,
                                                  PLAT_UI8  devAddr,
                                                  PLAT_UI16 speed,
                                                  PLAT_UI16 frameLength)
{
    (void)busID;
    (void)speed;

    if (frameLength > PORTABLE_I2C_BUF_SIZE) {
        return STSE_PLATFORM_BUFFER_ERR;
    }

    i2c_frame_size   = frameLength;
    i2c_frame_offset = 0;

    const stse_portable_io_t *io = stse_platform_get_io();
    if (io == NULL) {
        return STSE_PLATFORM_BUS_ACK_ERROR;
    }

    if (io->i2c_read(devAddr, i2c_buffer, i2c_frame_size) != 0) {
        return STSE_PLATFORM_BUS_ACK_ERROR;
    }

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_receive_continue(PLAT_UI8  busID,
                                                     PLAT_UI8  devAddr,
                                                     PLAT_UI16 speed,
                                                     PLAT_UI8 *pData,
                                                     PLAT_UI16 data_size)
{
    (void)busID;
    (void)devAddr;
    (void)speed;

    if (pData != NULL) {
        if ((i2c_frame_size - i2c_frame_offset) < data_size) {
            return STSE_PLATFORM_BUFFER_ERR;
        }
        memcpy(pData, i2c_buffer + i2c_frame_offset, data_size);
    }
    i2c_frame_offset += data_size;

    return STSE_OK;
}

stse_ReturnCode_t stse_platform_i2c_receive_stop(PLAT_UI8  busID,
                                                 PLAT_UI8  devAddr,
                                                 PLAT_UI16 speed,
                                                 PLAT_UI8 *pData,
                                                 PLAT_UI16 data_size)
{
    stse_ReturnCode_t ret;

    ret = stse_platform_i2c_receive_continue(busID, devAddr, speed,
                                             pData, data_size);
    i2c_frame_offset = 0;

    return ret;
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
