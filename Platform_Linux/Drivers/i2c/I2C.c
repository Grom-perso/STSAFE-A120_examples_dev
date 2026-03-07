/******************************************************************************
 * \file    I2C.c
 * \brief   I2C driver for Linux (STM32MP1) using /dev/i2c-X interface
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

#include "Drivers/i2c/I2C.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define I2C_MAX_BUS 16

static int i2c_fds[I2C_MAX_BUS];

uint8_t i2c_init(I2C_TypeDef bus_num) {
    char dev_path[32];

    if (bus_num < 0 || bus_num >= I2C_MAX_BUS) {
        fprintf(stderr, "i2c_init: invalid bus number %d\n", bus_num);
        return 1;
    }

    snprintf(dev_path, sizeof(dev_path), "/dev/i2c-%d", bus_num);
    i2c_fds[bus_num] = open(dev_path, O_RDWR);
    if (i2c_fds[bus_num] < 0) {
        fprintf(stderr, "i2c_init: failed to open %s: %s\n", dev_path, strerror(errno));
        return 1;
    }

    return 0;
}

void i2c_deinit(I2C_TypeDef bus_num) {
    if (bus_num >= 0 && bus_num < I2C_MAX_BUS && i2c_fds[bus_num] >= 0) {
        close(i2c_fds[bus_num]);
        i2c_fds[bus_num] = -1;
    }
}

int8_t i2c_write(I2C_TypeDef bus_num, uint8_t slave_address, uint16_t speed, uint8_t *pbuffer, uint16_t size) {
    struct i2c_msg msg;
    struct i2c_rdwr_ioctl_data data;

    (void)speed;

    if (bus_num < 0 || bus_num >= I2C_MAX_BUS || i2c_fds[bus_num] < 0) {
        return -1;
    }

    msg.addr  = slave_address;
    msg.flags = 0;          /* write */
    msg.len   = size;
    msg.buf   = pbuffer;

    data.msgs  = &msg;
    data.nmsgs = 1;

    if (ioctl(i2c_fds[bus_num], I2C_RDWR, &data) < 0) {
        return -1;
    }

    return 0;
}

int8_t i2c_read(I2C_TypeDef bus_num, uint8_t slave_address, uint16_t speed, uint8_t *pbuffer, uint16_t size) {
    struct i2c_msg msg;
    struct i2c_rdwr_ioctl_data data;

    (void)speed;

    if (bus_num < 0 || bus_num >= I2C_MAX_BUS || i2c_fds[bus_num] < 0) {
        return -1;
    }

    msg.addr  = slave_address;
    msg.flags = I2C_M_RD;  /* read */
    msg.len   = size;
    msg.buf   = pbuffer;

    data.msgs  = &msg;
    data.nmsgs = 1;

    if (ioctl(i2c_fds[bus_num], I2C_RDWR, &data) < 0) {
        return -1;
    }

    return 0;
}

void i2c_wake(I2C_TypeDef bus_num, uint8_t slave_address) {
    /* Send zero-length write to wake STSAFE device */
    struct i2c_msg msg;
    struct i2c_rdwr_ioctl_data data;

    if (bus_num < 0 || bus_num >= I2C_MAX_BUS || i2c_fds[bus_num] < 0) {
        return;
    }

    msg.addr  = slave_address;
    msg.flags = 0;
    msg.len   = 0;
    msg.buf   = NULL;

    data.msgs  = &msg;
    data.nmsgs = 1;

    /* Ignore return value - NACK is expected on wake */
    ioctl(i2c_fds[bus_num], I2C_RDWR, &data);
}
