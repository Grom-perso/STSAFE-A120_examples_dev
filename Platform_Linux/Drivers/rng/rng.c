/******************************************************************************
 * \file    rng.c
 * \brief   Random Number Generator driver for Linux (STM32MP1) using getrandom()
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
#include <fcntl.h>
#include <stdio.h>
#include <sys/random.h>
#include <unistd.h>

void rng_start(void) {
    /* Nothing to start on Linux - kernel RNG is always available */
}

uint32_t rng_generate_random_number(void) {
    uint32_t value = 0;
    ssize_t  ret;

    ret = getrandom(&value, sizeof(value), 0);
    if (ret != sizeof(value)) {
        /* Fallback: read from /dev/urandom */
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            if (read(fd, &value, sizeof(value)) != sizeof(value)) {
                /* If read fails, return 0 - caller should handle this */
                value = 0;
            }
            close(fd);
        }
    }

    return value;
}

void rng_stop(void) {
    /* Nothing to stop on Linux */
}
