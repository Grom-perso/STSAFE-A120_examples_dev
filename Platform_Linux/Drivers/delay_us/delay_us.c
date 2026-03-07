/******************************************************************************
 * \file    delay_us.c
 * \brief   Microsecond delay driver for Linux (STM32MP1)
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

#include "Drivers/delay_us/delay_us.h"
#include <time.h>
#include <unistd.h>

static struct timespec timeout_us_end;

void delay_us_init(void) {
    /* Nothing to initialize on Linux */
}

void delay_us(uint16_t us) {
    struct timespec ts;
    ts.tv_sec  = us / 1000000;
    ts.tv_nsec = (us % 1000000) * 1000L;
    nanosleep(&ts, NULL);
}

void timeout_us_start(uint16_t us) {
    clock_gettime(CLOCK_MONOTONIC, &timeout_us_end);
    timeout_us_end.tv_nsec += (long)us * 1000L;
    if (timeout_us_end.tv_nsec >= 1000000000L) {
        timeout_us_end.tv_sec  += timeout_us_end.tv_nsec / 1000000000L;
        timeout_us_end.tv_nsec  = timeout_us_end.tv_nsec % 1000000000L;
    }
}

uint8_t timeout_us_get_status(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec > timeout_us_end.tv_sec ||
        (now.tv_sec == timeout_us_end.tv_sec && now.tv_nsec >= timeout_us_end.tv_nsec)) {
        return 1; /* timeout elapsed */
    }
    return 0;
}
