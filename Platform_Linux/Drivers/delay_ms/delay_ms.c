/******************************************************************************
 * \file    delay_ms.c
 * \brief   Millisecond delay driver for Linux (STM32MP1)
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

#include "Drivers/delay_ms/delay_ms.h"
#include <time.h>
#include <unistd.h>

static struct timespec timeout_end;

void delay_ms_init(void) {
    /* Nothing to initialize on Linux */
}

void delay_ms(uint16_t ms) {
    struct timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

void timeout_ms_start(uint16_t ms) {
    clock_gettime(CLOCK_MONOTONIC, &timeout_end);
    timeout_end.tv_sec  += ms / 1000;
    timeout_end.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (timeout_end.tv_nsec >= 1000000000L) {
        timeout_end.tv_sec  += 1;
        timeout_end.tv_nsec -= 1000000000L;
    }
}

uint8_t timeout_ms_get_status(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec > timeout_end.tv_sec ||
        (now.tv_sec == timeout_end.tv_sec && now.tv_nsec >= timeout_end.tv_nsec)) {
        return 1; /* timeout elapsed */
    }
    return 0;
}
