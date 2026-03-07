/******************************************************************************
 * \file    uart.c
 * \brief   UART driver for Linux (STM32MP1) - wraps standard I/O
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

#include "Drivers/uart/uart.h"
#include <stdio.h>

void uart_init(uint32_t baudrate) {
    (void)baudrate;
    /* On Linux, stdout/stdin are used directly; no initialization needed */
    setbuf(stdout, NULL); /* disable buffering for immediate output */
}

void uart_putc(uint8_t c) {
    putchar((int)c);
}

uint8_t uart_getc(void) {
    return (uint8_t)getchar();
}
