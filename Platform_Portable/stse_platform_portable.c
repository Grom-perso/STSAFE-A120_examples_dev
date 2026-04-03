/******************************************************************************
 * \file    stse_platform_portable.c
 * \brief   Portable platform I/O registration implementation.
 *          Stores the caller-supplied function pointers and exposes them to
 *          the platform driver files in Platform_Portable/STSELib/.
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

#include "stse_platform_portable.h"
#include <string.h>

static stse_portable_io_t g_portable_io;
static int                g_io_initialized = 0;

int stse_platform_set_io(const stse_portable_io_t *p_io)
{
    if (p_io == NULL ||
        p_io->i2c_read  == NULL ||
        p_io->i2c_write == NULL ||
        p_io->delay_ms  == NULL) {
        return -1;
    }

    memcpy(&g_portable_io, p_io, sizeof(stse_portable_io_t));
    g_io_initialized = 1;

    return 0;
}

const stse_portable_io_t *stse_platform_get_io(void)
{
    if (!g_io_initialized) {
        return NULL;
    }
    return &g_portable_io;
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
