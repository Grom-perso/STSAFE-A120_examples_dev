/******************************************************************************
 * \file    stse_platform_generic.h
 * \brief   Generic platform type definitions for portable STSELib builds.
 *          Replaces the MCU-specific stse_platform_generic.h found in
 *          Platform/STSELib/ with a version that has no STM32 dependencies.
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

#ifndef STSE_PLATFORM_GENERIC_H
#define STSE_PLATFORM_GENERIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PLAT_UI8  uint8_t
#define PLAT_UI16 uint16_t
#define PLAT_UI32 uint32_t
#define PLAT_UI64 uint64_t
#define PLAT_I8   int8_t
#define PLAT_I16  int16_t
#define PLAT_I32  int32_t

/* Use standard C packed-struct attribute when not compiling for ARMCC */
#if defined(__GNUC__) || defined(__clang__)
#define PLAT_PACKED_STRUCT __attribute__((packed))
#elif defined(__ICCARM__)
#define PLAT_PACKED_STRUCT __packed
#else
#define PLAT_PACKED_STRUCT
#endif

#ifdef __cplusplus
}
#endif

#endif /* STSE_PLATFORM_GENERIC_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
