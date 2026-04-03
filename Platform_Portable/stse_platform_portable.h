/******************************************************************************
 * \file    stse_platform_portable.h
 * \brief   Portable platform abstraction layer for STSecureElement library.
 *          Provides function-pointer-based I/O registration to allow the
 *          STSELib to run on any host architecture (STM32, ESP32, Nordic,
 *          Linux, …) without modification.
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

#ifndef STSE_PLATFORM_PORTABLE_H
#define STSE_PLATFORM_PORTABLE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/**
 * @defgroup STSE_Portable_Platform Portable Platform Abstraction
 * @brief    Host-agnostic I/O and timing abstraction for STSELib.
 *
 * To port STSELib to a new host (e.g. ESP32, Nordic nRF, Linux):
 *  1. Implement three functions matching the signatures below.
 *  2. Call stse_platform_set_io() once at start-up, before stse_init().
 *
 * @{
 */

/**
 * @brief  I2C read function pointer type.
 *
 * The implementation must:
 *  - Address the I2C device at @p dev_addr (7-bit, un-shifted).
 *  - Read @p length bytes into @p p_data.
 *  - Return 0 on success, non-zero on error.
 *
 * @param dev_addr  7-bit I2C device address.
 * @param p_data    Destination buffer.
 * @param length    Number of bytes to read.
 * @return          0 on success, non-zero on error.
 */
typedef int (*stse_portable_i2c_read_t)(uint8_t dev_addr,
                                        uint8_t *p_data,
                                        uint16_t length);

/**
 * @brief  I2C write function pointer type.
 *
 * @param dev_addr  7-bit I2C device address.
 * @param p_data    Source buffer.
 * @param length    Number of bytes to write.
 * @return          0 on success, non-zero on error.
 */
typedef int (*stse_portable_i2c_write_t)(uint8_t dev_addr,
                                         const uint8_t *p_data,
                                         uint16_t length);

/**
 * @brief  Millisecond delay function pointer type.
 *
 * @param ms  Number of milliseconds to wait.
 */
typedef void (*stse_portable_delay_ms_t)(uint32_t ms);

/**
 * @brief  Random number generation function pointer type.
 *
 * @param p_data  Destination buffer for random bytes.
 * @param length  Number of random bytes to generate.
 * @return        0 on success, non-zero on error.
 */
typedef int (*stse_portable_rng_t)(uint8_t *p_data, uint16_t length);

/**
 * @brief  Portable I/O context structure.
 *
 * Populate all fields and pass a pointer to stse_platform_set_io().
 */
typedef struct {
    stse_portable_i2c_read_t  i2c_read;   /**< I2C read implementation    */
    stse_portable_i2c_write_t i2c_write;  /**< I2C write implementation   */
    stse_portable_delay_ms_t  delay_ms;   /**< Millisecond delay impl.    */
    stse_portable_rng_t       rng;        /**< RNG implementation (opt.)  */
} stse_portable_io_t;

/**
 * @brief  Register platform I/O function pointers.
 *
 * Must be called before stse_init().  The @p p_io structure is copied
 * internally so the caller does not need to keep it alive.
 *
 * @param p_io  Pointer to a fully populated stse_portable_io_t.
 * @return       0 on success, -1 if @p p_io or mandatory fields are NULL.
 */
int stse_platform_set_io(const stse_portable_io_t *p_io);

/**
 * @brief  Return a pointer to the currently registered I/O context.
 *
 * Returns NULL if stse_platform_set_io() has not been called yet.
 */
const stse_portable_io_t *stse_platform_get_io(void);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* STSE_PLATFORM_PORTABLE_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
