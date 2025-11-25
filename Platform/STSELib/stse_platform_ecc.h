#ifndef STSE_PLATFORM_ECC_H
#define STSE_PLATFORM_ECC_H

#include <stdint.h>
#include "Middleware/STSELib/core/stse_generic_typedef.h"
#include "Middleware/STSELib/core/stse_return_codes.h"

#ifdef __cplusplus
extern "C" {
#endif

stse_ReturnCode_t stse_platform_ecc_verify_with_rs(stse_ecc_key_type_t key_type,
                                                  const uint8_t *pPubKey,
                                                  uint8_t *pDigest,
                                                  uint16_t digestLen,
                                                  const uint8_t *pR,
                                                  uint32_t rLen,
                                                  const uint8_t *pS,
                                                  uint32_t sLen);

// Optionally declare helpers for curve id and key length if needed

#ifdef __cplusplus
}
#endif

#endif // STSE_PLATFORM_ECC_H
