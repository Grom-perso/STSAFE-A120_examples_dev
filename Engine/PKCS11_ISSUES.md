# PKCS#11 Compliance Issues — STSELib `sal/pkcs11/`

This document reports PKCS#11 standard compliance gaps and limitations
found in the STSELib `feature/pkcs11` branch
(`Grom-perso/STSELib-dev@cbcaf3f`) during integration with the OpenSSL
ENGINE and the TLS client example.

---

## Verified behaviour (no issue)

| Item | Status |
|------|--------|
| `C_GetFunctionList` exported and returns a valid function list | ✅ |
| `C_Initialize` / `C_Finalize` open/close the STSAFE over I2C | ✅ |
| `C_OpenSession` / `C_CloseSession` (one session, slot 0) | ✅ |
| `C_SignInit(CKM_ECDSA)` + `C_Sign` offloads ECDSA to STSAFE | ✅ |
| `CKM_ECDSA_SHA256` / `CKM_ECDSA_SHA384` / `CKM_ECDSA_SHA512` supported | ✅ |
| `C_FindObjectsInit` / `C_FindObjects` / `C_FindObjectsFinal` | ✅ |
| `C_GetAttributeValue(CKA_EC_PARAMS)` returns DER OID | ✅ |
| `C_GetAttributeValue(CKA_EC_POINT)` returns DER uncompressed point | ✅ |

---

## Issues and limitations

### P11-01 — `CKA_VALUE` length query returns a hardcoded estimate

**File**: `sal/pkcs11/stse_cryptoki.c`, `C_GetAttributeValue`, case `CKA_VALUE`

**Description**: When `pValue == NULL` (the standard two-pass pattern for
querying buffer length), the implementation returns `2048UL` as an estimate
instead of the real DER certificate size.

```c
} else {
    /* Caller is querying the length — return a reasonable estimate */
    pAttr->ulValueLen = 2048UL;
}
```

**Impact**:
- The OpenSSL ENGINE currently allocates 2048 bytes and performs a second
  call. This works in practice because STSAFE-A device certificates are
  typically 300–600 bytes, but is not standards-compliant.
- Applications that rely on the exact length (e.g. for tight buffer allocation
  or DER-length validation) may fail.

**Recommended fix**: Call `stse_get_device_certificate_size()` when
`pValue == NULL` to return the real certificate length.

```c
case CKA_VALUE:
    if (obj_class != CKO_CERTIFICATE) { ... }
    if (pAttr->pValue != NULL) {
        /* read DER ... */
    } else {
        /* Query actual size */
        uint16_t cert_size = 0;
        stse_ReturnCode_t rc2 = stse_get_device_certificate_size(
            &g_stse_pkcs11_lib.stse_handler,
            zone_idx, &cert_size);
        pAttr->ulValueLen = (rc2 == STSE_OK && cert_size > 0)
            ? (CK_ULONG)cert_size : (CK_ULONG)(-1L);
    }
    break;
```

---

### P11-02 — `C_GenerateRandom` is not implemented

**File**: `sal/pkcs11/stse_cryptoki.c`

**Description**: `C_GenerateRandom` returns `CKR_FUNCTION_NOT_SUPPORTED`.
STSAFE-A120 has a hardware RNG exposed via `stse_get_random()` (STSELib API)
or `stsafea_get_random()` (service layer).

**Impact**: Applications that use PKCS#11 for random number generation (e.g.
generating ephemeral session keys or nonces) cannot rely on the STSAFE RNG.

**Recommended fix**: Implement `C_GenerateRandom` by calling `stse_get_random()`.

---

### P11-03 — `C_SignUpdate` / `C_SignFinal` not supported

**File**: `sal/pkcs11/stse_cryptoki.c`

**Description**: These functions return `CKR_FUNCTION_NOT_SUPPORTED`.
Streaming multi-part signing is required by PKCS#11 v2.40 §11.11 for
compliant implementations.

**Impact**: Applications that call `C_SignUpdate` / `C_SignFinal` will fail.
TLS stacks that use single-call `C_Sign` (which is the common case) are
unaffected.  The OpenSSL ENGINE in this repository uses the single-call
`C_SignInit + C_Sign` pattern and is not affected.

**Note**: The limitation is acceptable for an embedded hardware token where
the STSAFE-A120 always receives the full digest in a single command.  This
is consistent with the PKCS#11 spec's allowance for tokens that only support
single-part operations if they set the `CKF_SIGN` flag without
`CKF_SIGN_RECOVER` in the mechanism info.

---

### P11-04 — Single session limit (`STSE_PKCS11_MAX_SESSIONS = 1`)

**File**: `sal/pkcs11/stse_pkcs11.h`

**Description**: Only one concurrent PKCS#11 session is supported.
Attempting to open a second session returns `CKR_SESSION_COUNT`.

**Impact**: Multi-threaded applications that open more than one session
(e.g. servers handling many TLS connections simultaneously) will fail after
the first session is taken.

**Note**: The PKCS#11 spec only requires that at least one session is
supported, so this is technically compliant.  For server scenarios where
signing is called from multiple threads, a mutex-protected session pool (or
a single shared session with a mutex) should be added.

---

### P11-05 — No `C_Login` / authentication support

**File**: `sal/pkcs11/stse_cryptoki.c`

**Description**: `C_Login` / `C_Logout` return `CKR_FUNCTION_NOT_SUPPORTED`.

**Impact**: Applications that require user-PIN authentication or entity
authentication before accessing the private key will fail.

**Note**: For STSAFE-A120 devices that use entity authentication (host key
establishment), the `C_Login` function should be wired to trigger the
appropriate authentication sequence before private-key operations.  Currently
this is a gap for security-sensitive deployments.

---

### P11-06 — Token label is identical to slot label

**File**: `sal/pkcs11/stse_cryptoki.c`, `C_GetTokenInfo` / `C_GetSlotInfo`

**Description**: Both `C_GetSlotInfo` and `C_GetTokenInfo` use
`"STSAFE-A120"` as their label string.

**Impact**: Minor: standard PKCS#11 interoperability is unaffected, but
URI-based key references (PKCS#11 URI `pkcs11:token=…`) must use exactly
`"STSAFE-A120"` which may be surprising to users.

---

### P11-07 — `stse_data_storage_read_data_zone` used for certificate retrieval (not `stse_get_device_certificate`)

**File**: `sal/pkcs11/stse_cryptoki.c`, case `CKA_VALUE`

**Description**: Certificate data is read with a raw data-zone read
(`stse_data_storage_read_data_zone`) rather than with the dedicated
`stse_get_device_certificate` / `stse_get_device_certificate_size` API.

**Impact**:
- No automatic size detection (linked to P11-01 above).
- The raw read requires the caller to pre-configure `cert_zone_count` and
  `cert_zone_indices` in `stse_pkcs11_config_t`, otherwise certificates
  are not visible.

**Recommended fix**: Use `stse_get_device_certificate_size` for length query
and `stse_get_device_certificate` for the actual data read.  This is
consistent with the STSELib API contract and benefits from any future
transparent encryption/decryption at the device driver level.

---

## Summary

| ID | Severity | Category | Status |
|----|----------|----------|--------|
| P11-01 | Medium | Compliance | Open — workaround in engine (2048-byte buffer) |
| P11-02 | Low | Feature gap | Open |
| P11-03 | Low | Compliance | Acceptable for hardware token |
| P11-04 | Low | Scalability | Acceptable for embedded use-case |
| P11-05 | Medium | Security | Open — relevant for entity-auth devices |
| P11-06 | Info | UX | Open |
| P11-07 | Medium | Correctness | Open — linked to P11-01 |
