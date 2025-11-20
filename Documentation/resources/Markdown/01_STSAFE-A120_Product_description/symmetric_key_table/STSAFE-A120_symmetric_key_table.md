# Symmetric Key Table {#Symmetric_key_table}

The **Symmetric Key Table** in the STSAFE-A120 device is designed to securely store and manage symmetric keys used for a variety of cryptographic operations including encryption, decryption, message authentication code (MAC) generation and verification, and key derivation.

This table provides flexible key management capabilities with fine-grained control over key usage, access conditions, and lifecycle.

## Number of Slots

- The symmetric key table contains a configurable number of slots, with a maximum of **16 slots**.
- The exact number of slots is defined during device personalization.
- Each slot securely stores one symmetric key along with its associated attributes and operational parameters.

## Key Slot Attributes

Each symmetric key slot includes the following key attributes:

| Attribute                    | Description                                                                                       |
|------------------------------|---------------------------------------------------------------------------------------------------|
| **Key Value**                | The actual symmetric key bit string (AES-128, AES-256, or Generic secret key).                    |
| **Key Type**                 | Specifies the key type: AES-128, AES-256, or Generic secret (variable length 16 to 32 bytes).     |
| **Mode of Operation**        | Cryptographic mode supported by the key (e.g., CCM*, CMAC, ECB, GCM, HMAC, HKDF).                 |
| **Key Usage**                | Defines permitted operations such as encrypt, decrypt, generate MAC, verify MAC, derive keys.     |
| **Lock Indicator**           | Controls protection level of the slot: Unlocked, Locked, or Erasable.                             |
| **Provisioning Control**     | Flags controlling provisioning methods (plaintext, wrapped, derived) and update permissions.      |
| **Mode-specific Parameters** | Parameters specific to the mode of operation (e.g., authentication tag length for CCM* or GCM).   |


## Applicative Usage of Symmetric Key Slots

- Symmetric key slots are used for:
  - **Encryption and Decryption** of data using AES in various modes (CCM*, ECB, GCM, CTR).
  - **MAC Generation and Verification** using CMAC or HMAC.
  - **Key Derivation** using HKDF.
- Keys can be provisioned in multiple ways:
  - During personalization by STMicroelectronics.
  - Dynamically by the host using commands such as **Write Symmetric Key Plaintext**, **Write Symmetric Key Wrapped**, or **Derive Keys**.
- The provisioning and usage of keys are subject to access conditions and provisioning control flags to ensure secure lifecycle management.
- Lock indicators enforce slot protection:
  - **Unlocked (00b)**: Key can be overwritten or erased.
  - **Locked (01b)**: Key cannot be overwritten or erased.
  - **Erasable (10b)**: Key cannot be overwritten but can be erased to free the slot.

## Key Usage and Modes of Operation

| Mode of Operation | Supported Key Types       | Supported Key Usages                                         |
|-------------------|---------------------------|--------------------------------------------------------------|
| **CCM\***         | AES-128, AES-256          | Encrypt, Decrypt, Encrypt by chunks, Decrypt by chunks       |
| **ECB**           | AES-128, AES-256          | Encrypt, Decrypt                                             |
| **GCM**           | AES-128, AES-256          | Encrypt, Decrypt, Encrypt by chunks, Decrypt by chunks, GMAC |
| **CMAC**          | AES-128, AES-256          | Generate MAC, Verify MAC                                     |
| **HMAC**          | Generic secret            | Generate MAC, Verify MAC                                     |
| **HKDF**          | Generic secret            | Derive keys                                                  |

> **NOTE:**  
> AES CTR mode is supported as a sub-mode of CCM* with specific configuration.  
> GMAC is supported as a specialization of GCM mode for authentication only.

## Provisioning Control and Security

- Provisioning control fields define allowed provisioning methods:
  - **Plaintext provisioning**: Allowed or disallowed per slot.
  - **Wrapped provisioning**: Requires a valid working KEK derived from a volatile base KEK.
  - **Derived keys**: Slots can be designated to accept keys derived via the **Derive Keys** command.
- Provisioning control fields can be updated once during the device lifetime.
- Access to provisioning commands is protected by command authentication and access conditions.
- The host secure channel protocol can be enforced on commands operating on symmetric keys to ensure confidentiality and integrity.

## Key Management

Keys can be securely erased using the **Erase Symmetric Key Slot** command if the slot is marked as Erasable or Unlocked.  
Usage limits and access conditions can be configured to restrict key operations and enhance security.  
The device supports atomic and chunked encryption/decryption operations for handling large data securely.  
Symmetric keys never leave the device in plaintext when wrapped provisioning is used, ensuring key confidentiality.