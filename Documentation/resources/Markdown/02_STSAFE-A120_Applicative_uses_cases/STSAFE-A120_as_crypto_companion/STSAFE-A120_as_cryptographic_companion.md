# Using STSAFE-A120 as a Cryptographic Companion{#STSAFE-A120_as_crypto_companion}

The STSAFE-A120 is a specialized hardware security module engineered to perform and manage advanced cryptographic operations in embedded systems.

It delivers hardware-accelerated support for AES, ECC, hash functions, true random number generation, and secure key wrapping/unwrapping.

This technical guide provides an in-depth overview of the cryptographic mechanisms, supported algorithms and curves, practical use cases, secure key storage and provisioning strategies, and includes detailed host-device interaction diagrams using precise STSAFE-A120 command nomenclature.

## Secure Key Storage and Management in STSAFE-A120

### Key Storage Architecture

The STSAFE-A120 employs a robust key storage architecture, isolating cryptographic keys in dedicated memory regions with stringent access controls to mitigate unauthorized access and tampering:

- **Private Key Table**: Retains ECC private keys (both static and ephemeral) for signature generation and key establishment operations.
- **Symmetric Key Table**: Contains AES and generic secret keys utilized for encryption, decryption, MAC generation, and key derivation.
- **Host Key Slot**: Stores host MAC and cipher keys, facilitating secure channel authentication and encryption.
- **Generic Public Key Table**: Maintains public keys for signature verification and entity authentication.
- **Local Envelope Key Slots**: Reserved for keys used exclusively in key wrapping and unwrapping procedures.

### Key Protection Mechanisms

To ensure the confidentiality, integrity, and controlled usage of cryptographic keys, the STSAFE-A120 implements multiple protection mechanisms:

- **Non-Volatile Memory (NVM)**: Static keys are securely stored in EEPROM, guaranteeing persistence across power cycles and device resets.
- **Volatile Memory (RAM)**: Ephemeral keys and volatile Key Encryption Keys (KEKs) reside in RAM, automatically erased upon reset or session termination to prevent leakage.
- **Access Conditions**: Each key slot is governed by configurable access conditions and usage flags, strictly defining permissible operations.
- **Provisioning Control Fields**: Specify allowed provisioning methods (plaintext, wrapped, derived) and update permissions, enforcing provisioning policies.
- **Lock Indicators**: Enable permanent locking, overwriting, or erasure controls for individual keys, supporting lifecycle management and revocation.
- **Host Secure Channel**: All key-related commands require host authentication (C-MAC) and, optionally, encryption, safeguarding against unauthorized access and eavesdropping.
- **Usage Limits**: Keys can be assigned usage counters, restricting the number of cryptographic operations to reduce exposure and mitigate compromise risks.

### Developer options for Key Provisioning and Management

STSAFE-A120 offers flexible secure key provisioning and management options to its host processor:

- **Provisioning Methods**:
    - **Plaintext Provisioning**: Directly write keys in plaintext, subject to provisioning controls and security policies.
    - **Wrapped Provisioning**: Provision keys securely wrapped with a working KEK, derived from a volatile base KEK established via ECDHE.
    - **Key Derivation**: Utilize HKDF to derive new keys from existing key material, supporting hierarchical key management.
    - **ECDH-Based Provisioning**: Establish keys through ECDH key agreement protocols, ensuring secure shared secret generation.
- **Key Generation**: Generate new ECC key pairs or symmetric keys internally using dedicated device commands, ensuring keys never leave the secure boundary.
- **Key Update and Rotation**: Update or rotate keys securely when reprovisioning is permitted, supporting robust key lifecycle management.
- **Key Erasure**: Securely erase keys to free slots or revoke compromised credentials.
- **Access Control Configuration**: Define and enforce access conditions and provisioning controls to align with organizational security policies.
- **Signature Verification**: Leverage stored public keys to verify digital signatures and authenticate provisioning sources, ensuring trustworthiness.

---

### AES Symmetric Cryptography

AES (Advanced Encryption Standard) is the cornerstone of symmetric cryptography, providing robust data confidentiality and integrity.  
The STSAFE-A120 supports AES-128 and AES-256 keys, offering multiple operational modes to address diverse security requirements:

- **CCM\*** (Counter with CBC-MAC): Delivers authenticated encryption with associated data (AEAD), ensuring confidentiality, integrity, and authenticity.
- **ECB** (Electronic Codebook): Basic block cipher mode, primarily for legacy compatibility or specific use cases.
- **GCM** (Galois/Counter Mode): High-performance AEAD mode with strong security guarantees.
- **CMAC** (Cipher-based Message Authentication Code): Facilitates message authentication.
- **HMAC** (Hash-based Message Authentication Code): Employs SHA-256 for message authentication.
- **HKDF** (HMAC-based Key Derivation Function): Enables secure derivation of new keys from existing key material.

The following table summarizes the supported key types and usages for each AES mode in the STSAFE-A120:

| Mode of Operation | Supported Key Types       | Supported Key Usages                                        |
|-------------------|--------------------------|--------------------------------------------------------------|
| CCM\*             | AES-128, AES-256         | Encrypt, Decrypt, Encrypt by chunks, Decrypt by chunks       |
| ECB               | AES-128, AES-256         | Encrypt, Decrypt                                             |
| GCM               | AES-128, AES-256         | Encrypt, Decrypt, Encrypt by chunks, Decrypt by chunks, GMAC |
| CMAC              | AES-128, AES-256         | Generate MAC, Verify MAC                                     |
| HMAC              | Generic secret           | Generate MAC, Verify MAC                                     |
| HKDF              | Generic secret           | Derive keys                                                  |

AES symmetric cryptography is applicable in the following scenarios:

- **Data Encryption and Integrity**: Employ CCM* or GCM modes to encrypt sensitive data and guarantee its integrity during transmission or storage.
- **Message Authentication**: Use CMAC or HMAC to generate and verify message authentication codes, protecting against unauthorized modification.
- **Key Derivation**: Apply HKDF to securely derive multiple keys from a master key, facilitating key rotation and hierarchical management.

### Provisioning or Establishing Symmetric Keys

Symmetric keys can be provisioned into the device’s symmetric key table via several secure methods:

- **Plaintext Provisioning**: Use the `Write Symmetric Key Plaintext` command to store keys directly, subject to access controls.
- **Wrapped Provisioning**: Use the `Write Symmetric Key Wrapped` command to provision keys securely wrapped with a KEK.
- **ECDH-Based Establishment**: Establish keys via ECDH using the `Establish Symmetric Keys` and `Confirm Symmetric Keys` commands.

The following interaction diagram illustrates the secure establishment of symmetric keys via ECDHE:

@startuml
participant "HOST \n (MCU/MPU)" as Host
participant "STSAFE-A120" as Device

Host -> Device: Generate ECDHE Key
Device --> Host: Device ECDHE Public Key

Host -> Device: Start Volatile KEK Session\n(Host ECDHE Public Key + Signature)
Device --> Host: (Session Established)

Host -> Device: Establish Symmetric Keys\n(Host ECDHE Public Key + Signature)
Device --> Host: (Shared Secret Derived)

Host -> Device: Confirm Symmetric Keys\n(Key Confirmation MAC + Key Info)
Device --> Host: (Keys Stored Securely)
@enduml

> **NOTE:**  
> For plaintext or wrapped provisioning, substitute the `Establish Symmetric Keys` and `Confirm Symmetric Keys` commands with `Write Symmetric Key Plaintext` or `Write Symmetric Key Wrapped`, following a similar host-device interaction sequence.

### Deriving Symmetric Keys

New symmetric keys can be derived from existing keys using the `Derive Keys` command, which implements HKDF.  
Derived keys may be stored internally or exported to the host, supporting session key generation and hierarchical key management.

@startuml
participant "HOST \n (MCU/MPU)" as Host
participant "STSAFE-A120" as Device

Host -> Device: Derive Keys\n(Input Key + HKDF Parameters + Output Key Description)
Device --> Host: Derived Key(s) or Confirmation
@enduml

> **NOTE:**  
> This interaction pattern applies to all key derivation operations, including MAC and encryption key derivation.

---

### Data Encryption

The STSAFE-A120 provides secure primitives for encrypting sensitive data, both in transit and at rest.  
Encryption is performed using a symmetric key stored within the device, invoked via the `Encrypt` command.  
Authenticated encryption modes such as CCM* and GCM are supported.

@startuml
participant "HOST \n (MCU/MPU)" as Host
participant "STSAFE-A120" as Device

Host -> Device: Encrypt\n(Key Slot + Nonce + Plaintext + Associated Data)
Device --> Host: Ciphertext + Authentication Tag
@enduml

> **NOTE:**  
> For large datasets, utilize the chunked commands `Start Encrypt`, `Process Encrypt`, and `Finish Encrypt` to manage data in segments.

### Data Decryption

Decryption of received ciphertext and verification of its integrity are facilitated by the `Decrypt` command, using a symmetric key securely stored in the device.  
Authentication tag verification is supported for AEAD modes.

'''
@startuml
participant "HOST \n (MCU/MPU)" as Host
participant "STSAFE-A120" as Device

Host -> Device: Decrypt\n(Key Slot + Nonce + Ciphertext + Authentication Tag + Associated Data)
Device --> Host: Plaintext + Verification Result
@enduml
'''

> **NOTE:**  
> For large ciphertexts, employ `Start Decrypt`, `Process Decrypt` and `Finish Decrypt` commands for segmented processing.

### Message Authentication Code (MAC) Generation

The STSAFE-A120 enables generation of MACs to ensure message integrity and authenticity.  
The `Generate MAC` command supports both CMAC and HMAC modes, selectable via key slot and MAC length parameters.

'''
@startuml
participant "HOST \n (MCU/MPU)" as Host
participant "STSAFE-A120" as Device

Host -> Device: Generate MAC\n(Key Slot + Message + MAC Length)
Device --> Host: MAC
@enduml
'''

> **NOTE:**  
> The interaction scheme applies to both CMAC and HMAC; select the appropriate key slot and MAC length as required.

### MAC Verification

Received messages can be validated using the `Verify MAC` command, which supports both CMAC and HMAC verification modes.

'''
@startuml
participant "HOST \n (MCU/MPU)" as Host
participant "STSAFE-A120" as Device

Host -> Device: Verify MAC\n(Key Slot + Message + MAC)
Device --> Host: Verification Result (True/False)
@enduml
'''

> **NOTE:**  
> The `Verify MAC` command is compatible with both CMAC and HMAC verification.

---

### Elliptic Curve Cryptography (ECC)

ECC delivers efficient asymmetric cryptographic operations with reduced key sizes, enhancing performance and security. The following table details the supported elliptic curves and cryptographic schemes for key generation, digital signatures, and key establishment in the STSAFE-A120:

| Curve Name           | Curve ID (Hex)         | Usage                          | Standards/References                |
|----------------------|------------------------|--------------------------------|-------------------------------------|
| NIST P-256           | 0x2A8648CE3D030107     | Signature, Key Establishment   | FIPS 186-4, ANSI X9.62              |
| NIST P-384           | 0x2B81040022           | Signature, Key Establishment   | FIPS 186-4, ANSI X9.62              |
| NIST P-521           | 0x2B81040023           | Signature, Key Establishment   | FIPS 186-4, ANSI X9.62              |
| Brainpool P-256      | 0x2B2403030208010107   | Signature, Key Establishment   | RFC 5639                            |
| Brainpool P-384      | 0x2B240303020801010B   | Signature, Key Establishment   | RFC 5639                            |
| Brainpool P-512      | 0x2B240303020801010D   | Signature, Key Establishment   | RFC 5639                            |
| Edwards25519         | 0x2B6570               | EdDSA Signature                | RFC 8032                            |
| Curve25519           | 0x2B656E               | X25519 Key Establishment       | RFC 7748                            |

ECC schemes are employed in the following contexts:

- **ECDSA (Elliptic Curve Digital Signature Algorithm)**: For secure digital signature generation and verification.
- **EdDSA (Edwards-curve Digital Signature Algorithm)**: High-performance signature scheme utilizing Edwards25519.
- **ECDH (Elliptic Curve Diffie-Hellman)**: For secure key agreement and shared secret derivation.
- **X25519**: Efficient key agreement using Curve25519.

### Key Pair Generation

If ECC keys are not pre-provisioned, the STSAFE-A120 can generate new ECC key pairs internally, securely storing the private key in a dedicated slot via the `Generate Key` command.

'''
@startuml
participant "HOST \n (MCU/MPU)" as Host
participant "STSAFE-A120" as Device

Host -> Device: Generate Key\n(Private Key Slot + Curve ID + Usage Limit)
Device --> Host: Public Key
@enduml
'''

> **NOTE:**  
> The `Generate Key` command supports both static and ephemeral key generation; ephemeral keys are stored in RAM for transient key establishment.

---

### Digital Signature Generation

For device authentication or secure data exchange, the STSAFE-A120 can generate digital signatures over messages or message digests using the `Generate Signature` command or within a signature session (`Start Session [Signature Session]` + `Get Signature`).

'''
@startuml
participant "HOST \n (MCU/MPU)" as Host
participant "STSAFE-A120" as Device

Host -> Device: Generate Signature\n(Private Key Slot + Message Digest)
Device --> Host: Signature
@enduml
'''

### Digital Signature Verification

To authenticate data or the device itself, the STSAFE-A120 verifies digital signatures using the `Verify Signature` command, requiring the public key and signature.

'''
@startuml
participant "HOST \n (MCU/MPU)" as Host
participant "STSAFE-A120" as Device

Host -> Device: Verify Signature\n(Public Key + Message Digest + Signature)
Device --> Host: Verification Result (True/False)
@enduml
'''

> **NOTE:**  
> The STSAFE-A120 supports both ECDSA and EdDSA signature verification; specify the key type as an argument to the `Verify Signature` command.

### Symmetric Key Establishment via ECDH

For secure encrypted communications, the STSAFE-A120 can derive shared symmetric keys using the `Establish Key [Private Key Slot]` command, leveraging ECDH key agreement.

'''
@startuml
participant "HOST \n (MCU/MPU)" as Host
participant "STSAFE-A120" as Device

Host -> Device: Host ECDH Public Key
Device --> Host: Device ECDH Public Key

Host -> Device: Establish Key\n(Private Key Slot + Host Public Key)
Device --> Host: Shared Secret
@enduml
'''

> **NOTE:**  
> Ephemeral keys are recommended for forward secrecy; derived shared secrets can be further processed using key derivation functions.

Following example(s) illustrating this process are available in the STSAFE-A120 examples package  

- [STSAFE-A120 Symmetric key establishment AES-128 CMAC](#STSAFE-A120_Symmetric_key_establishment_AES-128_CMAC)
- [STSAFE-A120 Symmetric key establishment AES-256 CCM](#STSAFE-A120_Symmetric_key_establishment_AES-256_CCM)


---

### Hash Engine

Hash functions generate fixed-length digests from arbitrary input data, supporting data integrity, digital signatures, and MAC operations.  
The STSAFE-A120 supports:

- **SHA-2 Family**: SHA-256, SHA-384, SHA-512.
- **SHA-3 Family**: SHA3-256, SHA3-384, SHA3-512.

Hashing is applicable for:

- **Data Integrity**: Verifying the integrity of data.
- **Signature Preparation**: Hashing messages prior to signing or verification.
- **MAC Computation**: Used internally in HMAC and HKDF operations.

The following diagram illustrates hash processing interactions:

'''
@startuml
participant "HOST \n (MCU/MPU)" as Host
participant "STSAFE-A120" as Device

Host -> Device: Start Hash Command
Host -> Device: Process Hash Commands (data chunks)
Host -> Device: Finish Hash Command
Device --> Host: Hash Digest
@enduml
'''

Following example(s) illustrating this process are available in the STSAFE-A120 examples package:

- [STSAFE-A120 Hash](#STSAFE-A120_Hash)

---

### Random Number Generation

Random numbers are fundamental to cryptographic operations such as key generation, nonces, and salts.  
The STSAFE-A120 integrates a True Random Number Generator (TRNG) compliant with NIST SP800-90B.

Random numbers are used for:

- **Key Generation**: Creating cryptographically strong keys.
- **Nonce Generation**: Ensuring uniqueness in encryption operations.
- **Salt Generation**: Supporting key derivation and hashing.

The following diagram demonstrates random number generation interactions:

'''
@startuml
participant "HOST \n (MCU/MPU)" as Host
participant "STSAFE-A120" as Device

Host -> Device: Generate Random Command (length)
Device --> Host: Random Bytes
@enduml
'''

Following example(s) illustrating this process are available in the STSAFE-A120 examples package:

- [STSAFE-A120_Random_number_generation](#STSAFE-A120_Random_number_generation)



---

### Key Wrapping and Unwrapping

Key wrapping securely encrypts keys for storage or transport, maintaining confidentiality and integrity.  
The STSAFE-A120 supports AES key wrap in accordance with NIST SP800-38F.

Key wrapping is utilized for:

- **Secure Key Storage**: Encrypting keys prior to host non-volatile memory storage.
- **Key Transport**: Securely transferring keys between host and device.
- **Key Lifecycle Management**: Rotating and updating keys securely.

The following diagram illustrates secure envelope wrap/unwrap interactions:

'''
@startuml
participant "HOST \n (MCU/MPU)" as Host
participant "STSAFE-A120" as Device

Host -> Device: Wrap Local Envelope\n(Working key + envelope key slot)
Device --> Host: Wrapped Key Envelope

Host -> Device: Unwrap Local Envelope\n(Wrapped key envelope + envelope key slot)
Device --> Host: Working Key
@enduml
'''

Following example(s) illustrating this process are available in the STSAFE-A120 examples package:

- [STSAFE-A120 Key wrapping](#STSAFE-A120_wrap_unwrap)

---

© 2025 STMicroelectronics – All rights reserved