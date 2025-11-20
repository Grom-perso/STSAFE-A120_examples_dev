# STSAFE-A120 PRODUCT DESCRIPTION

The STSAFE-A120 is part of the STSAFE-A secure element family from STMicroelectronics, designed to provide robust security services for a wide range of applications.

These secure elements are engineered to deliver authentication, confidentiality, and platform integrity, helping original equipment manufacturers (OEMs) protect their products against threats such as cloning, counterfeiting, malware injection, and unauthorized production.

STSAFE-A devices are compliant with stringent security certifications and are delivered as turnkey solutions, complete with pre-provisioned secrets and certificates, as well as comprehensive software libraries and drivers to facilitate secure and seamless integration into customer platforms.

![STSAFE-A120 authentication chip](./stsafe-a120-authentication-chip.avif)

## Product Feature Set

The **STSAFE-A120**  provides robust cryptographic services and secure key management for embedded systems.  
It supports a wide range of cryptographic primitives, secure key provisioning, and secure communication protocols to protect data integrity, confidentiality, and authenticity.

- **Host Secure Channel Protocol**
  - Establishes a secure communication link between the host and the STSAFE-A120.
  - Uses symmetric keys (host MAC key and host cipher key) for:
    - **Host C-MAC**: Command authentication to prevent counterfeit devices.
    - **Host R-MAC**: Response authentication to ensure response integrity.
    - **Host C-encryption**: Encrypts command data to protect against eavesdropping.
    - **Host R-encryption**: Encrypts response data for confidentiality.
  - Supports two host key slot formats:
    - **V2**: AES-128 or AES-256 keys with 32-bit sequence counter.
    - **V1**: AES-128 keys with 24-bit sequence counter (used primarily to ensure backward compatibility with the previous generation of STSAFE-A secure element).
  - Host key provisioning supports plaintext, wrapped keys, and keys derived via ECDH.

- **Entity Authentication**
  - Authenticates off-chip entities by verifying digital signatures over challenges.
  - Supports ECDSA and EdDSA signature schemes.
  - Public keys for authentication are stored in a generic public key table.

- **Data Partition**
  - Secure data container with multiple zones.
  - Zones can have one-way counters for atomic decrement and update operations.
  - Access conditions (read/update) enforce security policies.
  - Supports atomic and non-atomic updates.
  - Supports host secure channel enforcement for command authentication and encryption.

- **Private Key Signature Generation**
  - Supports ECDSA and EdDSA signature generation.
  - Two modes:
    - Signature over sequences of commands and responses.
    - Signature over messages or message digests provided by the host.
  - Supports Ed25519 with options for RFC8032-compliant or alternative ephemeral key generation.

- **Public Key Signature Verification**
  - Verifies signatures for message authentication and off-chip entity authentication.
  - Supports multiple elliptic curves including Montgomery (NIST & Brainpool) & Edwards curves.

- **Key Establishment**
  - Supports Diffie-Hellman (ECDH) key agreement protocols for Montgomery & Edwards curves.
  - Enables secure shared secret generation between host and remote entities.

- **Wrapping and Unwrapping Local Envelopes/Secrets**
  - Supports wrapping/unwrapping of working keys using AES key wrap (NIST SP800-38F).
  - Local envelope keys are securely stored and never leave the device.

- **Generic Symmetric Key Operations**
  - Supports AES-128 and AES-256 keys and generic secret keys.
  - Modes of operation include CCM*, CMAC, ECB, GCM, GMAC, HMAC, HKDF, and CTR.
  - Supports encryption, decryption, MAC generation/verification, and key derivation.

- **Hash Engine**
  - Supports SHA-2 (SHA-256, SHA-384, SHA-512) and SHA-3 (SHA3-256, SHA3-384, SHA3-512).
  - Commands for starting, processing, and finishing hash computations.

- **Random Number Generation**
  - True Random Number Generator (TRNG) compliant with NIST SP800-90B.
  - Generates variable-length random numbers.

- **Device Administration**
  - Lifecycle states: Operational, Locked, Terminated.
  - Password protection for lifecycle state changes.
  - I²C interface with configurable parameters.
  - Query and put attribute commands for device configuration and status.

## Personalization and Pre-Provisioning

Each STSAFE-A120 device is configured and pre-provisioned in STMicroelectronics' secure manufacturing facilities.  
During personalization, various device attributes can be set according to the customer's requirements.  
This ensures that each device is uniquely tailored for its intended application and security profile.

The following attributes can be configured in each personalization profile :
- @subpage Private_key_table_and_leaf_certificates
- @subpage Symmetric_key_table
- @subpage Generic_Public_Key_Table
- @subpage Host_key_provisioning_command_access_conditions_and_encryption_flags
- Generic device configuration (I²C parameters, Low power mode & password protection)

For customers who require a generic product evaluation or whose end-products are not intended to operate under a public key infrastructure (PKI) with STMicroelectronics as the certificate authority (CA) or intermediate CA provider, a generic personalization profile (SPL05) is available.  
For more details, refer to the documentation section: @subpage STSAFE-A120_How_to_use_STSAFE-A120_SPL05 .

For further information regarding device personalization, provisioning options, or to discuss your specific requirements, please contact your local STMicroelectronics sales representative.


---

© 2025 STMicroelectronics – All rights reserved