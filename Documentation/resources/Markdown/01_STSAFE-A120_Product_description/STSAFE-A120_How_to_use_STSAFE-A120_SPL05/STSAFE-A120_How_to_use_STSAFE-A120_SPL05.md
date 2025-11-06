# Getting Started with STSAFE-A120 SPL05 Generic Sample Profile {#STSAFE-A120_How_to_use_STSAFE-A120_SPL05}

This section summarizes the mandatory steps and key information to start using the STSAFE-A120 device configured with the SPL05 generic sample profile .
Detailed profile description is available on [www.st.com](https://www.st.com/resource/en/application_note/an6053-stsafea120-spl05-generic-sample-profile-description-stmicroelectronics.pdf)


## Overview of SPL05 Profile

The SPL05 profile provides a flexible, secure configuration of the STSAFE-A120 device, suitable for a wide range of applications. Key features include:

- **Preprovisioned NIST P-256 private key (Slot 0)** associated with a unique X.509 leaf certificate stored in User NVM Slot 0. This certificate is compatible with Amazon JIT and Microsoft Azure and attested by the ST root CA.
- **Four additional private key slots (Slots 1-4)** available for asymmetric cryptography use cases.
- **Four provisionable public key slots** for external entity authentication.
- **Sixteen provisionable symmetric key slots** for symmetric cryptography.
- **Provisionable host key slot** for secure host-device communication.
- **One-time programmable command access condition table** for secure command access control.
- **16 Kbytes of User NVM**, segmented into data and counter zones with configurable access conditions.


## Mandatory Steps to Start Using the Device

### Step 1: Understand the Public Key Infrastructure (PKI)

- The device’s leaf certificate (in User NVM Slot 0) is signed by the STMicroelectronics root CA (STM STSAFE-A PROD CA 01), which uses NIST P-256 curve and ECDSA with SHA-256.
- The root CA certificate is publicly available and should be used to verify the device leaf certificate.
- For production, it is recommended to replace the generic leaf certificate with a custom certificate signed by your own CA.

### Step 2: Verify Preprovisioned Keys and Certificates

- Slot 0 contains the preprovisioned NIST P-256 private key.
- User NVM Slot 0 contains the corresponding leaf certificate.
- Slots 1 to 4 are empty and ready for customer provisioning.
- Public key slots are empty and must be provisioned as needed.

### Step 3: Configure Host Secure Channel

- Provision the host key slot to enable secure communication.
- Configure provisioning control fields to allow or restrict reprovisioning, plaintext or wrapped key provisioning.
- Use the host secure channel commands (`Generate ECDHE Key`, `Start Volatile KEK Session`, `Write Host Key V2 Wrapped`, etc.) to establish secure communication.

### Step 4: Provision Additional Keys

- Use `Generate Key` command to create keys in slots 1 to 4 for asymmetric operations.
- Provision symmetric keys in the 16 symmetric key slots using plaintext, wrapped, or derived methods.
- Provision public keys in the generic public key table for entity authentication or host key verification.

### Step 5: Configure Command Access Conditions

- Use the one-time programmable command access condition table to restrict access to device commands.
- Set access conditions based on your security requirements to protect sensitive operations.

### Step 6: Utilize User NVM Zones

- User NVM zones are configured with read and update access conditions.
- Zone 0 contains the leaf certificate and is non-erasable.
- Other zones can be used to store certificates, data, or counters as needed.
- Use `Read`, `Update`, and `Decrement` commands to access and modify User NVM data respecting access conditions.

### Step 7: Implement Cryptographic Operations

- Use the preprovisioned and provisioned keys to perform cryptographic operations:
  - Signature generation and verification.
  - Key establishment (ECDH).
  - Symmetric encryption/decryption and MAC generation/verification.
  - Random number generation.
  - Key wrapping and unwrapping.

---

© 2025 STMicroelectronics – All rights reserved
