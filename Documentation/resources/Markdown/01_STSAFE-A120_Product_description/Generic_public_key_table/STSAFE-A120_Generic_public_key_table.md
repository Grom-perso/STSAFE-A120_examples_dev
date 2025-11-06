# Generic Public Key Table {#Generic_Public_Key_Table}

The **Generic Public Key Table** in the STSAFE-A120 device is used to securely store public keys that are essential for verifying digital signatures and authenticating off-chip entities. These public keys enable the device to perform critical security functions such as host key verification, entity authentication, and signature validation within secure communication protocols.

## Number of Slots

- The generic public key table contains **3 slots**.
- Each slot can hold one public key along with associated configuration flags.
- Slots can only be written once; a slot that already contains a key cannot be overwritten.

## Key Slot Attributes

Each generic public key slot includes the following attributes:

| Attribute              | Description                                                                                   |
|------------------------|-----------------------------------------------------------------------------------------------|
| **Presence Flag**      | Indicates whether the slot currently holds a valid public key (true/false).                   |
| **Curve ID**           | Identifies the elliptic curve domain parameters associated with the public key.               |
| **Public Key Value**   | The public key data, encoded according to the specified curve.                               |
| **Configuration Flags**| Flags defining the allowed uses of the public key within the device’s security operations.    |


## Configuration Flags and Usage

The configuration flags control the roles and permissions of each public key slot:

| Flag Name               | Description                                                                                   |
|-------------------------|-----------------------------------------------------------------------------------------------|
| **Establish Host Key V2** | Allows the public key to be used for authenticating host keys during the Establish Host Key V2 command. |
| **Entity Authentication** | Enables the public key to verify signatures for off-chip entity authentication.               |
| **Start Volatile KEK Session** | Permits the public key to verify signatures in the Start Volatile KEK Session command.     |
| **Establish Symmetric Keys** | Allows the public key to verify signatures in the Establish Symmetric Keys command.          |
| **Change Right**         | Indicates whether the configuration flags can be updated (one-time update allowed).           |


## Applicative Usage of Generic Public Key Slots

- Public keys stored in these slots are primarily used to:
  - Verify signatures on host key provisioning commands.
  - Authenticate off-chip entities by verifying their signatures over challenges.
  - Validate signatures during key establishment and volatile KEK session commands.
- The device enforces strict access control and signature verification using these keys to ensure only authorized entities can perform sensitive operations.
- Configuration flags must be set appropriately during provisioning to enable the intended usage scenarios.
- Once a public key is written to a slot, it cannot be overwritten, ensuring integrity and preventing unauthorized key replacement.


## Provisioning and Security Considerations

- Public keys can be pre-provision by STMicroelectronics or provisioned using the **Write Public Key** command.
Provisioning should ideally occur in a trusted environment to guarantee the authenticity of the public keys.
The device rejects attempts to write a public key to a non-empty slot.
Signature verification using these public keys is a fundamental part of the device’s secure channel and key provisioning protocols.
The **Change Right** flag allows a one-time update of configuration flags to lock the key’s usage permissions permanently.

---

© 2025 STMicroelectronics – All rights reserved