# STSAFE-A120 ECDH {#STSAFE-A120_ecdh}

This example demonstrates the Elliptic Curve Diffie-Hellman (ECDH) key agreement protocol using the STSAFE-A120 secure element.  
ECDH is a widely used cryptographic technique that enables two parties to establish a shared secret over an insecure channel.  
The STSAFE-A120 device performs the ECDH operation securely, ensuring that private keys never leave the secure element.

## Example Overview

The ECDH example application illustrates how to:
- Generate an ephemeral key pair on the host or the STSAFE-A120.
- Exchange public keys between the host and the secure element.
- Compute a shared secret using the ECDH protocol.
- Use the shared secret for further cryptographic operations (e.g., symmetric encryption).

## Example Flowchart

The following flowchart outlines the main steps performed by the ECDH example application:

@startuml "ECDH Example flowchart" width=5cm
:MAIN;
:Initialize application terminal (baudrate = 115200);
:Display example title and user instructions;
:ret = <b>stse_init</b>;
if(ret == STSE_OK) then (No)
	:Display error message;
	note right: Infinite loop
	-[hidden]->
detach
else (Yes)
	:Generate ephemeral key pair (host or STSAFE-A120);
	:Exchange public keys;
	:ret = <b>stse_ecdh_compute_shared_secret</b>;
	if(ret == STSE_OK) then (Yes)
		:Display the computed shared secret;
		stop
	else (No)
		:Display error message;
		note right: Infinite loop
		-[hidden]->
		detach
	endif
endif
@enduml

## Host Terminal Output

Upon execution, the host terminal displays logs reflecting the ECDH key agreement process, including key generation, public key exchange, and the resulting shared secret.  

Example output:

```
----------------------------------------------------------------------------------------------------------------
-                                       STSAFE-A ECDH example                                                  -
----------------------------------------------------------------------------------------------------------------
- This example illustrates STSAFE-A120 ECDH process.                                                           -
----------------------------------------------------------------------------------------------------------------
 - Initialize target STSAFE-A120

         - Shared secret:
  0x83 0x64 0xE6 0x4A 0x02 0xE9 0x54 0x64 0xBE 0x3D 0x82 0x7B 0x5A 0x0E 0x5A 0x2B
  0xB6 0x34 0xB4 0xCC 0xB6 0x26 0x16 0xF4 0x4D 0xED 0xF5 0xF4 0xAF 0x47 0x55 0x83
```

## Applicative Scenarios

The ECDH example is relevant for several secure communication scenarios:

- **Session Key Establishment:** Securely derive a symmetric session key for encrypted communication between a host and a device.
- **Mutual Authentication:** Combine ECDH with digital signatures to mutually authenticate both parties before establishing a secure channel.
- **IoT Device Pairing:** Use ECDH to securely pair IoT devices in the field, ensuring confidentiality and integrity of exchanged data.
- **Key Exchange in Embedded Systems:** Demonstrates best practices for offloading sensitive cryptographic operations to a secure element, reducing attack surface.

This example is essential for developers and system integrators who need to implement secure key exchange and session establishment using the STSAFE-A120 in embedded applications.
