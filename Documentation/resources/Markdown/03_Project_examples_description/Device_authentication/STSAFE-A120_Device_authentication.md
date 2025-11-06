# STSAFE-A120 Device Authentication {#STSAFE-A120_Device_authentication}

The STSAFE-A120 is a secure element designed to provide robust cryptographic functions, including device authentication, certificate management, and secure storage. In this example, the authentication process leverages several key APIs from the STSecureElement library to interact with the device, retrieve its certificate, and verify its authenticity against a trusted Certificate Authority (CA).

## Example Flowchart

The following flowchart illustrates the step-by-step process implemented in the example application:

@startuml{STSAFE-A120_Device_authentication.png} "STSAFE-A120_Device_authentication Example flowchart" width=5cm
    :MAIN;
    :Initialize application terminal (baudrate = 115200);
    :Display example title and user instructions;
    :ret = <b>stse_init</b>;
    if(ret != STSE_OK) then (Initialization Failed)
        :Display ERROR message;
        detach
    endif

    :ret = <b>stse_get_device_certificate_size</b>;
    if(ret != STSE_OK) then (Certificate Size Retrieval Failed)
        :Display ERROR message;
        detach
    endif

    :ret = <b>stse_get_device_certificate</b>;
    if(ret != STSE_OK) then (Certificate Retrieval Failed)
        :Display ERROR message;
        detach
    endif

    :Display retrieved <b>Device Certificate</b>;
    
    :ret = <b>stse_device_authenticate</b>;
    if(ret != STSE_OK) then (Authentication Failed)
        :Display ERROR message;
        detach
    endif

    while (true)
        :Maintain application loop for continuous operation;
    end while
    detach
@enduml

## STSELib API Functions Utilized

The example leverages the following STSecureElement library APIs:

- **stse_get_device_certificate_size**: Determines the size of the device certificate stored in the secure element.
- **stse_get_device_certificate**: Retrieves the actual device certificate, which is typically an X.509 certificate containing the device’s public key and identity information.
- **stse_device_authenticate**: Performs cryptographic authentication of the device by verifying its certificate against the trusted CA certificate.

## Example Output

When the application is executed, the following output is displayed on the host computer’s terminal window. This output includes the device certificate in hexadecimal format and the result of the authentication process.

```
----------------------------------------------------------------------------------------------------------------
                              STSAFE-A120 Device Authentication Example
----------------------------------------------------------------------------------------------------------------
This example demonstrates how to authenticate an STSAFE-A120 SPL02/SPL03 device over ST root CA certificate

- Note :
         An update of the ST root CA certificate (CA_SELF_SIGNED_CERTIFICATE_01) is required
         to adapt this example to a custom STSAFE-A120 personalization .
----------------------------------------------------------------------------------------------------------------

 ## STSAFE-A120 Device zone 0 certificate :

  0x30 0x82 0x01 0x99 0x30 0x82 0x01 0x3F 0xA0 0x03 0x02 0x01 0x02 0x02 0x0B 0x02
  0x09 0xB0 0x84 0x61 0x59 0xE4 0x39 0x52 0x01 0x39 0x30 0x0A 0x06 0x08 0x2A 0x86
  0x48 0xCE 0x3D 0x04 0x03 0x02 0x30 0x4F 0x31 0x0B 0x30 0x09 0x06 0x03 0x55 0x04
  0x06 0x13 0x02 0x4E 0x4C 0x31 0x1E 0x30 0x1C 0x06 0x03 0x55 0x04 0x0A 0x0C 0x15
  0x53 0x54 0x4D 0x69 0x63 0x72 0x6F 0x65 0x6C 0x65 0x63 0x74 0x72 0x6F 0x6E 0x69
  0x63 0x73 0x20 0x6E 0x76 0x31 0x20 0x30 0x1E 0x06 0x03 0x55 0x04 0x03 0x0C 0x17
  0x53 0x54 0x4D 0x20 0x53 0x54 0x53 0x41 0x46 0x45 0x2D 0x41 0x20 0x50 0x52 0x4F
  0x44 0x20 0x43 0x41 0x20 0x30 0x31 0x30 0x20 0x17 0x0D 0x32 0x31 0x30 0x33 0x30
  0x35 0x30 0x30 0x30 0x30 0x30 0x30 0x5A 0x18 0x0F 0x32 0x30 0x35 0x31 0x30 0x33
  0x30 0x35 0x30 0x30 0x30 0x30 0x30 0x30 0x5A 0x30 0x51 0x31 0x0B

 ## Device authentication over ST SPL03 CA certificate : Successful

```

## Practical Scenario

Device authentication using the STSAFE-A120 is commonly employed in scenarios where accessories or consumables must be verified before use. For example, in medical devices, printers, or industrial equipment, only authorized components should be accepted to ensure safety, reliability, and compliance with warranty or regulatory requirements.

By following this example, developers can integrate secure authentication mechanisms into their products, leveraging the STSAFE-A120’s hardware-based security features to protect against unauthorized or counterfeit devices.

For further details on the STSAFE-A120 and the STSecureElement library, refer to the official documentation and API reference guides.

## Important Notes :

- **Customization**: If your application uses a custom STSAFE-A120 personalization, ensure that the root CA certificate (`CA_SELF_SIGNED_CERTIFICATE_01`) is updated accordingly.
