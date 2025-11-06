# STSAFE-A120 Host Key Provisioning (Wrapped) {#STSAFE-A120_Host_key_provisioning_wrapped}

This document provides a comprehensive overview of the host key provisioning process using wrapped keys for the STSAFE-A120 secure element. The example demonstrates the step-by-step procedure to securely provision host MAC and cipher keys into the target STSAFE-A120 device, leveraging its advanced security features to ensure confidentiality and integrity.

Host key provisioning is a critical operation that enables secure communication between the host system and the STSAFE-A120 device. By using wrapped keys, sensitive cryptographic material is protected during transfer and storage, reducing the risk of exposure or unauthorized access. This example guides users through the initialization, configuration, and provisioning stages, highlighting important security considerations and operational constraints.

## Example Flowchart

The following flowchart illustrates the main steps involved in the host key provisioning process:

@startuml{STSAFE-A120_Host_key_provisioning_wrapped.png} "STSAFE-A120_Host_key_provisioning_wrapped Example flowchart" width=5cm
	:MAIN;
	:Initialize application terminal;
	:Initialize STSAFE-A120 device (address 0x20);
	:Display Host MAC and Host Cipher keys;
	:Query host key provisioning control fields;
	if(ret != STSE_OK) then (No)
		:Display ERROR;
		-[hidden]->
		detach
	else (Yes)
		:Display host key provisioning control fields;
		:Display WARNING regarding slot lock;
		if(provisioning_ctrl_fields.change_right == 0) then (No)
			:Update host key provisioning control fields;
			if(ret != STSE_OK) then (No)
				:Display ERROR;
				-[hidden]->
				detach
			else (Yes)
				:Proceed;
			endif
		else (Yes)
			if(provisioning_ctrl_fields.reprovision == 0) then (No)
				:Display "Control fields already set";
			else (Yes)
				:Display ERROR;
				-[hidden]->
				detach
			endif
		endif
	endif
	:Provision host keys using wrapped method;
	if(ret != STSE_OK) then (No)
		:Display ERROR;
		-[hidden]->
		detach
	else (Yes)
		:Display "Host key provisioning wrapped: PASS";
	endif
	while (while(1))
	end while
	-[hidden]->
	detach
@enduml

## STSELib APIs and Services Utilized

The following APIs and services are employed in this example:

- `stse_init`: Initializes the STSAFE-A120 device and communication interface.
- `stse_host_key_provisioning_wrapped`: Executes the host key provisioning using wrapped keys.
- `stsafea_query_host_key_provisioning_ctrl_fields`: Retrieves the current provisioning control fields for the host key slot.
- `stsafea_put_host_key_provisioning_ctrl_fields`: Updates the provisioning control fields to enable or restrict key provisioning.

## Example Execution and Terminal Output

Upon running the example, the host computer terminal displays detailed logs that reflect each stage of the provisioning process. These logs provide transparency and traceability, allowing users to verify successful execution and identify any issues:

```
 ----------------------------------------------------------------------------------------------------------------
 -                                  STSAFE-A120 Host key provisioning wrapped example                                   -
 ----------------------------------------------------------------------------------------------------------------
 -
 - Description:
 - This example illustrates the process of securely provisioning host keys to a target STSAFE-A120 device using wrapped keys.
 -
 ----------------------------------------------------------------------------------------------------------------

 - Initializing target STSAFE-A120...

 - Host MAC key to be written:

  0x00 0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88 0x99 0xAA 0xBB 0xCC 0xDD 0xEE 0xFF

 - Host cipher key to be written:

  0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF 0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF

 - Host key slot provisioning control fields:

 --------------+--------------+-----------+-------------------+----------------------------
  Change right | Re-provision | Plaintext | Wrapped anonymous | Wrapped authentication key
 --------------+--------------+-----------+-------------------+----------------------------
	  YES      |     NO       |    YES    |        NO         |            0xFF
 --------------+--------------+-----------+-------------------+----------------------------

 +--------------------------------------------------------------------------------------------------------------+
 |                                                                                                              |
 |                                           /!\ W A R N I N G /!\                                              |
 |                                                                                                              |
 | The program will write test keys into the target STSAFE-A120 and enable re-provisioning.                     |
 | Please note the following constraints:                                                                       |
 |    - The host keys slot will remain open for re-provisioning indefinitely, which is not recommended for production use. |
 |    - The target STSAFE-A120 will no longer support `stse_host_key_provisioning_wrapped_authenticated`.       |
 |                                                                                                              |
 | Press any key to continue and write the host keys:                                                           |
 |                                                                                                              |
 +--------------------------------------------------------------------------------------------------------------+

 - Opening host key slot for re-provisioning...

 - Host key provisioning wrapped: PASS

```

## Applicative Scenario

This example covers two key scenarios:

- **Restricting Host Key Slot Provisioning:** Demonstrates how to configure the control fields to limit further provisioning operations, enhancing security by preventing unauthorized key updates.
- **Host Key Provisioning (Wrapped):** Shows the secure process of provisioning host keys using wrapped methods, ensuring that sensitive key material is never exposed in plaintext during transfer or storage.

## Security Considerations

- **Key Confidentiality:** Wrapped provisioning ensures that host keys are encrypted during transfer, minimizing the risk of interception or leakage.
- **Slot Locking:** After provisioning, the host key slot can be locked to prevent further changes, which is essential for maintaining device integrity in production environments.
- **Operational Constraints:** Enabling indefinite re-provisioning is suitable for development and testing but should be avoided in production deployments to prevent potential security vulnerabilities.

By following this example, users can gain a deeper understanding of secure host key provisioning practices with the STSAFE-A120 and adapt the process to meet their specific security requirements.