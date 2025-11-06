# STSAFE-A120 Host Key Provisioning {#STSAFE-A120_Host_key_provisioning}

 Host key provisioning is a critical step in establishing secure communication channel between a host system and the STSAFE-A120 device.
The example described here demonstrates the end-to-end procedure for provisioning host keys to a target STSAFE-A120 device. This includes initializing the necessary hardware and software components, querying and configuring key provisioning control fields, and securely writing both MAC and cipher keys to the device. The process also highlights important security considerations and constraints associated with key provisioning, especially in the context of production environments.

## Example Flowchart

The following flowchart illustrates the main steps involved in the host key provisioning process:

@startuml{STSAFE-A120_Host_key_provisioning.png} "STSAFE-A120_Host_key_provisioning Example flowchart" width=5cm
	:MAIN;
	:Initialize apps terminal]
	:Initialize STSE device (addr 0x20)]
	:print Host MAC and Host Cipher keys]
	:ret = stsafea_query_host_key_provisioning_ctrl_fields|
	if(ret != STSE_OK) then (No)
	else (Yes)
		:print ERROR]
		-[hidden]-> detach
	endif
	:print Host key provisioning control fields]
	:print WARNING about the lock of target slot]
	if(provisioning_ctrl_fields.change_right == 0) then (No)
		:stsafea_put_host_key_provisioning_ctrl_fields|
		if(ret != STSE_OK) then (No)
		else (Yes)
			:print ERROR]
			-[hidden]-> detach
		endif
	else (Yes)
		if(provisioning_ctrl_fields.reprovision == 0) then (No)
			:print "control fields already set"]
		else (Yes)
			:print ERROR]
			-[hidden]-> detach
		endif
	endif
	:ret = stse_host_key_provisioning|
	if(ret != STSE_OK) then (No)
	else (Yes)
		:print ERROR]
		-[hidden]-> detach
	endif
	:print "stse_host_key_provisioning : PASS"]
	while (while(1))
	end while
	-[hidden]-> detach
@enduml

## APIs and Services Utilized

The following APIs and services are integral to the host key provisioning workflow:

- `stse_init`: Initializes the STSAFE-A120 device and prepares it for communication.
- `stse_host_key_provisioning`: Executes the host key provisioning operation, writing the MAC and cipher keys to the device.
- `stsafea_query_host_key_provisioning_ctrl_fields`: Retrieves the current control fields associated with host key provisioning, allowing the application to determine the device's provisioning status and rights.
- `stsafea_put_host_key_provisioning_ctrl_fields`: Updates the control fields to configure provisioning rights and options as required.

## Example Output

Upon successful execution, the following log output can be observed on the host computer terminal. This output details each step of the provisioning process, including key values, control field settings, and important warnings:

```
 ----------------------------------------------------------------------------------------------------------------
 -                                  STSAFE-A120 Host key provisioning example                                   -
 ----------------------------------------------------------------------------------------------------------------
 -
 - description :
 - This examples illustrates host keys provisioning of a target STSAFE-A120 device
 -
 ----------------------------------------------------------------------------------------------------------------

 - Initialize target STSAFE-A120

 - Host mac key to write :

  0x00 0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88 0x99 0xAA 0xBB 0xCC 0xDD 0xEE 0xFF

 - Host cipher key to write :

  0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF 0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF

 - Host key slot provisioning control fields :

 --------------+--------------+-----------+-------------------+----------------------------
  Change right | Re-provision | Plaintext | Wrapped anonymous | Wrapped authentication key
 --------------+--------------+-----------+-------------------+----------------------------
	  YES      |     NO       |    YES    |        NO         |            0xFF
 --------------+--------------+-----------+-------------------+----------------------------

 +--------------------------------------------------------------------------------------------------------------+
 |                                                                                                              |
 |                                           /!\ W A R N I N G /!\                                              |
 |                                                                                                              |
 | The program will write test keys in the target STSAFE-A120 and enable re-provisioning                        |
 | It will add two following constraints:                                                                       |
 |    - The host keys slot will be opened to re-provisioning forever and this id not be suitable for production |
 |    - The target STSAFE-A120 will no longer support stse_host_key_provisioning_wrapped_authenticated          |
 |                                                                                                              |
 | Press any key to continue and write the host keys :                                                          |
 |                                                                                                              |
 +--------------------------------------------------------------------------------------------------------------+

 - Open host key slot to re-provisioning

 - stse_host_key_provisioning : PASS

```

## Security Considerations

> **IMPORTANT:** The example provided is intended for demonstration and testing purposes only. The configuration used here enables perpetual re-provisioning of the host key slot, which is **not recommended for production deployments**. In a secure production environment, key slots should be locked after provisioning to prevent unauthorized changes, and the use of wrapped authenticated keys should be enforced for enhanced security.

## Applicative Scenarios

This example covers the following scenarios:

- **Restricting Host Key Slot Provisioning:** Demonstrates how to configure the device to limit further changes to the host key slot after initial provisioning.
- **Plaintext Host Key Provisioning:** Shows the process of writing host keys in plaintext, which may be suitable for certain test environments but should be avoided in production.

For more advanced use cases, such as provisioning using wrapped keys or integrating with secure key management systems, refer to the STSAFE-A120 documentation and security guidelines.
