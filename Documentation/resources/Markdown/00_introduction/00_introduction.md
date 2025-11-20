# INTRODUCTION

The STSAFE-A120 example package offers developers a collection of applicative examples demonstrating the use of the STSAFE-A120 secure element product line from STMicroelectronics.

These examples can serve as software reference implementations for integrating STSAFE-A devices on host microcontroller platforms. 

## Software package content 

The software package includes a set of drivers, middleware, and examples for STM32L452RE microcontroller.

![Software Package Architecture](./Software_package_architecture.png)

- **Application Layer**

  This layer contains a set of STM32 Cube IDE project use case examples that illustrate the use of STSAFE-A Secure Elements on the different hardware development platforms provided by STMicroelectronics.

- **Middleware Layer**

  - **[STM32 Cryptographic Library (CMOX)](../../../Middleware/STM32_Cryptographic/Release_Notes.html)**

    The STM32 cryptographic library (CMOX) includes all the major security algorithms for encryption, hashing, message authentication, and digital signing.  
    Detailed [documentation](./../../../Middleware/STM32_Cryptographic/Release_Notes.html) on the STM32 Cryptographic Middleware version included in this software package is available in /Middleware/STM32_Cryptographic. 

  - **STSecureElement Library (STSELib)**

    Middleware providing a complete set of high-level APIs and core services to interface with the STMicroelectronics Secure Element device family.  
    Detailed [documentation](./../../../Middleware/STSELib/doc/documentation.html) on the STELib version included in this software package is available in /Middleware/STSELib/doc. 

- **Platforms**

  Optimized integrated peripheral drivers for STM32 MCUs, which can be used as a reference for porting the framework to other platforms.

  ## Using the example software package
  
  Following prerequisites are required to make use of the example package 
  
  - <b>Hardware prerequisites</b> 
    - STM32L452 NUCLEO board
    - X-NUCLEO-STSAFEA1 expansion board 
    - 1x micro USB cable 
  
  - <b>Software  prerequisites</b> 
    - STM32CubeIDE
    - STSE Software package
    - Serial terminal PC software  (i.e. Teraterm)
  
  ### Hardware Setup 
  
  - **STEP 1 :** Connect the STSAFE-A120 Nucleo expansion board on the top of the Host STM32 Nucleo board as shown in picture below:
  
  ![](./X-NUCLEO-SAFEA1_eval_kit.png)
  
> **Note:**  
> Jumper P7 (RST control) must be left open to communicate with the target STSAFE-A120.
  
  - **STEP 2 :** Connect the board to the development computer and Open and configure a terminal software as follow (i.e. Teraterm):
  
    ![](./teraterm_config.png)
  
> **Note:**   
> The COM port can differ from board to board. Please refer to windows "device manager" panel.
  
  ### Software Setup
  
  - **STEP 1 :** Open one of the projects provided within the STSAFE-Axxx software package by double clicking on its **.project** file as shown in picture below:
  
  ![](./project_cproj.png)
  
  - **STEP 2 :** When loaded, the STM32 Cube IDE will display the project as follow:
  
  ![](./STSAFE_Project_IDE.png)
  
  - **STEP 3 :** Build the project by clicking the **Build the active configurations of selected projects button** and verify that no error is reported by the GCC compiler/Linker. 
  
  ![](./STSAFE_project_build.png)
  
  - **STEP 4 :** Launch a debug session then wait the debugger to stop on the first main routine instruction and press Start button to execute the main routine. 
  
  ![](./STSAFE_project_debug.png)
  
  - **Result :**  
  
  Each project example reports execution log through the on-board STLINK CDC bridge.  
  These logs can be analyzed on development computer using a serial terminal application (i.e.: Teraterm) as example below:
  
  ![](./Project_teraterm_output.png)
  
  
## Known issues
  
Please find below a list of known issue with this package.
  
### 1 - Linker options STM32 CubeIDE / GCC toolchain  

When compiling with a CubeIDE version below 1.16 the following issue on linker flags prevent the project to compile  

![](./ld_issues.png)

it is possible to workaround the issue by removing the flags from project toolchain Linker settings. see screenshot below :

![](./ld_workaround.png)

  ---

© 2025 STMicroelectronics – All rights reserved
