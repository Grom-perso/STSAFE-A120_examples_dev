# STSAFE-A120 examples package 

The **STSAFE-A120 example package** offers developers a collection of applicative examples demonstrating the use of the STSAFE-A120 secure element product line from STMicroelectronics. These examples can serve as software reference implementations for integrating STSAFE-A120 devices on host microcontroller platforms. 

![STSAFE-A120 Examples package](Documentation/resources/Markdown/00_introduction/Software_package_architecture.png)

Following HW/SW prerequisites are required to work with the package

- Hardware Prerequisites
  - [NUCLEO-L4523](https://www.st.com/en/evaluation-tools/nucleo-l452re.html) STM32 development board
  - [X-NUCLEO-ESE01A1](https://www.st.com/en/evaluation-tools/x-nucleo-ese01a1.html#overview) Nucleo expansion board

- SW prerequisites 
  - One of the following compatible toolchain/IDE 
    - [STM32CubeIDE](https://www.st.com/en/development-tools/stm32cubeide.html)
    - [Keil uVision 5.37](https://www.st.com/en/partner-products-and-services/arm-keil-mdk.html)
    - [IAR ewarm 9.40.1](https://www.st.com/en/partner-products-and-services/iar-embedded-workbench-for-arm.html)
  - [X-CUBE-CRYPTOLIB 4.5.0](https://www.st.com/en/embedded-software/x-cube-cryptolib.html)
  - [Doxygen v1.14.0](https://github.com/doxygen/doxygen/releases/tag/Release_1_14_0) 

Please refer to package documentation to get information on how to get started with the package.

## Building the Documentation 

HTML documentation can either be downloaded as standalone package from the STSELib github repository [release section]()
or compiled from the library sources by executing following commands from the STSELib root directory:

```bash
    cd documentation/resources
    doxygen STSAFE-A120_Examples.doxyfile
    cd ../../Middleware/STSELib/doc/resources/
    doxygen STSELib.doxyfile
```

> [!NOTE]
>
> Doxygen version 1.14.0 is required to build the documentation  


## Installing the STM32 Cryptolibrary 

Due to **STM32 Cryptographic library** license agreement enforcement (required for distributing SW module under SLA088) . 
This package does not include the library objects and headers .

Please follow the instructions from ["Middleware/STM32_Cryptographic/ReadMe.md"](Middleware/STM32_Cryptographic/ReadMe.md) to install the library into the package

> **IMPORTANT**: The examples provided in this package are not functional if the **STM32 Cryptographic library** is not installed



