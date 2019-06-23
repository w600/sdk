;********************************************************************************
;* @file      port_iar.s
;* @version   V1.00
;* @date      1/16/2019
;* @brief     CMSIS Cortex-M3 Core Device Startup File for the W60X
;*
;* @note      Copyright (C) 2019 WinnerMicro Inc. All rights reserved.
;*
;* <h2><center>&copy; COPYRIGHT 2019 WinnerMicro</center></h2>
;*
;********************************************************************************

    PUBLIC vPortStartFirstTask
    RSEG NEAR_CODE:CODE:NOROOT(2)
vPortStartFirstTask:

        ldr r0, =0xE000ED08
        ldr r0, [r0]
        ldr r0, [r0]
        msr msp, r0
        cpsie i
        svc 0
        nop
        END