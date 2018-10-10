;********************************************************************************************************
;                                               uC/OS-II
;                                         The Real-Time Kernel
;
;                               (c) Copyright 1992-2006, Micrium, Weston, FL
;                                          All Rights Reserved
;
;                                           Generic ARM Port
;
; File          : OS_CPU_A.S
; Version       : V1.70
; By            : Jean J. Labrosse
;
; For           : ARM7 or ARM9
; Mode          : ARM or Thumb
; Modified by   : shen cheng
; Modified date : 2006-7-4
;********************************************************************************************************
;		INCLUDE wm_config.inc
			PRESERVE8	  		
		 AREA  UCOS_ARM, CODE, READONLY
;	IF :DEF: __TLS_OS_UCOS
            IMPORT  OSRunning                    ; External references
            IMPORT  OSPrioCur
            IMPORT  OSPrioHighRdy
            IMPORT  OSTCBCur
            IMPORT  OSTCBHighRdy
            IMPORT  OSIntNesting
            IMPORT  OSIntExit
            IMPORT  OSTaskSwHook


            EXPORT  OSCPUSaveSR               ; Functions declared in this file
            EXPORT  OSCPURestoreSR
            EXPORT  OSStartHighRdy
            EXPORT  OSCtxSw
            EXPORT  OSIntCtxSw
			EXPORT  PendSV_Handler
			EXPORT  OS_CPU_PendSVHandler_nosave
			EXPORT portGET_IPSR

NVIC_INT_CTRL     EQU     0xE000ED04   ;中断控制及状态寄存器 ICSR 的地址
NVIC_SYSPRI14     EQU     0xE000ED22   ;PendSV Priority Reg Addr
NVIC_PENDSV_PRI   EQU     0xFF         ;PendSV Interrupt Priority 255(lowest)
NVIC_PENDSVSET    EQU      0x10000000   ;位 28 为 1  

portGET_IPSR PROC
	PRESERVE8
	mrs r0, ipsr
	bx r14
	ENDP


OSCPUSaveSR PROC
        MRS     R0,PRIMASK                     ; Set IRQ and FIQ bits in CPSR to disable all interrupts
		CPSID	I
        BX      LR                          ; Disabled, return the original CPSR contents in R0
		ENDP

OSCPURestoreSR PROC
        MSR     PRIMASK,R0
        BX      LR
		ENDP

;*********************************************************************************************************
;                                          START MULTITASKING
;                                       void OSStartHighRdy(void)
;
; Note(s) : 1) OSStartHighRdy() MUST:
;              a) Call OSTaskSwHook() then,
;              b) Set OSRunning to TRUE,
;              c) Switch to the highest priority task.
;*********************************************************************************************************

OSStartHighRdy PROC

		LDR 	R0, =NVIC_SYSPRI14									; Set the PendSV exception priority  
		LDR 	R1, =NVIC_PENDSV_PRI  
		STRB	R1, [R0]  
		  
		MOVS	R0, #0												; Set the PSP to 0 for initial context switch call	
		MSR 	PSP, R0  
		  
		LDR 	R0, =OSRunning										; OSRunning = TRUE	
		MOVS	R1, #1	
		STRB	R1, [R0]  

		LDR 	R0, =NVIC_INT_CTRL									; Trigger the PendSV exception (causes context switch)	
		LDR 	R1, =NVIC_PENDSVSET  
		STR 	R1, [R0]  
		CPSIE	I
OSStartHand   ;Forever Loop, Do not go here
		B   OSStartHand
		ENDP

OSCtxSw PROC
	LDR     R0, =NVIC_INT_CTRL                                  ; Set the PendSV exception priority  
	LDR     R1, =NVIC_PENDSVSET  
	STR     R1, [R0] 
	BX	    LR
	ENDP
	
OSIntCtxSw PROC
	LDR     R0, =NVIC_INT_CTRL                                  ; Set the PendSV exception priority  
	LDR     R1, =NVIC_PENDSVSET  
	STR     R1, [R0] 
	BX	    LR
	ENDP
	
PendSV_Handler PROC
	CPSID   I
	MRS     R0,PSP
	CBZ     R0,OS_CPU_PendSVHandler_nosave

	SUBS    R0,R0,#0x20
	STM     R0,{R4-R11}

	LDR     R1,=OSTCBCur
	LDR     R1,[R1]
	STR     R0,[R1]
	
OS_CPU_PendSVHandler_nosave
		;call OSTaskSwHook()
		PUSH {R14} ;save R14
		LDR R0, =OSTaskSwHook                ;R0 = &OSTaskSwHook 
		BLX R0                               ;call OSTaskSwHook() 
		POP {R14}                            ;restore R14

		;OSPrioCur = OSPrioHighRdy; 
		LDR R0, =OSPrioCur                   ;R0 = &OSPrioCur 
		LDR R1, =OSPrioHighRdy               ;R1 = &OSPrioHighRdy 
		LDRB R2, [R1]                        ;R2 = *R1 (R2 = OSPrioHighRdy) 
		STRB R2, [R0]                        ;*R0 = R2 (OSPrioCur = OSPrioHighRdy)
		                                     ;OSTCBCur = OSTCBHighRdy; 
		LDR R0, =OSTCBCur                    ;R0 = &OSTCBCur 
		LDR R1, =OSTCBHighRdy                ;R1 = &OSTCBHighRdy 
		LDR R2, [R1]                         ;R2 = *R1 (R2 = OSTCBHighRdy) 
		STR R2, [R0]                         ;*R0 = R2 (OSTCBCur = OSTCBHighRdy)

		LDR R0, [R2]                         ;R0 = *R2 (R0 = OSTCBHighRdy), R0 is new task SP
		                                     ;SP = OSTCBHighRdy->OSTCBStkPtr #3
		LDM R0, {R4-R11}                     ;Restore R4-R11 from task SP
		ADDS R0, R0, #0x20                   ;R0 += 0x20
		MSR PSP, R0                          ;PSP = R0，use new task SP load PSP
		ORR LR, LR, #0x04                    ;Confirm LR bit2 sets 1，use process SP #4 when return
		CPSIE I                              ;enable Interrupt
		BX LR                                ;iret
		ENDP
;	ENDIF
	ALIGN
		END
