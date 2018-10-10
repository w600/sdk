@;********************************************************************************************************
@;                                               uC/OS-II
@;                                         The Real-Time Kernel
@;
@;                               (c) Copyright 1992-2006, Micrium, Weston, FL
@;                                          All Rights Reserved
@;
@;                                           Generic ARM Port
@;
@; File          : OS_CPU_A.S
@; Version       : V1.70
@; By            : Jean J. Labrosse
@;
@; For           : ARM7 or ARM9
@; Mode          : ARM or Thumb
@; Modified by   : shen cheng
@; Modified date : 2006-7-4
@;********************************************************************************************************
@			PRESERVE8	  		
@		 AREA  UCOS_ARM, CODE, READONLY
	.include "../../../Include/wm_config_gcc.inc"
.section .text  
.ifdef __TLS_OS_UCOS
	.extern  OSRunning                    @; External references
	.extern   OSPrioCur
	.extern   OSPrioHighRdy  
	.extern   OSTCBCur
	.extern   OSTCBHighRdy
	.extern   OSIntNesting
	.extern   OSIntExit
	.extern   OSTaskSwHook
	.extern   OS_CPU_IRQ_ISR_Handler
	@;.extern   OS_CPU_FIQ_ISR_Handler


	.global  OSCPUSaveSR               @; Functions declared in this file
	.global  OSCPURestoreSR
	.global  OSStartHighRdy
	.global  OSCtxSw
	.global  OSIntCtxSw
	.global  OS_CPU_IRQ_ISR
	.global  OS_CPU_Tick_ISR


	.equ NO_INT,0xC0                         @; Mask used to disable interrupts (Both FIR and IRQ)
	.equ NO_IRQ,0x80                         @; Mask used to disable interrupts (Both FIR and IRQ)
	.equ NO_FIQ,0x40                         @; Mask used to disable interrupts (Both FIR and IRQ)
	.equ SVC32_MODE,0x13
	.equ FIQ32_MODE,0x11
	.equ IRQ32_MODE,0x12

   
@;*********************************************************************************************************
@;                                   CRITICAL SECTION METHOD 3 FUNCTIONS
@;
@; Description: Disable/Enable interrupts by preserving the state of interrupts.  Generally speaking you
@;              would store the state of the interrupt disable flag in the local variable 'cpu_sr' and then
@;              disable interrupts.  'cpu_sr' is allocated in all of uC/OS-II's functions that need to
@;              disable interrupts.  You would restore the interrupt disable state by copying back 'cpu_sr'
@;              into the CPU's status register.
@;
@; Prototypes :     OS_CPU_SR  OS_CPU_SR_Save(void);
@;                  void       OS_CPU_SR_Restore(OS_CPU_SR cpu_sr);
@;
@;
@; Note(s)    : 1) These functions are used in general like this:
@;
@;                 void Task (void *p_arg)
@;                 {
@;                 #if OS_CRITICAL_METHOD == 3          /* Allocate storage for CPU status register */
@;                     OS_CPU_SR  cpu_sr;
@;                 #endif
@;
@;                          :
@;                          :
@;                     OS_ENTER_CRITICAL();             /* cpu_sr = OS_CPU_SaveSR();                */
@;                          :
@;                          :
@;                     OS_EXIT_CRITICAL();              /* OS_CPU_RestoreSR(cpu_sr);                */
@;                          :
@;                          :
@;                 }
@;
@;              2) OS_CPU_SaveSR() is implemented as recommended by Atmel's application note:
@;
@;                    "Disabling Interrupts at Processor Level"
@;*********************************************************************************************************
	

OSCPUSaveSR:
        MRS     R0,CPSR                     @; Set IRQ and FIQ bits in CPSR to disable all interrupts
        ORR     R1,R0,#NO_INT
        MSR     CPSR_c,R1
        MRS     R1,CPSR                     @; Confirm that CPSR contains the proper interrupt disable flags
        AND     R1,R1,#NO_INT
        CMP     R1,#NO_INT
        BNE     OSCPUSaveSR              	@; Not properly disabled (try again)
        BX      LR                          @; Disabled, return the original CPSR contents in R0


OSCPURestoreSR:
        MSR     CPSR_c,R0
        BX      LR


@;*********************************************************************************************************
@;                                          START MULTITASKING
@;                                       void OSStartHighRdy(void)
@;
@; Note(s) : 1) OSStartHighRdy() MUST:
@;              a) Call OSTaskSwHook() then,
@;              b) Set OSRunning to TRUE,
@;              c) Switch to the highest priority task.
@;*********************************************************************************************************

OSStartHighRdy:

        BL      OSTaskSwHook     @; OSTaskSwHook();


        MSR     CPSR_cxsf, #0xD3        @; Switch to SVC mode with IRQ and FIQ disabled

        LDR     R4, =OSRunning         @; OSRunning = TRUE
        MOV     R5, #1
        STRB    R5, [R4]

                                        @; SWITCH TO HIGHEST PRIORITY TASK
        LDR     R4, =OSTCBHighRdy      @;    Get highest priority task TCB address
        LDR     R4, [R4]               @ ;    get stack pointer
        LDR     SP, [R4]               @ ;    switch to the new stack

        LDR     R4,  [SP], #4          @ ;    pop new task's CPSR
        MSR     SPSR_cxsf,R4
        LDMFD   SP!, {R0-R12,LR,PC}^   @ ;    pop new task's context	


@;*********************************************************************************************************
@;                         PERFORM A CONTEXT SWITCH (From task level) - OSCtxSw()
@;
@; Note(s) : 1) OSCtxSw() is called in SYS mode with BOTH FIQ and IRQ interrupts DISABLED
@;
@;           2) The pseudo-code for OSCtxSw() is:
@;              a) Save the current task's context onto the current task's stack
@;              b) OSTCBCur->OSTCBStkPtr = SP;
@;              c) OSTaskSwHook();
@;              d) OSPrioCur             = OSPrioHighRdy;
@;              e) OSTCBCur              = OSTCBHighRdy;
@;              f) SP                    = OSTCBHighRdy->OSTCBStkPtr;
@;              g) Restore the new task's context from the new task's stack
@;              h) Return to new task's code
@;
@;           3) Upon entry:
@;              OSTCBCur      points to the OS_TCB of the task to suspend
@;              OSTCBHighRdy  points to the OS_TCB of the task to resume
@;*********************************************************************************************************

OSCtxSw:
                                        @; SAVE CURRENT TASK'S CONTEXT
        STMFD   SP!, {LR}               @;     Push return address
        STMFD   SP!, {LR}
        STMFD   SP!, {R0-R12}          @ ;     Push registers
        MRS     R4,  CPSR              @ ;     Push current CPSR
        TST     LR, #1                 @ ;     See if called from Thumb mode
        ORRNE   R4,  R4, #0x20         @ ;     If yes, Set the T-bit
        STMFD   SP!, {R4}

        LDR     R4, =OSTCBCur          @; OSTCBCur->OSTCBStkPtr = SP;
        LDR     R5, [R4]
        STR     SP, [R5]

        BL      OSTaskSwHook          @ ; OSTaskSwHook();


        LDR     R4, =OSPrioCur         @; OSPrioCur = OSPrioHighRdy
        LDR     R5, =OSPrioHighRdy
        LDRB    R6, [R5]
        STRB    R6, [R4]

        LDR     R4, =OSTCBCur          @; OSTCBCur  = OSTCBHighRdy;
        LDR     R6, =OSTCBHighRdy
        LDR     R6, [R6]
        STR     R6, [R4]

        LDR     SP, [R6]                @; SP = OSTCBHighRdy->OSTCBStkPtr;

                                       @ ; RESTORE NEW TASK'S CONTEXT
        LDMFD   SP!, {R4}               @;    Pop new task's CPSR
        MSR     SPSR_cxsf, R4

        LDMFD   SP!, {R0-R12,LR,PC}^    @;    Pop new task's context


@;*********************************************************************************************************
@;                   PERFORM A CONTEXT SWITCH (From interrupt level) - OSIntCtxSw()
@;
@; Note(s) : 1) OSIntCtxSw() is called in SYS mode with BOTH FIQ and IRQ interrupts DISABLED
@;
@;           2) The pseudo-code for OSCtxSw() is:
@;              a) OSTaskSwHook();
@;              b) OSPrioCur             = OSPrioHighRdy;
@;              c) OSTCBCur              = OSTCBHighRdy;
@;              d) SP                    = OSTCBHighRdy->OSTCBStkPtr;
@;              e) Restore the new task's context from the new task's stack
@;              f) Return to new task's code
@;
@;           3) Upon entry:
@;              OSTCBCur      points to the OS_TCB of the task to suspend
@;              OSTCBHighRdy  points to the OS_TCB of the task to resume
@;*********************************************************************************************************

OSIntCtxSw:
        BL      OSTaskSwHook           @; OSTaskSwHook();


        LDR     R4,=OSPrioCur          @; OSPrioCur = OSPrioHighRdy
        LDR     R5,=OSPrioHighRdy
        LDRB    R6,[R5]
        STRB    R6,[R4]

        LDR     R4,=OSTCBCur           @; OSTCBCur  = OSTCBHighRdy;
        LDR     R6,=OSTCBHighRdy
        LDR     R6,[R6]
        STR     R6,[R4]

        LDR     SP,[R6]                @ ; SP = OSTCBHighRdy->OSTCBStkPtr;

                                       @; RESTORE NEW TASK'S CONTEXT
        LDMFD   SP!, {R4}              @ ;    Pop new task's CPSR
        MSR     SPSR_cxsf, R4

        LDMFD   SP!, {R0-R12,LR,PC}^    @;    Pop new task's context

@;*********************************************************************************************************
@;                                      IRQ Interrupt Service Routine
@;*********************************************************************************************************
OS_CPU_Tick_ISR:
                                            @; ---- SAVE CONTEXT OF CURRENT TASK ----
                                            @; IRQ Mode:
        STMFD   SP!,{R0-R3,R12,LR}          @;   Push working registers on the IRQ stack

        MOV     R1,SP                       @;   Save IRQ SP
        ADD     SP,SP,#(6*4)                @;   Clean up IRQ stack

        SUB     R2,LR,#4                    @;   Correct return address and save

        MRS     R3,SPSR                     @;   Save SPSR of interrupted task

        MOV     R0,#0xD3                    @;   Disable interrupts for when we go back to SVC mode
        MSR     SPSR_c,R0                   @;   Prepare to switch to SVC mode

        LDR     R0,=.+8                     @;   Setup PC for SVC mode code (see below), current location + 2 instructions
        MOVS    PC,R0                       @;   Restore PC and CPSR

                                            @; SVC Mode:
        STMFD   SP!,{R2}                    @;   Push task's returns address
        STMFD   SP!,{LR}                    @;   Push task's LR
        STMFD   SP!,{R4-R12}                @;   Push task's R12-R4
        MOV     R4,R1                       @;   Move R0-R3 from IRQ stack to SVC stack
        MOV     R5,R3
        LDMFD   R4!,{R0-R3}                 @;   Load R0-R3 from IRQ stack
        STMFD   SP!,{R0-R3}                 @;   Push R0-R3
        STMFD   SP!,{R5}                    @;   Push task's SPSR
        
                                            @; ---- HANDLE NESTING COUNTER ----
        LDR     R0,=OSIntNesting           @; OSIntNesting++;
        LDRB    R1,[R0]
        ADD     R1,R1,#1
        STRB    R1,[R0]

        CMP     R1,#1                       @; if (OSIntNesting == 1) {
        BNE     OS_CPU_Tick_ISR_1

        LDR     R4,=OSTCBCur              @;     OSTCBCur->OSTCBStkPtr = SP
        LDR     R5,[R4]
        STR     SP,[R5]

OS_CPU_Tick_ISR_1:                          @; }

        LDR     R3,=OS_CPU_IRQ_ISR_Handler        @; Handle timer interrupt (see BSP.C)
        MOV     LR,PC
        BX      R3

                                            @; ---- EXIT INTERRUPT ----
        LDR     R3,=OSIntExit              @; OSIntExit()
        MOV     LR,PC
        BX      R3
                                            @; ---- RESTORE CONTEXT OF HIGH PRIORITY TASK ----
        LDMFD   SP!,{R4}                    @; Pop new task's SPSR
        MSR     SPSR_cxsf,R4

        LDMFD   SP!,{R0-R12,LR,PC}^         @; Pop new task's R0-R12,LR and PC

@;*********************************************************************************************************
@;                                      IRQ Interrupt Service Routine
@;*********************************************************************************************************

OS_CPU_IRQ_ISR:
                                               @; Disable FIQ for a moment
        MSR     CPSR_c, #(NO_INT | IRQ32_MODE)@ ; Change to IRQ mode (to use the IRQ stack to handle interrupt)
        STMFD   SP!, {R1-R3}                   @; PUSH WORKING REGISTERS ONTO IRQ STACK
        MOV     R1, SP                         @; Save   IRQ stack pointer
        ADD     SP, SP,#12                     @; Adjust IRQ stack pointer
        SUB     R2, LR,#4                      @; Adjust PC for return address to task
        MRS     R3, SPSR                       @; Copy SPSR (i.e. interrupted task's CPSR) to R3
        MSR     CPSR_c, #(NO_INT | SVC32_MODE) @; Change to SVC mode

                                               @; SAVE TASK'S CONTEXT ONTO TASK'S STACK
        STMFD   SP!, {R2}                      @;    Push task's Return PC
        STMFD   SP!, {LR}                      @;    Push task's LR
        STMFD   SP!, {R4-R12}                  @;    Push task's R12-R4

        LDMFD   R1!, {R4-R6}                   @;    Move task's R1-R3 from IRQ stack to SVC stack
        STMFD   SP!, {R4-R6}
        STMFD   SP!, {R0}                      @;    Push task's R0    onto task's stack
        STMFD   SP!, {R3}                     @;    Push task's CPSR (i.e. IRQ's SPSR)

                                              @; HANDLE NESTING COUNTER
        LDR     R0, =OSIntNesting             @; OSIntNesting++;
        LDRB    R1, [R0]
        ADD     R1, R1,#1
        STRB    R1, [R0]

        CMP     R1, #1                         @; if (OSIntNesting == 1) {
        BNE     OS_CPU_IRQ_ISR_1

        LDR     R4, =OSTCBCur                 @;     OSTCBCur->OSTCBStkPtr = SP
        LDR     R5, [R4]
        STR     SP, [R5]                       @; }

OS_CPU_IRQ_ISR_1:
        MSR     CPSR_c, #(NO_IRQ | IRQ32_MODE) @; Re-enable FIQ, Change to IRQ mode (to use the IRQ stack to handle interrupt)

        BL      OS_CPU_IRQ_ISR_Handler         @; OS_CPU_IRQ_ISR_Handler();


        MSR     CPSR_c, #(NO_INT | SVC32_MODE) @; Change to SVC mode

        BL      OSIntExit                     @; OSIntExit();


                                               @; RESTORE NEW TASK'S CONTEXT
        LDMFD   SP!, {R4}                      @;    Pop new task's CPSR
        MSR     SPSR_cxsf, R4

        LDMFD   SP!, {R0-R12,LR,PC}^           @;    Pop new task's context


@		END
.endif
.end

