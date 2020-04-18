;******************** Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. ********************
;* File Name     : startup_venus.s
;* Author            : 
;* Version          : 
;* Date               : 
;* Description    : 
; <h> Stack Configuration
;   <o> Stack Size (in Bytes)
; </h>

Stack_Size      EQU     0x00000400

                AREA    |.bss|, BSS, NOINIT, READWRITE, ALIGN=3
Stack_Mem       SPACE   Stack_Size
__initial_sp

; <h> Heap Configuration
;   <o>  Heap Size (in Bytes):at least 80Kbyte
; </h>

Heap_Size       EQU     0x001A000

                AREA    HEAP, NOINIT, READWRITE, ALIGN=3
__heap_base
Heap_Mem        SPACE   Heap_Size
__heap_limit

                PRESERVE8
                THUMB


; Vector Table Mapped to Address 0 at Reset
                AREA    RESET, DATA, READONLY
                EXPORT  __Vectors
                EXPORT  __Vectors_End
                EXPORT  __Vectors_Size
				IMPORT PendSV_Handler 
				IMPORT OS_CPU_SysTickHandler
				IMPORT UART0_IRQHandler
				IMPORT UART1_IRQHandler
				IMPORT tls_wl_rx_isr
				IMPORT tls_wl_mgmt_tx_isr
				IMPORT tls_wl_data_tx_isr
				IMPORT tls_wl_mac_isr
				IMPORT TIM0_IRQHandler
				IMPORT TIM1_IRQHandler	
				IMPORT TIM2_IRQHandler
				IMPORT TIM3_IRQHandler
				IMPORT TIM4_IRQHandler
				IMPORT TIM5_IRQHandler
				IMPORT WDG_IRQHandler
				IMPORT tls_exception_handler



__Vectors       DCD     __initial_sp			   ; Top of Stack
                DCD     Reset_Handler              ; Reset Handler
                DCD     NMI_Handler                ; NMI Handler
                DCD     HardFault_Handler          ; Hard Fault Handler
                DCD     MemManage_Handler          ; MPU Fault Handler
                DCD     BusFault_Handler           ; Bus Fault Handler
                DCD     UsageFault_Handler         ; Usage Fault Handler
                DCD     0                          ; Reserved
                DCD     0                          ; Reserved
                DCD     0                          ; Reserved
                DCD     0                          ; Reserved
                DCD     SVC_Handler                ; SVCall Handler
                DCD     DebugMon_Handler           ; Debug Monitor Handler
                DCD     0                          ; Reserved
                DCD     PendSV_Handler             ; PendSV Handler
                DCD     OS_CPU_SysTickHandler      ; SysTick Handler

                ; External Interrupts
                DCD     SDIO_RX_IRQHandler              ; HSPI&SDIO SLAVE Trasmit
                DCD     SDIO_TX_IRQHandler              ; HSPI & SDIO SLAVE Receive Data
                DCD     0						        ; Not Used
                DCD     SDIO_TX_CMD_IRQHandler          ; HSPI & SDIO SLAVE Receive Command
                DCD     tls_wl_mac_isr                  ; MAC isr
                DCD     0			             		; Not Used
                DCD     tls_wl_rx_isr           		; Wi-Fi Rx isr
                DCD     tls_wl_mgmt_tx_isr           	; Wi-Fi Managment tx isr
                DCD     tls_wl_data_tx_isr           	; Wi-Fi Data Tx isr
                DCD     PMU_TIMER1_IRQHandler           ; PMU Timer1
                DCD     PMU_TIMER0_IRQHandler           ; PMU Timer0
                DCD     PMU_GPIO_WAKE_IRQHandler   		; PMU Wakeup pin isr
                DCD     PMU_SDIO_WAKE_IRQHandler   		; SDIO Wakeup isr
                DCD     DMA_Channel0_IRQHandler   		; DMA Channel 0
                DCD     DMA_Channel1_IRQHandler   		; DMA Channel 1
                DCD     DMA_Channel2_IRQHandler   		; DMA Channel 2
                DCD     DMA_Channel3_IRQHandler   		; DMA Channel 3
                DCD     DMA_Channel4_7_IRQHandler   	; DMA Channel 4-7
                DCD     DMA_BURST_IRQHandler          	; DMA Burst isr
                DCD     I2C_IRQHandler  				; I2C isr
                DCD     ADC_IRQHandler 					; ADC isr
                DCD     SPI_LS_IRQHandler        		; Master SPI isr
                DCD     SPI_HS_IRQHandler        		; HSPI isr, not used
                DCD     UART0_IRQHandler         		; UART0 isr
                DCD     UART1_IRQHandler        		; UART1 isr
                DCD     GPIOA_IRQHandler         		; GPIOA isr
                DCD     TIM0_IRQHandler    				; TIM0 isr
                DCD     TIM1_IRQHandler         		; TIM1 isr
                DCD     TIM2_IRQHandler            		; TIM2 isr
                DCD     TIM3_IRQHandler            		; TIM3 isr
                DCD     TIM4_IRQHandler            		; TIM4 isr
                DCD     TIM5_IRQHandler         		; TIM5 isr
                DCD     WDG_IRQHandler        			; Watchdog isr
                DCD     0			         			; Not Used
                DCD     0				         		; Not Used
                DCD     PWM_IRQHandler            		; PWM isr
                DCD     I2S_IRQHandler            		; I2S isr
				DCD		PMU_RTC_IRQHandler				; PMU RTC isr
				DCD		RSA_IRQHandler                  ; RSA isr
		        DCD     CRYPTION_IRQHandler  			; CRYPTION isr
		        DCD     GPIOB_IRQHandler          		; GBIOB isr
                DCD     UART2_IRQHandler          		; UART2&7816 isr
				DCD		0								; Not Used
__Vectors_End

__Vectors_Size  EQU  __Vectors_End - __Vectors

                AREA    |.text|, CODE, READONLY

; Reset handler
Reset_Handler   PROC
                EXPORT  Reset_Handler             [WEAK]
		IMPORT  __main
				MOV		R0, #0
				MSR 	PRIMASK,R0
                LDR     R0, =__main
                BX      R0
                ENDP

; Dummy Exception Handlers (infinite loops which can be modified)

NMI_Handler     PROC
                EXPORT  NMI_Handler                [WEAK]
                B       .
                ENDP
HardFault_Handler\
                PROC
                EXPORT  HardFault_Handler          [WEAK]
                TST	LR, #4
                ITE EQ
				MRSEQ R0, MSP
				MRSNE R0, PSP
				MOV   R1, #0
                B       tls_exception_handler
                ENDP
MemManage_Handler\
                PROC
                EXPORT  MemManage_Handler          [WEAK]
				TST LR, #4
				ITE EQ
				MRSEQ R0, MSP
				MRSNE R0, PSP
				MOV   R1, #1			   
				B		tls_exception_handler

                ENDP
BusFault_Handler\
                PROC
                EXPORT  BusFault_Handler           [WEAK]
				TST LR, #4
				ITE EQ
				MRSEQ R0, MSP
				MRSNE R0, PSP
				MOV   R1, #2
				B		tls_exception_handler

                ENDP
UsageFault_Handler\
                PROC
                EXPORT  UsageFault_Handler         [WEAK]
				TST LR, #4
				ITE EQ
				MRSEQ R0, MSP
				MRSNE R0, PSP
				MOV   R1, #3			   
				B		tls_exception_handler

                ENDP
SVC_Handler     PROC
                EXPORT  SVC_Handler                [WEAK]
                B       .
                ENDP
DebugMon_Handler\
                PROC
                EXPORT  DebugMon_Handler           [WEAK]
                B       .
                ENDP
;PendSV_Handler  PROC
;                EXPORT  PendSV_Handler            [WEAK]
;                B       .
;                ENDP
;SysTick_Handler PROC
;                EXPORT  SysTick_Handler           [WEAK]
;                B       .
;                ENDP

Default_Handler PROC

                EXPORT  SDIO_RX_IRQHandler         [WEAK]
                EXPORT  SDIO_TX_IRQHandler         [WEAK]
                EXPORT  SDIO_TX_CMD_IRQHandler     [WEAK]
                EXPORT  RSV_IRQHandler             [WEAK]
                EXPORT  PMU_RTC_IRQHandler         [WEAK]
				EXPORT 	PMU_TIMER1_IRQHandler      [WEAK]
                EXPORT 	PMU_TIMER0_IRQHandler      [WEAK]
                EXPORT 	PMU_GPIO_WAKE_IRQHandler   [WEAK]
                EXPORT  PMU_SDIO_WAKE_IRQHandler   [WEAK]
                EXPORT  DMA_Channel0_IRQHandler    [WEAK]
                EXPORT  DMA_Channel1_IRQHandler    [WEAK]
                EXPORT  DMA_Channel2_IRQHandler    [WEAK]
                EXPORT  DMA_Channel3_IRQHandler    [WEAK]
                EXPORT  DMA_Channel4_7_IRQHandler  [WEAK]
                EXPORT  DMA_BURST_IRQHandler       [WEAK]
                EXPORT  I2C_IRQHandler  		   [WEAK]
                EXPORT  ADC_IRQHandler 			   [WEAK]
                EXPORT  SPI_LS_IRQHandler          [WEAK]
                EXPORT  SPI_HS_IRQHandler          [WEAK]
;               EXPORT  UART0_IRQHandler           [WEAK]
;               EXPORT  UART1_IRQHandler           [WEAK]
                EXPORT  GPIOA_IRQHandler           [WEAK]
;               EXPORT  TIM0_IRQHandler            [WEAK]
;               EXPORT  TIM1_IRQHandler            [WEAK]
;               EXPORT  TIM2_IRQHandler            [WEAK]
;               EXPORT  TIM3_IRQHandler            [WEAK]
;               EXPORT  TIM4_IRQHandler            [WEAK]
;               EXPORT  TIM5_IRQHandler        	   [WEAK]
;               EXPORT  WDG_IRQHandler             [WEAK]
                EXPORT  PWM_IRQHandler             [WEAK]
                EXPORT  I2S_IRQHandler             [WEAK]
                EXPORT  RSA_IRQHandler        	   [WEAK]	
                EXPORT  CRYPTION_IRQHandler        [WEAK]
				EXPORT  GPIOB_IRQHandler           [WEAK]
               	EXPORT	UART2_IRQHandler		   [WEAK]
SDIO_RX_IRQHandler
SDIO_TX_IRQHandler
SDIO_TX_CMD_IRQHandler
;MAC_IRQHandler           
RSV_IRQHandler
;SEC_RX_IRQHandler          
;SEC_TX_MNGT_IRQHandler          
;SEC_TX_DAT_IRQHandler          
PMU_RTC_IRQHandler          
PMU_TIMER1_IRQHandler       
PMU_TIMER0_IRQHandler       
PMU_GPIO_WAKE_IRQHandler   
PMU_SDIO_WAKE_IRQHandler
DMA_Channel0_IRQHandler
DMA_Channel1_IRQHandler
DMA_Channel2_IRQHandler
DMA_Channel3_IRQHandler
DMA_Channel4_7_IRQHandler
DMA_BURST_IRQHandler
I2C_IRQHandler
ADC_IRQHandler
SPI_LS_IRQHandler
SPI_HS_IRQHandler
;UART0_IRQHandler         
;UART1_IRQHandler        
GPIOA_IRQHandler         
;TIM0_IRQHandler    
;TIM1_IRQHandler       
;TIM2_IRQHandler          
;TIM3_IRQHandler           
;TIM4_IRQHandler            
;TIM5_IRQHandler        
;WDG_IRQHandler             
PWM_IRQHandler            
I2S_IRQHandler           
RSA_IRQHandler
CRYPTION_IRQHandler  
GPIOB_IRQHandler        
UART2_IRQHandler
                B       .

                ENDP

                ALIGN

;*******************************************************************************
; User Stack and Heap initialization
;*******************************************************************************
                 IF      :DEF:__MICROLIB

                 EXPORT  __initial_sp
                 EXPORT  __heap_base
                 EXPORT  __heap_limit

                 ELSE

                 IMPORT  __use_two_region_memory
                 EXPORT  __user_initial_stackheap

__user_initial_stackheap

                 LDR     R0, =  Heap_Mem
                 LDR     R1, =(Stack_Mem + Stack_Size)
                 LDR     R2, = (Heap_Mem +  Heap_Size)
                 LDR     R3, = Stack_Mem
                 BX      LR

                 ALIGN

                 ENDIF

                 END

;******************* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. *****END OF FILE*****
