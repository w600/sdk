/*
*********************************************************************************************************
*                                               uC/OS-II
*                                        The Real-Time Kernel
*
*                        (c) Copyright 1992-1998, Jean J. Labrosse, Plantation, FL
*                                          All Rights Reserved
*                        (c) Copyright ARM Limited 1999.  All rights reserved.
*
*                                          ARM Specific code
*
* File : OS_CPU.H
*********************************************************************************************************
*/

#ifndef  OS_CPU_H
#define  OS_CPU_H


#ifdef   OS_CPU_GLOBALS
#define  OS_CPU_EXT
#else
#define  OS_CPU_EXT  extern
#endif

/*
*********************************************************************************************************
*                                              DATA TYPES
*                                         (Compiler Specific)
*********************************************************************************************************
*/
#include "wm_type_def.h"
#include "wm_osal.h"

#if 0 // remove by kevin 140612
typedef unsigned char  BOOLEAN;
typedef unsigned char  INT8U;                    /* Unsigned  8 bit quantity                           */
typedef signed   char  INT8S;                    /* Signed    8 bit quantity                           */
typedef unsigned short INT16U;                   /* Unsigned 16 bit quantity                           */
typedef signed   short INT16S;                   /* Signed   16 bit quantity                           */
typedef unsigned int   INT32U;                   /* Unsigned 32 bit quantity                           */
typedef signed   int   INT32S;                   /* Signed   32 bit quantity                           */
typedef float          FP32;                     /* Single precision floating point                    */
typedef double         FP64;                     /* Double precision floating point                    */

typedef unsigned int   OS_STK;                   /* Each stack entry is 32-bit wide                    */
typedef unsigned int   OS_CPU_SR;                /* Define size of CPU status register (PSR = 32 bits) */
#if 0
typedef unsigned char  bool;
typedef unsigned char  u8;
typedef signed   char  s8;
typedef unsigned short u16;
typedef signed   short s16;
typedef unsigned int   u32;
typedef signed   int   s32;
typedef unsigned long long u64;
#endif
#define TRUE           1
#define FALSE          0

#define true            1
#define false           0
#endif

#ifdef BOOLEAN
#undef BOOLEAN
#endif
	typedef unsigned char BOOLEAN;
	
#ifdef INT8U
#undef INT8U
#endif
	typedef unsigned char INT8U;
	
#ifdef INT16U
#undef INT16U
#endif
	typedef unsigned short INT16U;
	
#ifdef INT32U
#undef INT32U
#endif
typedef unsigned int INT32U;

/* 
*********************************************************************************************************
*                              ARM, various architectures
*
*********************************************************************************************************
*/

#define  OS_CRITICAL_METHOD   3

#if OS_CRITICAL_METHOD == 3
#define  OS_ENTER_CRITICAL()  {cpu_sr = OSCPUSaveSR();}
#define  OS_EXIT_CRITICAL()   {OSCPURestoreSR(cpu_sr);}
#endif

#define  OS_STK_GROWTH        1                   /* Stack grows from HIGH to LOW memory on ARM        */

#define  OS_TASK_SW()         OSCtxSw()

/*
*********************************************************************************************************
*                                              PROTOTYPES
*********************************************************************************************************
*/

#if OS_CRITICAL_METHOD == 3                       /* See OS_CPU_A.S                                  */
OS_CPU_SR  OSCPUSaveSR(void);
void       OSCPURestoreSR(OS_CPU_SR cpu_sr);
#endif

void       OSCtxSw(void);
void       OSIntCtxSw(void);
void       OSStartHighRdy(void);

void       OS_CPU_PendSVHandler(void);

                                                  /* See OS_CPU_C.C                                    */
void       OS_CPU_SysTickHandler(void);
void       OS_CPU_SysTickInit(void);

                                                  /* See BSP.C                                         */
INT32U     OS_CPU_SysTickClkFreq(void);
#endif
