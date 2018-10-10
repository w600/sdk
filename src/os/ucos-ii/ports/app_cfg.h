/*
*********************************************************************************************************
*                                              EXAMPLE CODE
*
*                          (c) Copyright 2003-2006; Micrium, Inc.; Weston, FL
*
*               All rights reserved.  Protected by international copyright laws.
*               Knowledge of the source code may NOT be used to develop a similar product.
*               Please help us continue to provide the Embedded community with the finest
*               software available.  Your honesty is greatly appreciated.
*********************************************************************************************************
*/

#ifndef  __APP_CFG_H__
#define  __APP_CFG_H__

/*
*********************************************************************************************************
*                                       MODULE ENABLE / DISABLE
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*                                              TASKS NAMES
*********************************************************************************************************
*/


/*
*********************************************************************************************************
*                                            TASK PRIORITIES
*********************************************************************************************************
*/
#define     TASK_START_PRIO         0     /* Application tasks priorities   */


#define     OS_TASK_TMR_PRIO       (OS_LOWEST_PRIO - 2)

/*
*********************************************************************************************************
*                                            TASK STACK SIZES
*                             Size of the task stacks (# of OS_STK entries)
*********************************************************************************************************
*/
/*
(    157484)disp_task_stat_info : task 0 TCB Stack used 0 bytes

(    157485)disp_task_stat_info : task 7 TCB Stack used 464 bytes
(    157485)disp_task_stat_info : task 8 TCB Stack used 152 bytes
(    157486)disp_task_stat_info : task 9 TCB Stack used 800 bytes
(    157487)disp_task_stat_info : task 10 TCB Stack used 432 bytes
(    157487)disp_task_stat_info : task 11 TCB Stack used 128 bytes
(    157488)disp_task_stat_info : task 12 TCB Stack used 136 bytes
(    157488)disp_task_stat_info : task 13 TCB Stack used 472 bytes
(    157489)disp_task_stat_info : task 14 TCB Stack used 136 bytes
(    157490)disp_task_stat_info : task 15 TCB Stack used 624 bytes

(    157490)disp_task_stat_info : task 29 TCB Stack used 136 bytes	
(    157491)disp_task_stat_info : task 30 TCB Stack used 144 bytes
(    157491)disp_task_stat_info : task 31 TCB Stack used 88 bytes
*/
#define     TASK_STK_SIZE         256     /* Size of each task's stacks (# of WORDs)  */

#if 0
#define      CMD_TASK_STK_SIZE                  1024
#define      IBSS_TASK_STK_SIZE                 256		   
#define      MLME_TASK_STK_SIZE                 1024
#define      SCAN_TASK_STK_SIZE                 512        /* scan  task stack  */
#define      MGMT_TX_CMP_TASK_STK_SIZE          256		
#define      SDIO_RX_TASK_STK_SIZE              256   
#define      RX_TASK_STK_SIZE                   1024
#define      DATA_TX_CMP_TASK_STK_SIZE          256
#define      TX_TASK_STK_SIZE                   512
#endif

#endif /* __APP_CFG_H__ */
