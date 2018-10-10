/*****************************************************************************
*
* File Name : wm_osal_rtos.h
*
* Description: rtos include Module
*
* Copyright (c) 2014 Winner Microelectronics Co., Ltd.
* All rights reserved.
*
* Author : dave
*
* Date : 2014-8-27
*****************************************************************************/

#ifndef WM_OS_RTOS_H
#define WM_OS_RTOS_H

#include "wm_config.h"
#if TLS_OS_FREERTOS

//#include "include.h"
#include <stdio.h>
#include <stdlib.h>
#include "wm_type_def.h"
#include "wm_irq.h"
#include "FreeRTOS.h"
#include "task.h"
#include "rtosqueue.h"
#include "semphr.h"
#include "rtostimers.h"
#include "FreeRTOSConfig.h"
#include "wm_osal.h"
#include "wm_mem.h"
/*
*********************************************************************************************************
*                                     CREATE A TASK (Extended Version)
*
* Description: This function is used to have uC/OS-II manage the execution of a task.  Tasks can either
*              be created prior to the start of multitasking or by a running task.  A task cannot be
*              created by an ISR.
*
* Arguments  : task      is a pointer to the task'
*
*			name 	is the task's name
*
*			entry	is the task's entry function
*
*              param     is a pointer to an optional data area which can be used to pass parameters to
*                        the task when the task first executes.  Where the task is concerned it thinks
*                        it was invoked and passed the argument 'param' as follows:
*
*                            void Task (void *param)
*                            {
*                                for (;;) {
*                                    Task code;
*                                }
*                            }
*
*              stk_start      is a pointer to the task's bottom of stack.
*
*              stk_size  is the size of the stack in number of elements.  If OS_STK is set to u8,
*                        'stk_size' corresponds to the number of bytes available.  If OS_STK is set to
*                        INT16U, 'stk_size' contains the number of 16-bit entries available.  Finally, if
*                        OS_STK is set to INT32U, 'stk_size' contains the number of 32-bit entries
*                        available on the stack.
*
*              prio      is the task's priority.  A unique priority MUST be assigned to each task and the
*                        lower the number, the higher the priority.
*
*              flag       contains additional information about the behavior of the task.
*
* Returns    : TLS_OS_SUCCESS             if the function was successful.
*              TLS_OS_ERROR
*********************************************************************************************************
*/
tls_os_status_t tls_os_task_create(tls_os_task_t *task,
      const char* name,
      void (*entry)(void* param),
      void* param,
      u8 *stk_start,
      u32 stk_size,
      u32 prio,
      u32 flag)
{
    u8 error;
    tls_os_status_t os_status;

    if (((u32)stk_start >= TASK_STACK_USING_MEM_UPPER_RANGE) 
		||(((u32)stk_start + stk_size) >= TASK_STACK_USING_MEM_UPPER_RANGE))
    {
    	printf("\nCurrent Stack [0x%8x, 0x%8x) is NOT in VALID STACK range [0x20000000,0x20028000)\n", stk_start, stk_start + stk_size);
    	printf("Please refer to APIs' manul and modify task stack position!!!\n");
    	return TLS_OS_ERROR;
    }

	error = xTaskCreateExt(entry,
		(const signed char *)name,
		(portSTACK_TYPE *)stk_start,
		stk_size/sizeof(u32),
		param,
		configMAX_PRIORITIES - prio,	/*优先级颠倒一下，与ucos优先级顺序相反*/
		task	);
	//printf("configMAX_PRIORITIES - prio:%d\n", configMAX_PRIORITIES - prio);
    if (error == pdTRUE)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

    return os_status;
}


/*
*********************************************************************************************************
*                                            DELETE A TASK
*
* Description: This function allows you to delete a task.  The calling task can delete itself by
*              its own priority number.  The deleted task is returned to the dormant state and can be
*              re-activated by creating the deleted task again.
*
* Arguments  : prio: the task priority
*                    freefun: function to free resource
*
* Returns    : TLS_OS_SUCCESS             if the call is successful
*             	 TLS_OS_ERROR
*********************************************************************************************************
*/
#if ( INCLUDE_vTaskDelete == 1 )
tls_os_status_t tls_os_task_del(u8 prio,void (*freefun)(void))
{
	if (0 == vTaskDeleteByPriority(configMAX_PRIORITIES - prio)){
		if (freefun){
			freefun();
		}
		return TLS_OS_SUCCESS;
	}

	return TLS_OS_ERROR;
}
#endif

#if (INCLUDE_vTaskSuspend == 1)
/*
*********************************************************************************************************
*                                            SUSPEND A TASK
*
* Description: This function is called to suspend a task.
*
* Arguments  : task     is a pointer to the task
*
* Returns    : TLS_OS_SUCCESS               if the requested task is suspended
*
* Note       : You should use this function with great care.  If you suspend a task that is waiting for
*              an event (i.e. a message, a semaphore, a queue ...) you will prevent this task from
*              running when the event arrives.
*********************************************************************************************************
*/
 tls_os_status_t tls_os_task_suspend(tls_os_task_t *task)
{
	vTaskSuspend(task);

	return TLS_OS_SUCCESS;
}

/*
*********************************************************************************************************
*                                        RESUME A SUSPENDED TASK
*
* Description: This function is called to resume a previously suspended task.
*
* Arguments  : task     is a pointer to the task
*
* Returns    : TLS_OS_SUCCESS                if the requested task is resumed
*
*********************************************************************************************************
*/
 tls_os_status_t tls_os_task_resume(tls_os_task_t *task)
{
	vTaskResume(task);

	return TLS_OS_SUCCESS;
}
#endif

/*
*********************************************************************************************************
*                                  CREATE A MUTUAL EXCLUSION SEMAPHORE
*
* Description: This function creates a mutual exclusion semaphore.
*
* Arguments  : prio          is the priority to use when accessing the mutual exclusion semaphore.  In
*                            other words, when the semaphore is acquired and a higher priority task
*                            attempts to obtain the semaphore then the priority of the task owning the
*                            semaphore is raised to this priority.  It is assumed that you will specify
*                            a priority that is LOWER in value than ANY of the tasks competing for the
*                            mutex.
*
*              mutex          is a pointer to the event control clock (OS_EVENT) associated with the
*                            created mutex.
*
*
* Returns    :TLS_OS_SUCCESS         if the call was successful.
*                 TLS_OS_ERROR
*
* Note(s)    : 1) The LEAST significant 8 bits of '.OSEventCnt' are used to hold the priority number
*                 of the task owning the mutex or 0xFF if no task owns the mutex.
*
*              2) The MOST  significant 8 bits of '.OSEventCnt' are used to hold the priority number
*                 to use to reduce priority inversion.
*********************************************************************************************************
*/
#if (1 == configUSE_MUTEXES)
 tls_os_status_t tls_os_mutex_create(u8 prio,
        tls_os_mutex_t **mutex)
{
    tls_os_status_t os_status;

	*mutex = xSemaphoreCreateMutex();

    if (*mutex != NULL)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

    return os_status;
}

/*
*********************************************************************************************************
*                                          DELETE A MUTEX
*
* Description: This function deletes a mutual exclusion semaphore and readies all tasks pending on the it.
*
* Arguments  : mutex        is a pointer to the event control block associated with the desired mutex.
*
* Returns    : TLS_OS_SUCCESS             The call was successful and the mutex was deleted
*                            TLS_OS_ERROR        error
*
* Note(s)    : 1) This function must be used with care.  Tasks that would normally expect the presence of
*                 the mutex MUST check the return code of OSMutexPend().
*
*              2) This call can potentially disable interrupts for a long time.  The interrupt disable
*                 time is directly proportional to the number of tasks waiting on the mutex.
*
*              3) Because ALL tasks pending on the mutex will be readied, you MUST be careful because the
*                 resource(s) will no longer be guarded by the mutex.
*
*              4) IMPORTANT: In the 'OS_DEL_ALWAYS' case, we assume that the owner of the Mutex (if there
*                            is one) is ready-to-run and is thus NOT pending on another kernel object or
*                            has delayed itself.  In other words, if a task owns the mutex being deleted,
*                            that task will be made ready-to-run at its original priority.
*********************************************************************************************************
*/
 tls_os_status_t tls_os_mutex_delete(tls_os_mutex_t *mutex)
{
	vSemaphoreDelete((xQUEUE *)mutex);

    return TLS_OS_SUCCESS;
}

/*
*********************************************************************************************************
*                                  PEND ON MUTUAL EXCLUSION SEMAPHORE
*
* Description: This function waits for a mutual exclusion semaphore.
*
* Arguments  : mutex        is a pointer to the event control block associated with the desired
*                            mutex.
*
*              wait_time       is an optional timeout period (in clock ticks).  If non-zero, your task will
*                            wait for the resource up to the amount of time specified by this argument.
*                            If you specify 0, however, your task will wait forever at the specified
*                            mutex or, until the resource becomes available.
*
*
*
* Returns    : TLS_OS_SUCCESS        The call was successful and your task owns the mutex
*                  TLS_OS_ERROR
*
* Note(s)    : 1) The task that owns the Mutex MUST NOT pend on any other event while it owns the mutex.
*
*              2) You MUST NOT change the priority of the task that owns the mutex
*********************************************************************************************************
*/
//不可在中断中调用
 tls_os_status_t tls_os_mutex_acquire(tls_os_mutex_t *mutex,
        u32 wait_time)
{
    u8 error;
    tls_os_status_t os_status;
	unsigned int time;

	if(0 == wait_time)
		time = portMAX_DELAY;
	else
		time = wait_time;
	error = xSemaphoreTake((xQUEUE *)mutex, time );
    if (error == pdPASS)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

    return os_status;
}


/*
*********************************************************************************************************
*                                  POST TO A MUTUAL EXCLUSION SEMAPHORE
*
* Description: This function signals a mutual exclusion semaphore
*
* Arguments  : mutex              is a pointer to the event control block associated with the desired
*                                  mutex.
*
* Returns    : TLS_OS_SUCCESS             The call was successful and the mutex was signaled.
*              	TLS_OS_ERROR
*********************************************************************************************************
*/
 tls_os_status_t tls_os_mutex_release(tls_os_mutex_t *mutex)
{
	u8 error;
	tls_os_status_t os_status;
	portBASE_TYPE pxHigherPriorityTaskWoken = pdFALSE;
	u8 isrcount = 0;

	isrcount = tls_get_isr_count();
	if(isrcount > 0)
	{
		error = xSemaphoreGiveFromISR((xQUEUE *)mutex, &pxHigherPriorityTaskWoken );
		if((pdTRUE == pxHigherPriorityTaskWoken) && (1 == isrcount))
		{
			portYIELD_FROM_ISR();
		}
	}
	else
	{
		error = xSemaphoreGive((xQUEUE *)mutex );
	}
    if (error == pdPASS)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

    return os_status;
}

#endif

/*
*********************************************************************************************************
*                                           CREATE A SEMAPHORE
*
* Description: This function creates a semaphore.
*
* Arguments  :sem		 is a pointer to the event control block (OS_EVENT) associated with the
*                            created semaphore
*			cnt           is the initial value for the semaphore.  If the value is 0, no resource is
*                            available (or no event has occurred).  You initialize the semaphore to a
*                            non-zero value to specify how many resources are available (e.g. if you have
*                            10 resources, you would initialize the semaphore to 10).
*
* Returns    : TLS_OS_SUCCESS	The call was successful
*			TLS_OS_ERROR
*********************************************************************************************************
*/

#if (1 == configUSE_COUNTING_SEMAPHORES)
 tls_os_status_t tls_os_sem_create(tls_os_sem_t **sem, u32 cnt)
{
    tls_os_status_t os_status;

	*sem = xSemaphoreCreateCounting( configSEMAPHORE_INIT_VALUE, cnt );


    if (*sem != NULL)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

    return os_status;
}


/*
*********************************************************************************************************
*                                         DELETE A SEMAPHORE
*
* Description: This function deletes a semaphore and readies all tasks pending on the semaphore.
*
* Arguments  : sem        is a pointer to the event control block associated with the desired
*                            semaphore.
*
* Returns    : TLS_OS_SUCCESS             The call was successful and the semaphore was deleted
*                            TLS_OS_ERROR
*
*********************************************************************************************************
*/
 tls_os_status_t tls_os_sem_delete(tls_os_sem_t *sem)
{
	vSemaphoreDelete((xQUEUE *)sem);

    return TLS_OS_SUCCESS;
}

/*
*********************************************************************************************************
*                                           PEND ON SEMAPHORE
*
* Description: This function waits for a semaphore.
*
* Arguments  : sem        is a pointer to the event control block associated with the desired
*                            semaphore.
*
*              wait_time       is an optional timeout period (in clock ticks).  If non-zero, your task will
*                            wait for the resource up to the amount of time specified by this argument.
*                            If you specify 0, however, your task will wait forever at the specified
*                            semaphore or, until the resource becomes available (or the event occurs).
*
* Returns    : TLS_OS_SUCCESS
*			TLS_OS_ERROR
*********************************************************************************************************
*/
//该函数不可用于中断服务程序中
 tls_os_status_t tls_os_sem_acquire(tls_os_sem_t *sem,
        u32 wait_time)
{
    u8 error;
    tls_os_status_t os_status;
	unsigned int time;

	if(0 == wait_time)
		time = portMAX_DELAY;
	else
		time = wait_time;
	error = xSemaphoreTake((xQUEUE *)sem, time );
    if (error == pdPASS)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

    return os_status;
}

/*
*********************************************************************************************************
*                                         POST TO A SEMAPHORE
*
* Description: This function signals a semaphore
*
* Arguments  : sem        is a pointer to the event control block associated with the desired
*                            semaphore.
*
* Returns    : TLS_OS_SUCCESS
*			TLS_OS_ERROR
*********************************************************************************************************
*/
 tls_os_status_t tls_os_sem_release(tls_os_sem_t *sem)
{
	u8 error;
	tls_os_status_t os_status;
	portBASE_TYPE pxHigherPriorityTaskWoken = pdFALSE;
	u8 isrcount = 0;

	isrcount = tls_get_isr_count();
	if(isrcount > 0)
	{
		error = xSemaphoreGiveFromISR((xQUEUE *)sem, &pxHigherPriorityTaskWoken );
		if((pdTRUE == pxHigherPriorityTaskWoken) && (1 == isrcount))
		{
			portYIELD_FROM_ISR();
		}
	}
	else
	{
		error = xSemaphoreGive((xQUEUE *)sem );
	}
	if (error == pdPASS)
		os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

    return os_status;

}
#endif

// ========================================================================= //
// Message Passing							     //
// ========================================================================= //

/*
*********************************************************************************************************
*                                        CREATE A MESSAGE QUEUE
*
* Description: This function creates a message queue if free event control blocks are available.
*
* Arguments  : queue	is a pointer to the event control clock (OS_EVENT) associated with the
*                                created queue
*
*			queue_start         is a pointer to the base address of the message queue storage area.  The
*                            storage area MUST be declared as an array of pointers to 'void' as follows
*
*                            void *MessageStorage[size]
*
*              	queue_size          is the number of elements in the storage area
*
*			msg_size
*
* Returns    : TLS_OS_SUCCESS
*			TLS_OS_ERROR
*********************************************************************************************************
*/

 tls_os_status_t tls_os_queue_create(tls_os_queue_t **queue, u32 queue_size)
{
    tls_os_status_t os_status;
	u32 queuesize = 10;
	void *queue_start = NULL;

	if (queue_size)
	{
		queuesize = queue_size;
	}
	queue_start = tls_mem_alloc(queuesize *(sizeof(void *)));
	if (NULL == queue_start)
	{
		return TLS_OS_ERROR;
	}

	*queue = xQueueCreateExt(queue_start, queuesize, sizeof(void *));

    if (*queue != NULL)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

    return os_status;
}

/*
*********************************************************************************************************
*                                        DELETE A MESSAGE QUEUE
*
* Description: This function deletes a message queue and readies all tasks pending on the queue.
*
* Arguments  : queue        is a pointer to the event control block associated with the desired
*                            queue.
*
*
* Returns    : TLS_OS_SUCCESS
*			TLS_OS_ERROR
*********************************************************************************************************
*/
extern u32 __heap_base;
 tls_os_status_t tls_os_queue_delete(tls_os_queue_t *queue)
{

	if ((((xQUEUE *)queue)->pcHead) >= &__heap_base)		//如果没有从堆申请，不用释放)
	{
		tls_mem_free(((xQUEUE *)queue)->pcHead);
	}
	vQueueDeleteExt((xQUEUE *)queue);

    return TLS_OS_SUCCESS;
}

/*
*********************************************************************************************************
*                                        POST MESSAGE TO A QUEUE
*
* Description: This function sends a message to a queue
*
* Arguments  : queue        is a pointer to the event control block associated with the desired queue
*
*              	msg          is a pointer to the message to send.
*
*			msg_size
* Returns    : TLS_OS_SUCCESS
*			TLS_OS_ERROR
*********************************************************************************************************
*/
 tls_os_status_t tls_os_queue_send(tls_os_queue_t *queue,
        void *msg,
        u32 msg_size)
{
	u8 error;
	tls_os_status_t os_status;
	portBASE_TYPE pxHigherPriorityTaskWoken = pdFALSE;
	u8 isrcount = 0;

	isrcount = tls_get_isr_count();
	if(isrcount > 0)
	{
		error = xQueueSendFromISR((xQUEUE *) queue, &msg, &pxHigherPriorityTaskWoken );
		if((pdTRUE == pxHigherPriorityTaskWoken) && (1 == isrcount))
		{			
			portYIELD_FROM_ISR();
		}
	}
	else
	{
		error = xQueueSend((xQUEUE *)queue, &msg, 0 );
	}

    if (error == pdPASS)
        os_status = TLS_OS_SUCCESS;
    else {
        os_status = TLS_OS_ERROR;
    }

    return os_status;
}
/*
*********************************************************************************************************
*                                     PEND ON A QUEUE FOR A MESSAGE
*
* Description: This function waits for a message to be sent to a queue
*
* Arguments  : queue        is a pointer to the event control block associated with the desired queue
*
*			msg		is a pointer to the message received
*
*			msg_size
*
*              wait_time       is an optional timeout period (in clock ticks).  If non-zero, your task will
*                            wait for a message to arrive at the queue up to the amount of time
*                            specified by this argument.  If you specify 0, however, your task will wait
*                            forever at the specified queue or, until a message arrives.
*
* Returns    : TLS_OS_SUCCESS
*			TLS_OS_ERROR
*********************************************************************************************************
*/
 tls_os_status_t tls_os_queue_receive(tls_os_queue_t *queue,
        void **msg,
        u32 msg_size,
        u32 wait_time)
{
	u8 error;
	tls_os_status_t os_status;
	unsigned int xTicksToWait;
	portBASE_TYPE pxHigherPriorityTaskWoken = pdFALSE;
	u8 isrcount = 0;

	if(0 == wait_time)
		xTicksToWait = portMAX_DELAY;
	else
		xTicksToWait = wait_time;
	isrcount = tls_get_isr_count();
	if(isrcount > 0)
	{
		error = xQueueReceiveFromISR((xQUEUE *)queue, msg, &pxHigherPriorityTaskWoken);
		if((pdTRUE == pxHigherPriorityTaskWoken) && (1 == isrcount))
		{
			portYIELD_FROM_ISR();
		}
	}
	else
	{
		error = xQueueReceive((xQUEUE *)queue, msg, xTicksToWait );
	}

    if (error == pdPASS)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

    return os_status;
}

/*
*********************************************************************************************************
*                                             FLUSH QUEUE
*
* Description : This function is used to flush the contents of the message queue.
*
* Arguments   : none
*
* Returns    : TLS_OS_SUCCESS
*			 TLS_OS_ERROR
*At present, no use for freeRTOS
*********************************************************************************************************
*/
tls_os_status_t tls_os_queue_flush(tls_os_queue_t *queue)
{
	return TLS_OS_SUCCESS;
}

/*
*********************************************************************************************************
*                                        CREATE A MESSAGE MAILBOX
*
* Description: This function creates a message mailbox if free event control blocks are available.
*
* Arguments  : mailbox		is a pointer to the event control clock (OS_EVENT) associated with the
*                                created mailbox
*
*			mailbox_start          is a pointer to a message that you wish to deposit in the mailbox.  If
*                            you set this value to the NULL pointer (i.e. (void *)0) then the mailbox
*                            will be considered empty.
*
*			mailbox_size
*
*			msg_size
*
Returns    : TLS_OS_SUCCESS
*			TLS_OS_ERROR
*********************************************************************************************************
*/
#if (1 == configUSE_MAILBOX)
 tls_os_status_t tls_os_mailbox_create(tls_os_mailbox_t **mailbox,
        u32 mailbox_size)
{
    tls_os_status_t os_status;
	u32 mbox_size = 1;

	if (mailbox_size)
	{
		mbox_size = mailbox_size;
	}

	*mailbox = xQueueCreate(mbox_size, sizeof(void *));

    if (*mailbox != NULL)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

    return os_status;
}

/*
*********************************************************************************************************
*                                         DELETE A MAIBOX
*
* Description: This function deletes a mailbox and readies all tasks pending on the mailbox.
*
* Arguments  : mailbox        is a pointer to the event control block associated with the desired
*                            mailbox.
*
*
Returns    : TLS_OS_SUCCESS
*			TLS_OS_ERROR
*********************************************************************************************************
*/

 tls_os_status_t tls_os_mailbox_delete(tls_os_mailbox_t *mailbox)
{
	vQueueDelete((xQUEUE *)mailbox);

    return TLS_OS_SUCCESS;
}


/*
*********************************************************************************************************
*                                       POST MESSAGE TO A MAILBOX
*
* Description: This function sends a message to a mailbox
*
* Arguments  : mailbox        is a pointer to the event control block associated with the desired mailbox
*
*              msg          is a pointer to the message to send.  You MUST NOT send a NULL pointer.
*
Returns    : TLS_OS_SUCCESS
*			TLS_OS_ERROR
*********************************************************************************************************
*/
 tls_os_status_t tls_os_mailbox_send(tls_os_mailbox_t *mailbox,
        void *msg)
{
	u8 error;
	tls_os_status_t os_status;
	portBASE_TYPE pxHigherPriorityTaskWoken = pdFALSE;
	u8 isrcount = 0;

	isrcount = tls_get_isr_count();
	if(isrcount > 0)
	{
		error = xQueueSendFromISR( (xQUEUE *)mailbox, &msg, &pxHigherPriorityTaskWoken );
		if((pdTRUE == pxHigherPriorityTaskWoken) && (1 == isrcount))
		{
			vTaskSwitchContext();
		}
	}
	else
	{
		error = xQueueSend( (xQUEUE *)mailbox, &msg, 0 );
	}

    if (error == pdPASS)
        os_status = TLS_OS_SUCCESS;
    else {
        os_status = TLS_OS_ERROR;
    }

    return os_status;
}
/*
*********************************************************************************************************
*                                      PEND ON MAILBOX FOR A MESSAGE
*
* Description: This function waits for a message to be sent to a mailbox
*
* Arguments  : mailbox        is a pointer to the event control block associated with the desired mailbox
*
*			msg			is a pointer to the message received
*
*              wait_time       is an optional timeout period (in clock ticks).  If non-zero, your task will
*                            wait for a message to arrive at the mailbox up to the amount of time
*                            specified by this argument.  If you specify 0, however, your task will wait
*                            forever at the specified mailbox or, until a message arrives.
*
*Returns    : TLS_OS_SUCCESS
*			TLS_OS_ERROR
*********************************************************************************************************
*/
 tls_os_status_t tls_os_mailbox_receive(tls_os_mailbox_t *mailbox,
        void **msg,
        u32 wait_time)
{
	u8 error;
	tls_os_status_t os_status;
	unsigned int xTicksToWait;
	portBASE_TYPE pxHigherPriorityTaskWoken = pdFALSE;
	u8 isrcount = 0;

	if(0 == wait_time)
		xTicksToWait = portMAX_DELAY;
	else
		xTicksToWait = wait_time;

	isrcount = tls_get_isr_count();
	if(isrcount > 0)
	{
		error = xQueueReceiveFromISR((xQUEUE *)mailbox, msg, &pxHigherPriorityTaskWoken);
		if((pdTRUE == pxHigherPriorityTaskWoken) && (1 == isrcount))
		{
			portYIELD_FROM_ISR();
		}
	}
	else
	{
		error = xQueueReceive( (xQUEUE *)mailbox, msg, xTicksToWait );
	}

    if (error == pdPASS)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

    return os_status;
}

#endif

/*
*********************************************************************************************************
*                                         GET CURRENT SYSTEM TIME
*
* Description: This function is used by your application to obtain the current value of the 32-bit
*              counter which keeps track of the number of clock ticks.
*
* Arguments  : none
*
* Returns    : The current value of OSTime
*********************************************************************************************************
*/
 u32 tls_os_get_time(void)
{
    return xTaskGetTickCountFromISR();
}
u32 os_cnter = 0;
/**********************************************************************************************************
* Description: Disable interrupts by preserving the state of interrupts.
*
* Arguments  : none
*
* Returns    : cpu_sr
***********************************************************************************************************/
 u32 tls_os_set_critical(void)
{
	os_cnter++;
	vPortEnterCritical();
    return 1;
}

/**********************************************************************************************************
* Description: Enable interrupts by preserving the state of interrupts.
*
* Arguments  : cpu_sr
*
* Returns    : none
***********************************************************************************************************/
 void tls_os_release_critical(u32 cpu_sr)
{
	if (os_cnter)
	os_cnter--;
    return vPortExitCritical();
}

/*
************************************************************************************************************************
*                                                   CREATE A TIMER
*
* Description: This function is called by your application code to create a timer.
*
* Arguments  : timer	A pointer to an OS_TMR data structure.This is the 'handle' that your application
*						will use to reference the timer created.
*
*		        callback      Is a pointer to a callback function that will be called when the timer expires.  The
*                               callback function must be declared as follows:
*
*                               void MyCallback (OS_TMR *ptmr, void *p_arg);
*
* 	             callback_arg  Is an argument (a pointer) that is passed to the callback function when it is called.
*
*          	   	 period        The 'period' being repeated for the timer.
*                               If you specified 'OS_TMR_OPT_PERIODIC' as an option, when the timer expires, it will
*                               automatically restart with the same period.
*
*			repeat	if repeat
*
*             	pname         Is a pointer to an ASCII string that is used to name the timer.  Names are useful for
*                               debugging.
*
*Returns    : TLS_OS_SUCCESS
*			TLS_OS_ERROR
************************************************************************************************************************
*/
 tls_os_status_t tls_os_timer_create(tls_os_timer_t **timer,
        TLS_OS_TIMER_CALLBACK callback,
        void *callback_arg,
        u32 period,
        bool repeat,
        u8 *name)
{
    tls_os_status_t os_status;

	if(0 == period)
		period = 1;
#if configUSE_TIMERS
	*timer = (xTIMER *)xTimerCreateExt( (signed char *)name, period, repeat, NULL, callback, callback_arg );
#endif
    if (*timer  != NULL)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = TLS_OS_ERROR;

	return os_status;
}

/*
************************************************************************************************************************
*                                                   START A TIMER
*
* Description: This function is called by your application code to start a timer.
*
* Arguments  : timer          Is a pointer to an OS_TMR
*
************************************************************************************************************************
*/
 void tls_os_timer_start(tls_os_timer_t *timer)
{
	portBASE_TYPE pxHigherPriorityTaskWoken = pdFALSE;
	u8 isrcount = 0;

	isrcount = tls_get_isr_count();
	if(isrcount > 0)
	{
#if configUSE_TIMERS
		xTimerStartFromISR((xTIMER *)timer, &pxHigherPriorityTaskWoken );
#endif
		if((pdTRUE == pxHigherPriorityTaskWoken) && (1 == isrcount))
		{
			portYIELD_FROM_ISR();
		}
	}
	else
	{
#if configUSE_TIMERS
		xTimerStart((xTIMER *)timer, 0 );		//no block time
#endif
	}
}
/*
************************************************************************************************************************
*                                                   CHANGE A TIMER WAIT TIME
*
* Description: This function is called by your application code to change a timer wait time.
*
* Arguments  : timer          Is a pointer to an OS_TMR
*
*			ticks			is the wait time
************************************************************************************************************************
*/
 void tls_os_timer_change(tls_os_timer_t *timer, u32 ticks)
{
	portBASE_TYPE pxHigherPriorityTaskWoken = pdFALSE;
	u8 isrcount = 0;

	if(0 == ticks)
		ticks = 1;

	isrcount = tls_get_isr_count();
	if(isrcount > 0)
	{
#if configUSE_TIMERS
		xTimerChangePeriodFromISR((xTIMER *)timer, ticks, &pxHigherPriorityTaskWoken );
		xTimerStartFromISR( (xTIMER *)timer, &pxHigherPriorityTaskWoken );
#endif
		if((pdTRUE == pxHigherPriorityTaskWoken) && (1 == isrcount))
		{
			portYIELD_FROM_ISR();
		}
	}
	else
	{
#if configUSE_TIMERS
		xTimerChangePeriod((xTIMER *)timer, ticks, 0 );
		xTimerStart((xTIMER *)timer, 0 );
#endif
	}
}
/*
************************************************************************************************************************
*                                                   STOP A TIMER
*
* Description: This function is called by your application code to stop a timer.
*
* Arguments  : timer          Is a pointer to the timer to stop.
*
************************************************************************************************************************
*/
 void tls_os_timer_stop(tls_os_timer_t *timer)
{
	portBASE_TYPE pxHigherPriorityTaskWoken = pdFALSE;
	u8 isrcount = 0;

	isrcount = tls_get_isr_count();
	if(isrcount > 0)
	{
#if configUSE_TIMERS
		xTimerStopFromISR((xTIMER *)timer, &pxHigherPriorityTaskWoken );
#endif
		if((pdTRUE == pxHigherPriorityTaskWoken) && (1 == isrcount))
		{
			portYIELD_FROM_ISR();
		}
	}
	else
	{
#if configUSE_TIMERS
		xTimerStop((xTIMER *)timer, 0 );
#endif
	}
}


/*
************************************************************************************************************************
*                                                   Delete A TIMER
*
* Description: This function is called by your application code to delete a timer.
*
* Arguments  : timer          Is a pointer to the timer to delete.
*
************************************************************************************************************************
*/
 int tls_os_timer_delete(tls_os_timer_t *timer)
{
	int ret = 0;
	/* xTimer is already active - delete it. */
	ret = xTimerDelete((xTIMER *)timer, 10);
	return ret;
}


/*
*********************************************************************************************************
*                                       DELAY TASK 'n' TICKS
*
* Description: This function is called to delay execution of the currently running task until the
*              specified number of system ticks expires.  This, of course, directly equates to delaying
*              the current task for some time to expire.  No delay will result If the specified delay is
*              0.  If the specified delay is greater than 0 then, a context switch will result.
*
* Arguments  : ticks     is the time delay that the task will be suspended in number of clock 'ticks'.
*                        Note that by specifying 0, the task will not be delayed.
*
* Returns    : none
*********************************************************************************************************
*/
 void tls_os_time_delay(u32 ticks)
{
	vTaskDelay(ticks);
}

/*
*********************************************************************************************************
*                                       task stat info
*
* Description: This function is used to display stat info
* Arguments  :
*
* Returns    : none
*********************************************************************************************************
*/
void tls_os_disp_task_stat_info(void)
{
	char *buf = NULL;

	buf = tls_mem_alloc(1024);
	if(NULL == buf)
		return;
#if configUSE_TRACE_FACILITY
	vTaskList((signed char *)buf);
#endif
	printf("\n%s",buf);
	tls_mem_free(buf);
	buf = NULL;
}
/*
*********************************************************************************************************
*                                     OS INIT function
*
* Description: This function is used to init os common resource
*
* Arguments  : None;
*
* Returns    : None
*********************************************************************************************************
*/

void tls_os_init(void *arg)
{
}
/*
*********************************************************************************************************
*                                     OS scheduler start function
*
* Description: This function is used to start task schedule
*
* Arguments  : None;
*
* Returns    : None
*********************************************************************************************************
*/

void tls_os_start_scheduler(void)
{
	vTaskStartScheduler();
}
/*
*********************************************************************************************************
*                                     Get OS TYPE
*
* Description: This function is used to get OS type
*
* Arguments  : None;
*
* Returns    : TLS_OS_TYPE
*                	 OS_UCOSII = 0,
*	             OS_FREERTOS = 1,
*********************************************************************************************************
*/

int tls_os_get_type(void)
{
	return (int)OS_FREERTOS;
}
/*
*********************************************************************************************************
*                                     OS tick handler
*
* Description: This function is  tick handler.
*
* Arguments  : None;
*
* Returns    : None
*********************************************************************************************************
*/

void tls_os_time_tick(void *p){

}

/**
 * @brief          	get isr count
 *
 * @param[in]      	None
 *
 * @retval         	count
 *
 * @note           	None
 */

extern int portGET_IPSR(void);
u8 tls_get_isr_count(void)
{	 
//    return intr_counter;
	return (portGET_IPSR() > 13);
}

#endif
#endif /* end of WM_OSAL_RTOS_H */
