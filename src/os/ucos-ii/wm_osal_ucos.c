/*****************************************************************************
*
* File Name : wm_osal_ucos.h
*
* Description: usos include Module
*
* Copyright (c) 2014 Winner Microelectronics Co., Ltd.
* All rights reserved.
*
* Author : dave
*
* Date : 2014-6-13
*****************************************************************************/
#include "include.h"
#include <stdio.h>
#include <stdlib.h>
#include "wm_type_def.h"
#include "wm_osal.h"

#if TLS_OS_UCOS
#include "ucos_ii.h"
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
*              stk_size  is the size of the stack in number of elements.  If OS_STK is set to INT8U,
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
      INT8U *stk_start,
      INT32U stk_size,
      INT32U prio,
      INT32U flag)
{
    INT8U error;
    tls_os_status_t os_status;
#if OS_TASK_NAME_EN > 0u
    INT8U  err;
#endif

    if (((INT32U)stk_start >= TASK_STACK_USING_MEM_UPPER_RANGE) 
		||(((INT32U)stk_start + stk_size) >= TASK_STACK_USING_MEM_UPPER_RANGE))
    {
        printf("\nCurrent Stack [0x%8x, 0x%8x) is NOT in VALID STACK range [0x20000000,0x20028000)\n", stk_start, stk_start + stk_size);
        printf("Please refer to APIs' manul and modify task stack position!!!\n");
        return TLS_OS_ERROR;
    }

    error = OSTaskCreateExt(entry,                         /* task entry */
            param,                                         /* task context */
            (OS_STK *)(stk_start + stk_size - 4),          /* set top-of-stack */
            prio,                                          /* task priority */
            prio,                                          /* task id */
            (OS_STK *)stk_start,                           /* set Bottom-of-Stack */
            stk_size/sizeof(u32),                          /* stack size */
            (void *)0,                                     /* extends info */
            OS_TASK_OPT_STK_CHK | OS_TASK_OPT_STK_CLR);    /* flag */
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = (tls_os_status_t) error;
#if 0
    task->prio = prio;
#endif
	*((INT8U *)task) = prio;
#if OS_TASK_NAME_EN > 0u
    OSTaskNameSet(prio, (INT8U *)(void *)name, &err);
#endif
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
*             	TLS_OS_ERROR
*
*********************************************************************************************************
*/
#if OS_TASK_DEL_EN
tls_os_status_t tls_os_task_del(INT8U prio, void (*freefun)(void))
{
	INT8U error;
	INT8U selfdel = 0;

	if (prio == OSTCBCur->OSTCBPrio){
		selfdel = 1;
	}

	if (!selfdel){
		if (OS_ERR_NONE == OSTaskDel(prio)){
			if (freefun){
				freefun();
			}
			return TLS_OS_SUCCESS;
		}
	}else{
		error = OSTaskDelReq(prio);
		if (error == OS_ERR_TASK_NOT_EXIST){
			if (freefun){
				freefun();
			}
			return TLS_OS_SUCCESS;
		}

		if (error == OS_ERR_NONE){
			while (1){
				OSTimeDly(10);
				if (OSTaskDelReq(OS_PRIO_SELF) == OS_ERR_TASK_DEL_REQ){
					if (freefun){
						freefun();
					}
					OSTaskDel(OS_PRIO_SELF);
					return TLS_OS_SUCCESS;
				}
			}
		}
	}
	return TLS_OS_ERROR;
}

#endif
#if OS_TASK_SUSPEND_EN
/*
*********************************************************************************************************
*                                            SUSPEND A TASK
*
* Description: This function is called to suspend a task.
*
* Arguments  : task     is a pointer to the task
*
* Returns    : TLS_OS_SUCCESS               if the requested task is suspended
*              TLS_OS_ERROR
*
* Note       : You should use this function with great care.  If you suspend a task that is waiting for
*              an event (i.e. a message, a semaphore, a queue ...) you will prevent this task from
*              running when the event arrives.
*********************************************************************************************************
*/
 tls_os_status_t tls_os_task_suspend(tls_os_task_t *task)
{
    INT8U error;
    tls_os_status_t os_status;

    error = OSTaskSuspend((INT8U)task->prio);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = (tls_os_status_t)error;

    return os_status;
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
*              	TLS_OS_ERROR
*
*********************************************************************************************************
*/
 tls_os_status_t tls_os_task_resume(tls_os_task_t *task)
{
    INT8U error;
    tls_os_status_t os_status;

    error = OSTaskResume((INT8U)task->prio);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = (tls_os_status_t)error;

    return os_status;
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
#if OS_MUTEX_EN
 tls_os_status_t tls_os_mutex_create(INT8U prio,
        tls_os_muext_t **mutex)
{
    INT8U error;
    tls_os_status_t os_status;

    *mutex = OSMutexCreate(prio, &error);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = (tls_os_status_t)error;

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
    INT8U error;
    tls_os_status_t os_status;

    OSMutexDel((OS_EVENT *)mutex, OS_DEL_NO_PEND, &error);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = (tls_os_status_t)error;

    return os_status;
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
 tls_os_status_t tls_os_mutex_acquire(tls_os_mutex_t *mutex,
        INT32U wait_time)
{
    INT8U error;
    tls_os_status_t os_status;

    OSMutexPend((OS_EVENT *)mutex, wait_time, &error);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = (tls_os_status_t)error;

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
    INT8U error;
    tls_os_status_t os_status;

    error = OSMutexPost((OS_EVENT *)mutex);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = (tls_os_status_t)error;

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

#if OS_SEM_EN
 tls_os_status_t tls_os_sem_create(tls_os_sem_t **sem, INT32U cnt)
{
    tls_os_status_t os_status;

    *sem = OSSemCreate(cnt);
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
#if OS_SEM_DEL_EN
 tls_os_status_t tls_os_sem_delete(tls_os_sem_t *sem)
{
    INT8U error;
    tls_os_status_t os_status;

    OSSemDel((OS_EVENT *)sem, OS_DEL_ALWAYS, &error);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = (tls_os_status_t)error;

    return os_status;
}
#endif

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
 tls_os_status_t tls_os_sem_acquire(tls_os_sem_t *sem,
        INT32U wait_time)
{
    INT8U error;
    tls_os_status_t os_status;

    OSSemPend((OS_EVENT *)sem, wait_time, &error);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else {
        os_status = (tls_os_status_t)error;
    }

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
    INT8U error;
    tls_os_status_t os_status;

    error = OSSemPost((OS_EVENT *)sem);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else {
        os_status = (tls_os_status_t)error;
    }

    return os_status;
}

/*
*********************************************************************************************************
*                                              SET SEMAPHORE
*
* Description: This function sets the semaphore count to the value specified as an argument.  Typically,
*              this value would be 0.
*
*              You would typically use this function when a semaphore is used as a signaling mechanism
*              and, you want to reset the count value.
*
* Arguments  : sem     is a pointer to the event control block
*
*              cnt        is the new value for the semaphore count.  You would pass 0 to reset the
*                         semaphore count.
*
* Returns    : TLS_OS_SUCCESS
*			TLS_OS_ERROR
*********************************************************************************************************
*/
#if OS_SEM_SET_EN
 tls_os_status_t tls_os_sem_set(tls_os_sem_t *sem, INT16U cnt)
{
    INT8U error;
    tls_os_status_t os_status;

	OSSemSet((OS_EVENT *)sem, cnt, &error);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else {
        os_status = (tls_os_status_t)error;
    }

    return os_status;
}

#endif
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
#if OS_Q_EN
 tls_os_status_t tls_os_queue_create(tls_os_queue_t **queue, INT32U queue_size)
{
	tls_os_status_t os_status;
	void *queue_start = NULL;
	INT32U queuesize = 10;

	if (0 == queue_size)
	{
		queuesize = queue_size;
	}

	queue_start = tls_mem_alloc(queuesize *(sizeof(void *)));
	if (NULL == queue_start)
	{
		return TLS_OS_ERROR;
	}

	*queue = OSQCreate((void **)queue_start, queuesize);
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
    INT8U error;
    tls_os_status_t os_status;
    OS_Q      *pq;

    pq = (OS_Q *)(((OS_EVENT *)queue)->OSEventPtr);
    if((pq->OSQStart) >=&__heap_base)		//如果没有从堆申请，不用释放
    {
        tls_mem_free(pq->OSQStart);
    }

    OSQDel((OS_EVENT *)queue, OS_DEL_ALWAYS, &error);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = (tls_os_status_t)error;

    return os_status;
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
        INT32U msg_size)
{
    INT8U error;
    tls_os_status_t os_status;

    error = OSQPost((OS_EVENT *)queue, msg);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else {
        os_status = (tls_os_status_t)error;
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
        INT32U msg_size,
        INT32U wait_time)
{
    INT8U error;
    tls_os_status_t os_status;

    *msg = OSQPend((OS_EVENT *)queue, wait_time, &error);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = (tls_os_status_t)error;

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
*
*********************************************************************************************************
*/

tls_os_status_t tls_os_queue_flush(tls_os_queue_t *queue)
{
	OSQFlush((OS_EVENT *)queue);
	return TLS_OS_SUCCESS;
}

#endif

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
#if OS_MBOX_EN
 tls_os_status_t tls_os_mailbox_create(tls_os_mailbox_t **mailbox,
        INT32U mailbox_size)
{
    tls_os_status_t os_status;
	void *mailbox_start = NULL;
	INT32U mbox_size = 10;

	if (mailbox_size)
	{
		mbox_size = mailbox_size;
	}

	mailbox_start = tls_mem_alloc(mbox_size * sizeof(void *));
	if (NULL == mailbox_start)
	{
		return TLS_OS_ERROR;
	}

    *mailbox = OSMboxCreate(mailbox_start);
    if (mailbox != NULL)
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
#if OS_MBOX_DEL_EN
 tls_os_status_t tls_os_mailbox_delete(tls_os_mailbox_t *mailbox)
{
    INT8U error;
    tls_os_status_t os_status;

    OSMboxDel((OS_EVENT *)mailbox, OS_DEL_NO_PEND, &error);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = (tls_os_status_t)error;

    return os_status;
}
#endif

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
    INT8U error;
    tls_os_status_t os_status;

    error = OSMboxPost((OS_EVENT *)mailbox, msg);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = (tls_os_status_t)error;

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
        INT32U wait_time)
{
    INT8U error;
    tls_os_status_t os_status;

    *msg = OSMboxPend((OS_EVENT *)mailbox, wait_time, &error);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = (tls_os_status_t)error;

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
    return OSTimeGet();
}

/**********************************************************************************************************
* Description: Disable interrupts by preserving the state of interrupts.
*
* Arguments  : none
*
* Returns    : cpu_sr
***********************************************************************************************************/
 u32 tls_os_set_critical(void)
{
    return OSCPUSaveSR();
}

/**********************************************************************************************************
* Description: Enable interrupts by preserving the state of interrupts.
*
* Arguments  : cpu_sr
*
* Returns    : none
***********************************************************************************************************/
 void tls_os_release_critical(INT32U cpu_sr)
{
    OSCPURestoreSR(cpu_sr);
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
        INT32U period,
        bool repeat,
        u8 *name)
{
    INT8U ucos_tmr_opt = OS_TMR_OPT_NONE;
    INT8U error;
    tls_os_status_t os_status;
    INT32U timer_ticks;

    timer_ticks = (period * OS_TMR_CFG_TICKS_PER_SEC) / OS_TICKS_PER_SEC;
    if (timer_ticks == 0)
        timer_ticks = 1;

    if (repeat)
        ucos_tmr_opt = OS_TMR_OPT_PERIODIC;

    *timer = OSTmrCreate(0, timer_ticks, ucos_tmr_opt, callback, callback_arg, name, &error);
    if (error == OS_ERR_NONE)
        os_status = TLS_OS_SUCCESS;
    else
        os_status = (tls_os_status_t)error;

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
    INT8U err;

    OSTmrStart((OS_TMR *)timer, &err);
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
    INT32U cpu_sr;
    INT32U timer_ticks;

    cpu_sr = tls_os_set_critical();
    timer_ticks = (ticks * OS_TMR_CFG_TICKS_PER_SEC) / OS_TICKS_PER_SEC;
    if (timer_ticks == 0)
        timer_ticks = 1;
    ((OS_TMR *)timer)->OSTmrDly = timer_ticks;
    tls_os_release_critical(cpu_sr);

    tls_os_timer_start((OS_TMR *)timer);
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
    INT8U err;

    OSTmrStop((OS_TMR *)timer, OS_TMR_OPT_NONE, NULL, &err);
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
	INT8U err;
	OSTmrDel((OS_TMR *)timer,&err);
	return err;
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
    OSTimeDly(ticks);
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
	OS_TCB      *ptcb;
	INT8U        prio;
	INT8U        str[3] [8] = {"PEND", "TO", "ABORT"};
    for (prio = 0u; prio <= OS_TASK_IDLE_PRIO; prio++) {
        ptcb = OSTCBPrioTbl[prio];
        if (ptcb != (OS_TCB *)0) {           /* Make sure task 'ptcb' is ...   */
            if (ptcb != OS_TCB_RESERVED) {   /* ... still valid.               */
#if OS_TASK_PROFILE_EN > 0u
                printf("task %d TCB Stack used %d bytes, %d(total), Base:0x%x, Status:%s  name %s\n",
                        prio,
                        ptcb->OSTCBStkCount, ptcb->OSTCBStkSize*sizeof(u32), ptcb->OSTCBStkBase, str[ptcb->OSTCBStat],
                        ptcb->OSTCBTaskName!=NULL?ptcb->OSTCBTaskName:"");
#endif
            }
        }
    }
	printf("\r\n");
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
	/* Initialize uC/OS-II   */
	OSInit();
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
#if OS_TASK_STAT_EN > 0
	/* Initialize uC/OS-II's statistics */
	OSStatInit();
#endif

	OSStart();
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
	return (int)OS_UCOSII;
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
	OSTimeTick();
}

#endif

