/*
 * This file is part of the EasyLogger Library.
 *
 * Copyright (c) 2015, Armink, <armink.ztl@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * 'Software'), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Function: Portable interface for each platform.
 * Created on: 2015-04-28
 */

#include <elog.h>

#include <string.h>
#include "wm_include.h"
#include "task.h"

#define ELOG_USE_TASK_OUTPUT       1

#if ELOG_USE_TASK_OUTPUT

#define ELOG_QUEUE_SIZE            32
#define ELOG_TASK_PRIO             30
#define ELOG_TASK_SIZE             256

static tls_os_queue_t *elog_queue = NULL;

static OS_STK elog_task_stk[ELOG_TASK_SIZE];

#else /* ELOG_USE_TASK_OUTPUT */

static tls_os_sem_t *elog_lock = NULL;

#endif /* ELOG_USE_TASK_OUTPUT */


#if ELOG_USE_TASK_OUTPUT
static void elog_task_entry(void *data)
{
    int  ret;
    void *msg;

    for( ; ; )
	{
		ret = tls_os_queue_receive(elog_queue, (void **)&msg, 0, 0);
		if (TLS_OS_SUCCESS == ret)
		{
            printf("%s", (char *)msg);
            tls_mem_free(msg);
		}
	}
}
#endif

/**
 * EasyLogger port initialize
 *
 * @return result
 */
ElogErrCode elog_port_init(void) {
    ElogErrCode result = ELOG_NO_ERR;

    /* add your code here */
    int ret = TLS_OS_SUCCESS;

#if ELOG_USE_TASK_OUTPUT
    ret |= tls_os_queue_create(&elog_queue, ELOG_QUEUE_SIZE);

    ret |= tls_os_task_create(NULL, NULL, elog_task_entry,
                             (void *)0, (void *)elog_task_stk,
                             ELOG_TASK_SIZE * sizeof(u32),
                             ELOG_TASK_PRIO, 0);
#else
    ret |= tls_os_sem_create(&elog_lock, 1);
#endif

    if (TLS_OS_SUCCESS != ret)
    {
        result = ELOG_ERR;
        printf("elog init error\r\n");
    }

    return result;
}

/**
 * output log port interface
 *
 * @param log output of log
 * @param size log size
 */
void elog_port_output(const char *log, size_t size) {

    /* add your code here */
#if ELOG_USE_TASK_OUTPUT
    char *msg = tls_mem_alloc(size + 1);
    if (NULL == msg)
    {
        printf("elog malloc error: %.*s", (int)size, log);
        return;
    }
    memcpy(msg, log, size);
    msg[size] = '\0';
    int ret = tls_os_queue_send(elog_queue, (void *)msg, 0);
    if (TLS_OS_SUCCESS != ret)
    {
        tls_mem_free(msg);
        printf("elog send error: %.*s", (int)size, log);
    }
#else
    printf("%.*s", (int)size, log);
#endif
}

/**
 * output lock
 */
void elog_port_output_lock(void) {

    /* add your code here */
#if ELOG_USE_TASK_OUTPUT
    /* don't use lock */
#else
    tls_os_sem_acquire(elog_lock, 0);
#endif
}

/**
 * output unlock
 */
void elog_port_output_unlock(void) {

    /* add your code here */
#if ELOG_USE_TASK_OUTPUT
    /* don't use lock */
#else
    tls_os_sem_release(elog_lock);
#endif
}

/**
 * get current time interface
 *
 * @return current time
 */
const char *elog_port_get_time(void) {

    /* add your code here */
    static char elog_timestr[16];
    u32 ticks = tls_os_get_time();
    sprintf(elog_timestr, "%u.%02u", ticks / HZ, ticks % HZ);
    return elog_timestr;
}

/**
 * get current process name interface
 *
 * @return current process name
 */
const char *elog_port_get_p_info(void) {

    /* add your code here */
    return "";
}

/**
 * get current thread name interface
 *
 * @return current thread name
 */
const char *elog_port_get_t_info(void) {

    /* add your code here */
    const char * pcTaskName;
    const char * pcNoTask = "Task";
#if INCLUDE_pcTaskGetTaskName
    if( xTaskGetSchedulerState() != taskSCHEDULER_NOT_STARTED )
    {
        pcTaskName = (const char *)pcTaskGetTaskName( NULL );
    }
    else
#endif
    {
        pcTaskName = pcNoTask;
    }
    return pcTaskName;
}

void wm_log_init(void)
{
    /* initialize EasyLogger */
    elog_init();

    /* set EasyLogger log format */
    elog_set_fmt(ELOG_LVL_ASSERT, ELOG_FMT_ALL);
    elog_set_fmt(ELOG_LVL_ERROR, ELOG_FMT_LVL | ELOG_FMT_TAG | ELOG_FMT_TIME);
    elog_set_fmt(ELOG_LVL_WARN, ELOG_FMT_LVL | ELOG_FMT_TAG | ELOG_FMT_TIME);
    elog_set_fmt(ELOG_LVL_INFO, ELOG_FMT_LVL | ELOG_FMT_TAG | ELOG_FMT_TIME);
    elog_set_fmt(ELOG_LVL_DEBUG, ELOG_FMT_ALL & ~ELOG_FMT_FUNC);
    elog_set_fmt(ELOG_LVL_VERBOSE, ELOG_FMT_ALL & ~ELOG_FMT_FUNC);
#ifdef ELOG_COLOR_ENABLE
    elog_set_text_color_enabled(TRUE);
#endif
    /* start EasyLogger */
    elog_start();
}
