/*****************************************************************************
*
* File Name : wm_log_demo.c
*
* Description: log demo function
*
* Copyright (c) 2015 Winner Micro Electronic Design Co., Ltd.
* All rights reserved.
*
* Author : LiLimin
*
* Date : 2015-3-24
*****************************************************************************/
#include "wm_include.h"

#if DEMO_LOG

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG     "Demo"
#include "wm_log.h"

#define LOG_DEMO_TASK_PRIO             38
#define LOG_DEMO_TASK_SIZE             256
#define LOG_DEMO_QUEUE_SIZE            4

static bool log_demo_inited = FALSE;
static OS_STK log_demo_task_stk[LOG_DEMO_TASK_SIZE];

static u8 log_demo_dump_buf[256] = {0};

static void log_demo_loop(void)
{
    int i = 0;

    for (i = 0; i < sizeof(log_demo_dump_buf); i++)
    {
        log_demo_dump_buf[i] = i;
    }

    while (TRUE)
    {
        wm_log_assert("Hello W60X!");
        wm_log_error("Hello W60X!");
        wm_log_warn("Hello W60X!");
        wm_log_info("Hello W60X!");
        wm_log_debug("Hello W60X!");
        wm_log_verbose("Hello W60X!");
        wm_log_raw("Hello W60X!\r\n");
        wm_log_dump("test", 16, log_demo_dump_buf, sizeof(log_demo_dump_buf));
        tls_os_time_delay(5 * HZ);
    }
}

static void log_demo_task(void *p)
{
    wm_log_init();

    log_demo_loop();
}

int log_demo(void)
{
    if (!log_demo_inited)
    {
        tls_os_task_create(NULL, NULL, log_demo_task,
                           NULL, (void *)log_demo_task_stk,
                           LOG_DEMO_TASK_SIZE * sizeof(u32),
                           LOG_DEMO_TASK_PRIO, 0);

        log_demo_inited = TRUE;
    }

    return WM_SUCCESS;
}

#endif

