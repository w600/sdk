/***************************************************************************** 
* 
* File Name : main.c
* 
* Description: main 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-6-14
*****************************************************************************/ 
#include "wm_include.h"

#define USER_TASK_STK_SIZE      512
#define USER_TASK_PRIO          32

static u32 user_task_stk[USER_TASK_STK_SIZE];

void pre_gpio_config()
{
	
}

void helloworld_task(void *data)
{
    while(1)
    {
        printf("hello world!\r\n");
    //    tls_os_time_delay(1000/portTICK_RATE_MS);
        tls_os_time_delay(HZ);
    }
}

void UserMain(void)
{
    printf("\r\nw600 hello world example, compile @%s %s\r\n", __DATE__, __TIME__);
    /* create task */
    tls_os_task_create(NULL,
            "helloworld",
            helloworld_task,
            (void*) 0,
            (void*) &user_task_stk,  /* 任务栈的起始地址 */
            USER_TASK_STK_SIZE *sizeof(u32),  /* 任务栈的大小     */
            USER_TASK_PRIO,
            0);
}

