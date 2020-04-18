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
#include "wm_adc.h"
#include "wm_gpio_afsel.h"

#define USER_TASK_STK_SIZE      512
#define USER_TASK_PRIO          32

static u32 user_task_stk[USER_TASK_STK_SIZE];


void pre_gpio_config()
{
	
}

void adc_task(void *data)
{
    char temperature[8] = {0};
    u32 temp;

    while(1)
    {
        temp = adc_temp();
        sprintf(temperature, "%d.%d", temp/1000, (temp%1000)/100);
        printf("tem: %s\r\n", temperature);
        tls_os_time_delay(HZ*2);
    }
}

void adc_init(void)
{
    wm_adc_config(0);
    adc_get_offset();
}

void UserMain(void)
{
    printf("\r\nw600 adc example, compile @%s %s\r\n", __DATE__, __TIME__);
    adc_init();
    /* create task */
    printf("task start ... \r\n");
    tls_os_task_create(NULL,
            "adc",
            adc_task,
            (void*) 0,
            (void*) &user_task_stk,  /* 任务栈的起始地址 */
            USER_TASK_STK_SIZE *sizeof(u32),  /* 任务栈的大小     */
            USER_TASK_PRIO,
            0);
}

