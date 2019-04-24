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

void blink_task(void *data)
{

    u8 gpio_level = 0;

    tls_gpio_cfg(WM_IO_PB_14, WM_GPIO_DIR_OUTPUT, WM_GPIO_ATTR_FLOATING);
    tls_gpio_cfg(WM_IO_PB_15, WM_GPIO_DIR_OUTPUT, WM_GPIO_ATTR_FLOATING);
    tls_gpio_cfg(WM_IO_PB_16, WM_GPIO_DIR_OUTPUT, WM_GPIO_ATTR_FLOATING);
    tls_gpio_cfg(WM_IO_PB_17, WM_GPIO_DIR_OUTPUT, WM_GPIO_ATTR_FLOATING);
    tls_gpio_cfg(WM_IO_PB_18, WM_GPIO_DIR_OUTPUT, WM_GPIO_ATTR_FLOATING);

    while(1)
    {
        tls_gpio_write(WM_IO_PB_14, gpio_level);
        tls_gpio_write(WM_IO_PB_15, gpio_level);
        tls_gpio_write(WM_IO_PB_16, gpio_level);
        tls_gpio_write(WM_IO_PB_17, gpio_level);
        tls_gpio_write(WM_IO_PB_18, gpio_level);

        tls_os_time_delay(HZ);
        gpio_level = !gpio_level;
    }
}

void UserMain(void)
{
    printf("\r\nw600 blink example, compile @%s %s\r\n", __DATE__, __TIME__);
	printf("blink task start ...\r\n");
    /* create task */
    tls_os_task_create(NULL,
            "blink",
            blink_task,
            (void*) 0,
            (void*) &user_task_stk,  /* 任务栈的起始地址 */
            USER_TASK_STK_SIZE *sizeof(u32),  /* 任务栈的大小     */
            USER_TASK_PRIO,
            0);
}

