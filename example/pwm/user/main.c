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
#include "wm_pwm.h"
#include "wm_gpio_afsel.h"

#define USER_TASK_STK_SIZE      512
#define USER_TASK_PRIO          32

static u32 user_task_stk[USER_TASK_STK_SIZE];

void pre_gpio_config()
{
	
}

void pwm_task(void *data)
{
    u8 pwm_value = 0;
    u8 dir = 1; //0:down; 1: up;
    while(1)
    {
        if(dir)
        {
            if(pwm_value ++ < 255)
            {
                tls_pwm_duty_set(0, pwm_value);
                tls_pwm_duty_set(1, pwm_value);
                tls_pwm_duty_set(2, pwm_value);
                tls_pwm_duty_set(3, pwm_value);
                tls_pwm_duty_set(4, pwm_value);
            }
            else
            {
                pwm_value = 255;
                dir = 0;
            }
        }
        else
        {
            if(pwm_value-- > 0)
            {
                tls_pwm_duty_set(0, pwm_value);
                tls_pwm_duty_set(1, pwm_value);
                tls_pwm_duty_set(2, pwm_value);
                tls_pwm_duty_set(3, pwm_value);
                tls_pwm_duty_set(4, pwm_value);
            }
            else
            {
                pwm_value = 0;
                dir = 1;
            }
        }
        tls_os_time_delay(5);
    }
}

void pwm_init()
{
    wm_pwm1_config(WM_IO_PB_18);
    wm_pwm2_config(WM_IO_PB_17);
    wm_pwm3_config(WM_IO_PB_16);
    wm_pwm4_config(WM_IO_PB_15);
    wm_pwm5_config(WM_IO_PB_14);

    tls_pwm_init(0, 1000, 0, 0);
    tls_pwm_init(1, 1000, 0, 0);
    tls_pwm_init(2, 1000, 0, 0);
    tls_pwm_init(3, 1000, 0, 0);
    tls_pwm_init(4, 1000, 0, 0);

    tls_pwm_start(0);
    tls_pwm_start(1);
    tls_pwm_start(2);
    tls_pwm_start(3);
    tls_pwm_start(4);
}

void UserMain(void)
{
    printf("\r\nw600 pwm example, compile @%s %s\r\n", __DATE__, __TIME__);
    pwm_init();
	printf("pwm task start ...\r\n");
    /* create task */
    tls_os_task_create(NULL,
            "pwm",
            pwm_task,
            (void*) 0,
            (void*) &user_task_stk,  /* stk start addr */
            USER_TASK_STK_SIZE *sizeof(u32),  /* stk size     */
            USER_TASK_PRIO,
            0);
}

