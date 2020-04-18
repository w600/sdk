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
#include "wm_timer.h"

static u8 timer_id = 0;

void pre_gpio_config()
{
	
}

static void blink_timer_cb(u8 *arg)
{
    static u8 gpio_level = 0;
    static u8 cnt = 0;
    tls_gpio_write(WM_IO_PB_14, gpio_level);
    tls_gpio_write(WM_IO_PB_15, gpio_level);
    tls_gpio_write(WM_IO_PB_16, gpio_level);
    tls_gpio_write(WM_IO_PB_17, gpio_level);
    tls_gpio_write(WM_IO_PB_18, gpio_level);
    gpio_level = !gpio_level;
    if(cnt++ >= 100)
    {
        printf("blink timer stop\r\n");	
        tls_timer_stop(timer_id); // 如果该定时器后续还需要使用则不要销毁，不再使用
                                  // 则需要销毁，否则重复申请TIMER会失败
    }
}

static void blink_timer_init(void)
{
	struct tls_timer_cfg timer_cfg;
	
	timer_cfg.unit = TLS_TIMER_UNIT_MS;
	timer_cfg.timeout = 1000;   //500毫秒变化一次
	timer_cfg.is_repeat = 1;
	timer_cfg.callback = blink_timer_cb;
	timer_cfg.arg = NULL;
    
	timer_id = tls_timer_create(&timer_cfg);
	tls_timer_start(timer_id);
}

static void led_init(void)
{
    tls_gpio_cfg(WM_IO_PB_14, WM_GPIO_DIR_OUTPUT, WM_GPIO_ATTR_FLOATING);
    tls_gpio_cfg(WM_IO_PB_15, WM_GPIO_DIR_OUTPUT, WM_GPIO_ATTR_FLOATING);
    tls_gpio_cfg(WM_IO_PB_16, WM_GPIO_DIR_OUTPUT, WM_GPIO_ATTR_FLOATING);
    tls_gpio_cfg(WM_IO_PB_17, WM_GPIO_DIR_OUTPUT, WM_GPIO_ATTR_FLOATING);
    tls_gpio_cfg(WM_IO_PB_18, WM_GPIO_DIR_OUTPUT, WM_GPIO_ATTR_FLOATING);
}

void UserMain(void)
{
    printf("\r\nw600 blink timer example, compile @%s %s\r\n", __DATE__, __TIME__);
    led_init();
	printf("blink timer start ...\r\n");	
    blink_timer_init();
}
