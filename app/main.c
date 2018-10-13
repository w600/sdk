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


void UserMain(void)
{
	printf("\n user task\n");
	unsigned char power_mode = 0;
    tls_param_get(TLS_PARAM_ID_PSM, (void *)&power_mode, (bool)1);
    printf("power_mode: %d\r\n", power_mode);
    if(power_mode == 0)
    {
        printf("open low power mode\r\n");
        power_mode = 1;
        tls_param_set(TLS_PARAM_ID_PSM, (void *)&power_mode, (bool)1);
    }

#if DEMO_CONSOLE
	CreateDemoTask();
#endif
//用户自己的task
}

