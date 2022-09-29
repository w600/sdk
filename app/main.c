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
extern void user_main();
void pre_gpio_config(void)
{
}


void UserMain(void)
{
	printf("\r\nw600 Compiled @%s %s\r\n", __DATE__, __TIME__);

#if DEMO_CONSOLE
	CreateDemoTask();
#else
	user_main();
#endif
//用户自己的task
}

