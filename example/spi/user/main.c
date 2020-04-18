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

u8 spi_select = 0;	//spi_0 or spi_1

void pre_gpio_config()
{
	wm_hspi_gpio_config(spi_select);
}

void UserMain(void)
{
	/* close low power mode */
	bool enable = FALSE;
	tls_param_get(TLS_PARAM_ID_PSM, &enable, TRUE);	
	if (enable != FALSE)
	{
	    enable = FALSE;
	    tls_param_set(TLS_PARAM_ID_PSM, &enable, TRUE);	  
	}

    tls_watchdog_init(5*1000*1000);
    //let PORTM=2
	u8 mode = 2;
	tls_param_get(TLS_PARAM_ID_USRINTF, &mode, TRUE);	
	if (mode != 2)
	{
	    mode = 2;
	    tls_param_set(TLS_PARAM_ID_USRINTF, &mode, TRUE);	  
	}

    printf("\r\nw600 spi%d firmware, compile@%s %s\r\n", spi_select,  __DATE__, __TIME__);
	printf("ready\r\n");
}