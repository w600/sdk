/***************************************************************************** 
* 
* File Name : wm_adc_demo.c 
* 
* Description: adc demo function 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-8-18
*****************************************************************************/ 
#include "wm_include.h"
#include "wm_adc.h"
#include "wm_gpio_afsel.h"


#if DEMO_ADC

#define ADC_DEMO_CHANNEL   0

int adc_demo(void)
{
    char temperature[8] = {0};
    u32 temp;
    
    wm_adc_config(ADC_DEMO_CHANNEL);
    adc_get_offset();
    temp = adc_temp();
    sprintf(temperature, "%d.%d", temp/1000, (temp%1000)/100);
    printf("tem: %s", temperature);
    adc_get_inputVolt(ADC_DEMO_CHANNEL);
    adc_get_interVolt();
    
    return 0;
}

#endif





