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


#if TLS_CONFIG_TEM

#define ADC_DEMO_CHANNEL   0

static u8 adc_over_flag = 0;
static u16 adc_offset = 0;


static void adc_cb(u16 *buf, u16 len)
{
	adc_over_flag = 1;
}

static void waitForAdcDone(u8 *doneFlag, u8 blockTime)
{
    for(u8 i=0; i<blockTime; i++)
    {
        tls_os_time_delay(10);
        if(*doneFlag == 1)
            break;
    }
}

static u8 adc_get_offset(void)
{ 
	tls_adc_init(0, 0); 
	tls_adc_reference_sel(ADC_REFERENCE_INTERNAL);
	tls_adc_irq_register(ADC_INT_TYPE_ADC, adc_cb);
    
	adc_over_flag = 0;
	tls_adc_enable_calibration_buffer_offset(); //使能校准功能
    waitForAdcDone(&adc_over_flag, 10);
	adc_offset = tls_read_adc_result(); //获取adc转换结果
	tls_adc_stop(0);

	//printf("\r\noffset:%d", adc_offset);
    return adc_offset;
}

u32 adc_get_interTemp(void)
{
	u16 code2, code1, realCode;
    u32 tem;

    tls_adc_init(0, 0); 
	tls_adc_reference_sel(ADC_REFERENCE_INTERNAL);
	tls_adc_irq_register(ADC_INT_TYPE_ADC, adc_cb);

    adc_over_flag = 0;
    tls_adc_temp_offset_with_cpu(1); //code2
    waitForAdcDone(&adc_over_flag, 10);
    code2 = tls_read_adc_result(); 
    tls_adc_stop(0);
    signedToUnsignedData(&code2, &adc_offset);

    adc_over_flag = 0;
	tls_adc_temp_offset_with_cpu(0); //code1
    waitForAdcDone(&adc_over_flag, 10);
	code1 = tls_read_adc_result();
	tls_adc_stop(0);
    signedToUnsignedData(&code1, &adc_offset);

	realCode = ( (code1-code2)/2+8192 );
    //printf("\r\nTEMP:%.1f", realCode*0.12376-1294.58);
    //return (realCode*0.12376-1294.58);
    tem = realCode*124-1294580;
    return tem;
}

u16 adc_get_inputVolt(u8 channel)
{
    u16 average = 0;
    
    tls_adc_init(0, 0);
	tls_adc_reference_sel(ADC_REFERENCE_INTERNAL);
	tls_adc_irq_register(ADC_INT_TYPE_ADC, adc_cb);
	adc_over_flag = 0;
	tls_adc_start_with_cpu(channel);
    waitForAdcDone(&adc_over_flag, 10);
    average = tls_read_adc_result();
    tls_adc_stop(0);
    
    signedToUnsignedData(&average, &adc_offset);
    printf("\r\ninputVolt:%.2f", ((average-8192.0)/8192*2.25/1.2 + 1.584));
    return average;
}

u16 adc_get_interVolt(void)
{
	u16 voltValue;
	
	tls_adc_init(0, 0);
	tls_adc_reference_sel(ADC_REFERENCE_INTERNAL);
	tls_adc_irq_register(ADC_INT_TYPE_ADC, adc_cb);

	adc_over_flag = 0;
	tls_adc_voltage_start_with_cpu();
	waitForAdcDone(&adc_over_flag, 10);
	voltValue = tls_read_adc_result();
	tls_adc_stop(0);

    signedToUnsignedData(&voltValue, &adc_offset);
	float voltage = ( 1.214 - ((float)voltValue-8192)/8192*2.25/1.2 )*2;
	printf("\r\ninterVolt:%.2f", voltage);
    return voltValue;
}

u32 adc_temp(void)
{
    u32 tem;
    adc_get_offset();
    tem = adc_get_interTemp();
    return tem;
}

int adc_demo(void)
{
    wm_adc_config(ADC_DEMO_CHANNEL);
    adc_get_offset();
    adc_get_interTemp();
    adc_get_inputVolt(ADC_DEMO_CHANNEL);
    adc_get_interVolt();
    
    return 0;
}

#endif





