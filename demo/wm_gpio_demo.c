/*****************************************************************************
*
* File Name : wm_gpio_demo.c
*
* Description: gpio demo function
*
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd.
* All rights reserved.
*
* Author : dave
*
* Date : 2014-6-2
*****************************************************************************/
#include "wm_include.h"
#include "wm_demo.h"


#if DEMO_GPIO

#define DEMO_ISR_IO		WM_IO_PA_01
static void demo_gpio_isr_callback(void *context)
{
    u16 ret;

    ret = tls_get_gpio_irq_status(DEMO_ISR_IO);
    printf("\nint flag =%d\n", ret);
    if(ret)
    {
        tls_clr_gpio_irq_status(DEMO_ISR_IO);
        ret = tls_gpio_read(DEMO_ISR_IO);
        printf("\nafter int io =%d\n", ret);
    }
}

//gpio usage
int gpio_demo(void)
{
    enum tls_io_name gpio_pin;
    u16 ret;

    //use GPIOB13, GPIOB14 as test pin
    for(gpio_pin = WM_IO_PB_13; gpio_pin < WM_IO_PB_15; gpio_pin ++)
    {
        tls_gpio_cfg(gpio_pin, WM_GPIO_DIR_INPUT, WM_GPIO_ATTR_FLOATING);
        ret = tls_gpio_read(gpio_pin);	/*read default state*/
        printf("\ngpio%c[%d] default value==[%d]\n", (gpio_pin > WM_IO_PB_00) ? 'B' : 'A', gpio_pin - WM_IO_PB_00, ret);

        tls_gpio_cfg(gpio_pin, WM_GPIO_DIR_OUTPUT, WM_GPIO_ATTR_FLOATING);
        tls_gpio_write(gpio_pin, 1);			/*Output Hight during floating*/
        ret = tls_gpio_read(gpio_pin);
        printf("\ngpio%c[%d] floating high value==[%d]\n", (gpio_pin > WM_IO_PB_00) ? 'B' : 'A', gpio_pin - WM_IO_PB_00, ret);

        tls_gpio_cfg(gpio_pin, WM_GPIO_DIR_OUTPUT, WM_GPIO_ATTR_FLOATING);
        tls_gpio_write(gpio_pin, 0);			/*Output Low during floating*/
        ret = tls_gpio_read(gpio_pin);
        printf("\ngpio%c[%d] floating low value==[%d]\n", (gpio_pin > WM_IO_PB_00) ? 'B' : 'A', gpio_pin - WM_IO_PB_00, ret);

        tls_gpio_cfg(gpio_pin, WM_GPIO_DIR_OUTPUT, WM_GPIO_ATTR_PULLHIGH);
        tls_gpio_write(gpio_pin, 1);			/*Output Hight during pull-up*/
        ret = tls_gpio_read(gpio_pin);
        printf("\ngpio%c[%d] pullhigh high value==[%d]\n", (gpio_pin > WM_IO_PB_00) ? 'B' : 'A', gpio_pin - WM_IO_PB_00, ret);

        tls_gpio_cfg(gpio_pin, WM_GPIO_DIR_OUTPUT, WM_GPIO_ATTR_PULLHIGH);
        tls_gpio_write(gpio_pin, 0);			/*Output Low during pull-up*/
        ret = tls_gpio_read(gpio_pin);
        printf("\ngpio%c[%d] pullhigh low value==[%d]\n", (gpio_pin >= WM_IO_PB_00) ? 'B' : 'A', gpio_pin - WM_IO_PB_00, ret);

    }

    return WM_SUCCESS;
}


int gpio_isr_test(void)
{
    enum tls_io_name gpio_pin;

    gpio_pin = DEMO_ISR_IO;

    //GPIO Interrupt test
    tls_gpio_cfg(gpio_pin, WM_GPIO_DIR_INPUT, WM_GPIO_ATTR_PULLHIGH);
    tls_gpio_isr_register(gpio_pin, demo_gpio_isr_callback, NULL);
    tls_gpio_irq_enable(gpio_pin, WM_GPIO_IRQ_TRIG_RISING_EDGE);
    printf("\ntest gpio %d rising isr\n", gpio_pin);
    return WM_SUCCESS;
}

#endif
