/*****************************************************************************
*
* File Name : wm_pwm_demo.c
*
* Description: pwm demo function
*
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd.
* All rights reserved.
*
* Author : dave
*
* Date : 2014-7-18
*****************************************************************************/
#include <string.h>
#include "wm_include.h"
#include "wm_pwm.h"
#include "wm_cpu.h"
#include "wm_io.h"
#include "wm_demo.h"
#include "wm_regs.h"
#include "wm_dma.h"
#include "wm_gpio_afsel.h"

#if DEMO_PWM
static int pwm_demo_multiplex_config(u8 channel)
{

    switch (channel)
    {
    case 0:
        wm_pwm1_config(WM_IO_PB_18);
        break;
    case 1:
        wm_pwm2_config(WM_IO_PB_17);
        break;
    case 2:
        wm_pwm3_config(WM_IO_PB_16);
        break;
    case 3:
        wm_pwm4_config(WM_IO_PB_15);
        break;
    case 4:
        wm_pwm5_config(WM_IO_PB_14);
        break;
    default:
        return -1;
    }
}

/*
static int pwm_demo_independent_mode(u8 channel,u32 freq, u8 duty, u8 num)
{
    pwm_init_param pwm_param;
    int ret=-1;
	tls_sys_clk sysclk;

	tls_sys_clk_get(&sysclk);

    memset(&pwm_param, 0, sizeof(pwm_init_param));
    pwm_param.period = 255;
    pwm_param.cnt_type = WM_PWM_CNT_TYPE_EDGE_ALIGN_OUT;
    pwm_param.loop_type = WM_PWM_LOOP_TYPE_LOOP;
    pwm_param.mode = WM_PWM_OUT_MODE_INDPT;
    pwm_param.inverse_en = DISABLE;
    pwm_param.pnum = num;
    pwm_param.pnum_int = DISABLE;
    pwm_param.duty = duty;
    pwm_param.channel = channel;
    pwm_param.clkdiv = sysclk.apbclk*UNIT_MHZ/256/freq;

    ret = tls_pwm_out_init(pwm_param);

    return ret;
}
*/

static int pwm_demo_allsyc_mode(u8 channel, u32 freq, u8 duty, u8 num)
{
    pwm_init_param pwm_param;
    int ret = -1;
    tls_sys_clk sysclk;

    tls_sys_clk_get(&sysclk);

    memset(&pwm_param, 0, sizeof(pwm_init_param));
    pwm_param.period = 255;
    pwm_param.cnt_type = WM_PWM_CNT_TYPE_EDGE_ALIGN_OUT;
    pwm_param.loop_type = WM_PWM_LOOP_TYPE_LOOP;
    pwm_param.mode = WM_PWM_OUT_MODE_ALLSYC;
    pwm_param.inverse_en = DISABLE;
    pwm_param.pnum = num;
    pwm_param.pnum_int = DISABLE;
    pwm_param.duty = duty;
    pwm_param.channel = channel;
    pwm_param.clkdiv = sysclk.apbclk * UNIT_MHZ / 256 / freq;

    ret = tls_pwm_out_init(pwm_param);

    return ret;
}

static int pwm_demo_2syc_mode(u8 channel, u32 freq, u8 duty, u8 num)
{
    pwm_init_param pwm_param;
    int ret = -1;
    tls_sys_clk sysclk;

    tls_sys_clk_get(&sysclk);

    memset(&pwm_param, 0, sizeof(pwm_init_param));
    pwm_param.period = 255;
    pwm_param.cnt_type = WM_PWM_CNT_TYPE_EDGE_ALIGN_OUT;
    pwm_param.loop_type = WM_PWM_LOOP_TYPE_LOOP;
    pwm_param.mode = WM_PWM_OUT_MODE_2SYC;
    pwm_param.inverse_en = DISABLE;
    pwm_param.pnum = num;
    pwm_param.pnum_int = DISABLE;
    pwm_param.duty = duty;
    pwm_param.channel = channel;
    pwm_param.clkdiv = sysclk.apbclk * UNIT_MHZ / 256 / freq;

    ret = tls_pwm_out_init(pwm_param);

    return ret;
}

static int pwm_demo_mc_mode(u8 channel, u32 freq, u8 duty, u8 num)
{
    pwm_init_param pwm_param;
    int ret = -1;
    tls_sys_clk sysclk;

    tls_sys_clk_get(&sysclk);

    memset(&pwm_param, 0, sizeof(pwm_init_param));
    pwm_param.period = 255;
    pwm_param.cnt_type = WM_PWM_CNT_TYPE_EDGE_ALIGN_OUT;
    pwm_param.loop_type = WM_PWM_LOOP_TYPE_LOOP;
    pwm_param.mode = WM_PWM_OUT_MODE_MC;
    pwm_param.inverse_en = DISABLE;
    pwm_param.pnum = num;
    pwm_param.pnum_int = DISABLE;
    pwm_param.duty = duty;
    pwm_param.channel = channel;
    pwm_param.clkdiv = sysclk.apbclk * UNIT_MHZ / 256 / freq;

    pwm_param.dten = ENABLE;
    pwm_param.dtclkdiv = 3;
    pwm_param.dtcnt = 255;

    ret = tls_pwm_out_init(pwm_param);

    return ret;
}

static int pwm_demo_break_mode(u8 channel, u32 freq, u8 duty)
{
    int ret = -1;

    ret = tls_pwm_brake_mode_config(channel, ENABLE, WM_PWM_BRAKE_OUT_HIGH);

    return ret;
}

static void pwm_isr_callback4(void)
{
    int fcount = 0, rcount = 0;
    int status = tls_reg_read32(HR_PWM_CAP2CTL);

    if (status & 0x80)
    {
        tls_reg_write32(HR_PWM_CAP2CTL, status | 0x18);
    }
    else
    {
        if (status & 0x10)
        {
            if ((status & 0xC0) == 0)
            {
                fcount = ((tls_reg_read32(HR_PWM_CAP2DAT) & 0xFFFF0000) >> 16);
            }
            tls_reg_write32(HR_PWM_CAP2CTL, status | 0x10);
            printf("fcount = %d\n", fcount);
        }
        if (status & 0x08)
        {
            if ((status & 0xA0) == 0)
            {
                rcount = (tls_reg_read32(HR_PWM_CAP2DAT) & 0x0000FFFF);
            }
            tls_reg_write32(HR_PWM_CAP2CTL, status | 0x08);
            printf("rcount = %d\n", rcount);
        }
    }
}

static void pwm_isr_callback0(void)
{
    int fcount = 0, rcount = 0;
    int status = tls_reg_read32(HR_PWM_INTSTS);

    if (status & 0x200)
    {
        tls_reg_write32(HR_PWM_INTSTS, status | 0x60);
    }
    else
    {
        if (status & 0x40)
        {
            if ((status & 0x300) == 0)
            {
                fcount = ((tls_reg_read32(HR_PWM_CAPDAT) & 0xFFFF0000) >> 16);
            }
            tls_reg_write32(HR_PWM_INTSTS, status | 0x40);
            printf("fcount = %d\n", fcount);
        }
        if (status & 0x00000020)
        {
            if ((status & 0x00000280) == 0)
            {
                rcount = (tls_reg_read32(HR_PWM_CAPDAT) & 0x0000FFFF);
            }
            tls_reg_write32(HR_PWM_INTSTS, status | 0x20);
            printf("rcount = %d\n", rcount);
        }
    }
}
u32 pwmDmaCap[100];

static void pwm_dma_callback(void)
{
    int i;

    for (i = 0; i < 100; i++)
    {
        printf("num:%d, pwmH:%d, pwmL:%d\n", i, (pwmDmaCap[i] >> 16), (pwmDmaCap[i] & 0x0000ffff));
    }
}

void pwm_capture_mode_int(u8 channel, u32 freq)
{
    tls_sys_clk sysclk;

    tls_sys_clk_get(&sysclk);

    pwm_demo_multiplex_config(channel);

    tls_pwm_stop(channel);

    if (channel == 0)
        tls_pwm_isr_register(pwm_isr_callback0);
    else
        tls_pwm_isr_register(pwm_isr_callback4);

    tls_pwm_cap_init(channel, sysclk.apbclk * UNIT_MHZ / 256 / freq, DISABLE, WM_PWM_CAP_RISING_FALLING_EDGE_INT);
    tls_pwm_start(channel);
}

void pwm_capture_mode_dma(u8 channel, u32 freq)
{
    u8 dmaCh;
    struct tls_dma_descriptor DmaDesc;
    tls_sys_clk sysclk;

    tls_sys_clk_get(&sysclk);

    memset(pwmDmaCap, 0, sizeof(pwmDmaCap) / sizeof(char));

    pwm_demo_multiplex_config(channel);
    tls_pwm_stop(channel);

    dmaCh = tls_dma_request(1, TLS_DMA_FLAGS_CHANNEL_SEL(TLS_DMA_SEL_PWM_CAP0) | TLS_DMA_FLAGS_HARD_MODE);
    DmaDesc.src_addr = HR_PWM_CAPDAT;
    DmaDesc.dest_addr = (unsigned int)pwmDmaCap;
    DmaDesc.dma_ctrl = TLS_DMA_DESC_CTRL_DEST_ADD_INC | TLS_DMA_DESC_CTRL_BURST_SIZE1 | TLS_DMA_DESC_CTRL_DATA_SIZE_WORD | TLS_DMA_DESC_CTRL_TOTAL_BYTES(400);
    DmaDesc.valid = TLS_DMA_DESC_VALID;
    DmaDesc.next = NULL;
    tls_dma_start(dmaCh, &DmaDesc, 0);
    tls_dma_irq_register(dmaCh, pwm_dma_callback, NULL, TLS_DMA_IRQ_TRANSFER_DONE);

    tls_pwm_cap_init(channel, sysclk.apbclk * UNIT_MHZ / 256 / freq, DISABLE, WM_PWM_CAP_DMA_INT);
    tls_pwm_start(channel);
}

/**
 * @brief          This function is used demonstrate pwm usage.
 *
 * @param[in]       channel    pwm channel, range from 0 to 4
 * @param[in]       freq       freq range from 3Hz~160kHz
 * @param[in]       duty       duty range from 0 to 255
 * @param[in]       mode       0:BRAKE, 1:ALLSYC, 2:2SYC, 3:MC, 4:INDPT
 * @param[in]       pnum       period num,range from 0 to 255
 *
 * @retval         WM_SUCCESS success
 * @retval         WM_FAILED  failed
 *
 * @note           For example, call this like this "pwm_demo(0,20,99,1,0);".
 */
int pwm_demo(u8 channel, u16 freq, u8 duty, u8 mode, u8 num)
{
    int ret = -1;

    printf("\r\nchannel:%d, freq:%d, duty:%d, mode:%d, num:%d\r\n", channel, freq, duty, mode, num);
    if (channel < 5)
    {
        pwm_demo_multiplex_config(channel);
        tls_pwm_stop(channel);
    }
    else
    {
        return WM_FAILED;
    }

    switch (mode)
    {
    case WM_PWM_OUT_MODE_INDPT:
        ret = tls_pwm_init(channel, freq, duty, num);
        if (ret != WM_SUCCESS)
            return ret;
        tls_pwm_start(channel);
        break;

    case WM_PWM_OUT_MODE_ALLSYC:
        ret = pwm_demo_allsyc_mode(channel, freq, duty, num);
        if (ret != WM_SUCCESS)
            return ret;
        tls_pwm_start(channel);
        break;

    case WM_PWM_OUT_MODE_2SYC:
        ret = pwm_demo_2syc_mode(channel, freq, duty, num);
        if (ret != WM_SUCCESS)
            return ret;
        tls_pwm_start(channel);
        break;

    case WM_PWM_OUT_MODE_MC:
        ret = pwm_demo_mc_mode(channel, freq, duty, num);
        if (ret != WM_SUCCESS)
            return ret;
        tls_pwm_start(channel);
        break;

    case WM_PWM_OUT_MODE_BRAKE:
        ret = pwm_demo_break_mode(channel, freq, duty);
        if (ret != WM_SUCCESS)
            return ret;
        tls_pwm_start(channel);
        break;

    default:
        break;
    }
    return WM_SUCCESS;
}
#endif
