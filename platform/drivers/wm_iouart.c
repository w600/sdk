/**
 * @file    wm_iouart.c
 *
 * @brief   IO uart Driver Module
 *
 * @author  dave
 *
 * Copyright (c) 2015 Winner Microelectronics Co., Ltd.
 */

#include <string.h>
#include "wm_iouart.h"
#include "wm_debug.h"
#include "wm_irq.h"
#include "wm_config.h"
#include "wm_mem.h"
#include "wm_gpio.h"
#include "wm_timer.h"


#if 1//TLS_CONFIG_IOUART

struct tls_io_uart io_uart;


#if !IO_UART_FOR_PRINT
void iouart0_timer_cb(void)
{
    int i = 0;
    static u8 ch = 0;

// if(io_uart.ifrx)
    {
        if (0 == io_uart.bitnum)    // 起始位
        {
            io_uart.bit[io_uart.bitcnt] = tls_gpio_read(IO_UART_RX);
			
            if (io_uart.bit[io_uart.bitcnt++] != 0)
            {
                io_uart.bitcnt = 0;
                tls_timer_stop(io_uart.timerid);
                tls_gpio_irq_enable(IO_UART_RX, WM_GPIO_IRQ_TRIG_LOW_LEVEL);
                return;
            }

//                  if(io_uart.bitcnt == IO_UART_ONEBITE_SAMPLE_NUM)
            {
                io_uart.bitcnt = 0;
                io_uart.bitnum ++;
                ch = 0;
            }
        }
        else if (io_uart.bitnum >= 1 && io_uart.bitnum <= 8)    // 数据位
        {
            io_uart.bit[io_uart.bitcnt++] = tls_gpio_read(IO_UART_RX);

            if(io_uart.bitcnt == IO_UART_ONEBITE_SAMPLE_NUM)
            {
                for(i=0; i<(IO_UART_ONEBITE_SAMPLE_NUM-1); i++)
                {
                    if(io_uart.bit[i] != io_uart.bit[i+1])
                    {
                        io_uart.bitcnt = 0;
                        io_uart.bitnum = 0;
                        tls_timer_stop(io_uart.timerid);
                        tls_gpio_irq_enable(IO_UART_RX, WM_GPIO_IRQ_TRIG_LOW_LEVEL);
                        return;						
                    }
                }
                if(io_uart.bit[0])
                {
                    ch |= (1 << (io_uart.bitnum - 1));
                }
                io_uart.bitnum ++;
                io_uart.bitcnt = 0;				
            }
        }
        else if (9 == io_uart.bitnum)   // 停止位
        {
            io_uart.bit[io_uart.bitcnt++] = tls_gpio_read(IO_UART_RX);
            if(io_uart.bitcnt == IO_UART_ONEBITE_SAMPLE_NUM)
            {
                if(io_uart.bit[i] != io_uart.bit[i+1])
                {
                    io_uart.bitcnt = 0;
                    io_uart.bitnum = 0;
                    tls_timer_stop(io_uart.timerid);
                    tls_gpio_irq_enable(IO_UART_RX, WM_GPIO_IRQ_TRIG_LOW_LEVEL);
                    return; 					
                }
            }
            if(io_uart.bit[0] == 0)
            {
                io_uart.bitcnt = 0;
                io_uart.bitnum = 0;
                tls_timer_stop(io_uart.timerid);
                tls_gpio_irq_enable(IO_UART_RX, WM_GPIO_IRQ_TRIG_LOW_LEVEL);
                return; 	
            }
            io_uart.recv.buf[io_uart.recv.head] = ch;
            io_uart.recv.head =(io_uart.recv.head + 1) & (TLS_IO_UART_RX_BUF_SIZE -1);			
            io_uart.bitnum = 0;
            io_uart.bitcnt = 0;			
            ch = 0;		
			io_uart.ifrx = 0;
            tls_timer_stop(io_uart.timerid);
            tls_gpio_irq_enable(IO_UART_RX, WM_GPIO_IRQ_TRIG_LOW_LEVEL);
        }
    }
}

void iouart0_gpio_isr_callback(void *context)
{
    u16 ret;

    ret = tls_get_gpio_irq_status(IO_UART_RX);
    if(ret)
    {
        tls_clr_gpio_irq_status(IO_UART_RX);
        ret = tls_gpio_read(IO_UART_RX);
        if(ret == 0)
        {
		    io_uart.ifrx = 1;
            tls_gpio_irq_disable(IO_UART_RX);
            tls_timer_start(io_uart.timerid);
        }
    }
}
#endif

void iouart_tx_byte(u8 datatoSend)
{
    u8 i, tmp;
    u32 cpu_sr = 0;

    cpu_sr = tls_os_set_critical(); // 发送一个byte的过程中不能被打断，否则可能会有错误码
/* Start bit */
    tls_gpio_write(IO_UART_TX, 0);
    tls_delay_via_timer(io_uart.timercnt+1, 0);

    for (i = 0; i < 8; i++)
    {
        tmp = (datatoSend >> i) & 0x01;

        if (tmp == 0)
        {
            tls_gpio_write(IO_UART_TX, 0);
        }
        else
        {
            tls_gpio_write(IO_UART_TX, 1);
        }

        tls_delay_via_timer(io_uart.timercnt+1, 0);
    }

    tls_gpio_write(IO_UART_TX, 1);
    tls_delay_via_timer(io_uart.timercnt+1, 0);

    tls_os_release_critical(cpu_sr);
}

int tls_iouart_init(int bandrate)
{
    char *bufrx;

    memset(&io_uart, 0, sizeof(struct tls_io_uart));
#if !IO_UART_FOR_PRINT
    bufrx = tls_mem_alloc(TLS_IO_UART_RX_BUF_SIZE);
    if (!bufrx)
        return WM_FAILED;
    memset(bufrx, 0, TLS_IO_UART_RX_BUF_SIZE);
    io_uart.recv.buf = (u8 *) bufrx;
    io_uart.recv.head = 0;
    io_uart.recv.tail = 0;
#endif

    tls_gpio_cfg(IO_UART_TX, WM_GPIO_DIR_OUTPUT, WM_GPIO_ATTR_FLOATING);
    tls_gpio_write(IO_UART_TX, 1);

    tls_gpio_cfg(IO_UART_RX, WM_GPIO_DIR_INPUT, WM_GPIO_ATTR_PULLHIGH);

  	tls_gpio_isr_register(IO_UART_RX, iouart0_gpio_isr_callback, NULL);
  	tls_gpio_irq_enable(IO_UART_RX, WM_GPIO_IRQ_TRIG_LOW_LEVEL);
	
    io_uart.timercnt = 1000000 / bandrate;
#if !IO_UART_FOR_PRINT
    struct tls_timer_cfg timer_cfg;
    timer_cfg.unit = TLS_TIMER_UNIT_US;
    timer_cfg.timeout = io_uart.timercnt/IO_UART_ONEBITE_SAMPLE_NUM;
    timer_cfg.is_repeat = 1;
    timer_cfg.callback = (tls_timer_irq_callback)iouart0_timer_cb;
    timer_cfg.arg = NULL;
    io_uart.timerid = tls_timer_create(&timer_cfg);
#endif
    return WM_SUCCESS;
}

int tls_iouart_destroy(void)
{
    tls_gpio_irq_disable(IO_UART_RX);
    tls_timer_destroy(io_uart.timerid);
    io_uart.timerid = 0xFF;
    tls_mem_free(io_uart.recv.buf);
    return WM_SUCCESS;
}

int tls_iouart_read(u8 * buf, int bufsize)
{
    int data_cnt, buflen, bufcopylen;

    if (NULL == buf)
        return WM_FAILED;

    data_cnt =
        CIRC_CNT(io_uart.recv.head, io_uart.recv.tail, TLS_IO_UART_RX_BUF_SIZE);

    if (data_cnt >= bufsize)
    {
        buflen = bufsize;
    }
    else
    {
        buflen = data_cnt;
    }
    if ((io_uart.recv.tail + buflen) > TLS_IO_UART_RX_BUF_SIZE)
    {
        bufcopylen = (TLS_IO_UART_RX_BUF_SIZE - io_uart.recv.tail);
        MEMCPY(buf, io_uart.recv.buf + io_uart.recv.tail, bufcopylen);
        MEMCPY(buf + bufcopylen, io_uart.recv.buf, buflen - bufcopylen);
    }
    else
    {
        MEMCPY(buf, io_uart.recv.buf + io_uart.recv.tail, buflen);
    }
    io_uart.recv.tail = (io_uart.recv.tail + buflen) & (TLS_IO_UART_RX_BUF_SIZE - 1);
    return buflen;
}


int tls_iouart_write(u8 * buf, int bufsize)
{
    if (NULL == buf || bufsize <= 0 || 1 == io_uart.ifrx)
        return WM_FAILED;

    io_uart.iftx = 1;

    while (bufsize)
    {
        iouart_tx_byte(*buf);
        bufsize--;
        buf++;
    }
	
    io_uart.iftx = 0;
	
    return WM_SUCCESS;
}

int tls_iouart_output_char(int ch)
{
	if(ch == '\n')
		iouart_tx_byte('\r');
	iouart_tx_byte((char)ch);

    return ch;
}

#endif //TLS_CONFIG_IOUART

