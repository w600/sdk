/**
 * @file    wm_slave_spi_demo.c
 *
 * @brief   SPI slave demo function
 *
 * @author  dave
 *
 * Copyright (c) 2015 Winner Microelectronics Co., Ltd.
 */

#include <string.h>
#include "wm_include.h"
#include "wm_demo.h"
#include "wm_mem.h"


#if DEMO_SLAVE_SPI
#if (TLS_CONFIG_HOSTIF && TLS_CONFIG_HS_SPI)
static void demo_sspi_task(void *sdata);

#define DEMO_SSPI_RX_BUF_SIZE    	1024
#define DEMO_SSPI_TAST_STK_SIZE		512
#define DEMO_MSG_SPI_RECV			1


/**
 * @typedef struct DEMO_SSPI
 */
typedef struct DEMO_SSPI{
    tls_os_queue_t *demo_sspi_q;
    char *rx_buf;
}DEMO_SSPI_ST;

static DEMO_SSPI_ST  *demo_sspi = NULL;
static OS_STK  demo_sspi_task_stk[DEMO_SSPI_TAST_STK_SIZE];


s16 test_hspi_rx_data(char *buf)
{
    MEMCPY(demo_sspi->rx_buf, buf, DEMO_SSPI_RX_BUF_SIZE);
    tls_os_queue_send(demo_sspi->demo_sspi_q,(void *)DEMO_MSG_SPI_RECV, 0);

    return WM_SUCCESS;
}


int slave_spi_demo(int type)
{
    if(type == 0)
    {
        type = HSPI_INTERFACE_SPI;
    }
    else
    {
        type = HSPI_INTERFACE_SDIO;
    }

    if (NULL == demo_sspi)
    {
        demo_sspi = tls_mem_alloc(sizeof(DEMO_SSPI_ST));
        if (NULL == demo_sspi)
        {
            goto _error;
        }
        memset(demo_sspi, 0, sizeof(DEMO_SSPI_ST));

        tls_os_queue_create(&(demo_sspi->demo_sspi_q), DEMO_QUEUE_SIZE);

        demo_sspi->rx_buf = tls_mem_alloc(DEMO_SSPI_RX_BUF_SIZE + 1);
        if(NULL == demo_sspi->rx_buf)
        {
            goto _error1;
        }

        tls_os_task_create(NULL, NULL,
			demo_sspi_task,
                    (void *)demo_sspi,
                    (void *)&demo_sspi_task_stk[0],        /** 任务栈的起始地址 */
                    DEMO_SSPI_TAST_STK_SIZE, 				/** 任务栈的大小     */
                    DEMO_SSPI_TASK_PRIO,
                    0);
    }


    tls_slave_spi_init();
    tls_set_high_speed_interface_type(type);
    tls_set_hspi_user_mode(1);
	/*注册函数需要放在tls_set_hspi_user_mode之后*/
    tls_hspi_rx_data_callback_register(test_hspi_rx_data);
    //tls_hspi_rx_cmd_callback_register(NULL);
    tls_hspi_tx_data_callback_register(NULL);

    return WM_SUCCESS;

_error1:
    tls_mem_free(demo_sspi);
    demo_sspi = NULL;

_error:
    return WM_FAILED;
}

static void demo_sspi_task(void *sdata)
{
    DEMO_SSPI_ST *sspi = (DEMO_SSPI_ST *)sdata;
    void *msg;

    for (;;)
    {
        tls_os_queue_receive(sspi->demo_sspi_q, (void **)&msg, 0, 0);
        printf("\n msg =%d\n",(int)msg);
        switch ((u32)msg)
       {
            case DEMO_MSG_SPI_RECV:
                tls_hspi_tx_data(sspi->rx_buf, DEMO_SSPI_RX_BUF_SIZE);
                break;
            default:
                break;
        }
    }
}


#endif
#endif
