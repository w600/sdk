/**
 * @file    wm_master_spi_demo.c
 *
 * @brief   SPI master demo function
 *
 * @author  dave
 *
 * Copyright (c) 2015 Winner Microelectronics Co., Ltd.
 */

#include <string.h>
#include "wm_include.h"
#include "wm_demo.h"

#if DEMO_MASTER_SPI

#if 0
int test_spi_receive_data(char *buf)
{
    u8 cmd[4];
    u8 r_buf[4];
    u16 len = 0;

    memset(cmd, 0, sizeof(cmd));
    memset(r_buf, 0, sizeof(r_buf));
    cmd[0] = 0x06;
    tls_spi_read_with_cmd(cmd, 1, r_buf, 2);

    printf("\nrx status[%x][%x]\n", r_buf[0], r_buf[1]);

    if (r_buf[0] & 0x01)
    {
        cmd[0] = 0x02;
        tls_spi_read_with_cmd(cmd, 1, r_buf, 2);
        len |= r_buf[0];
        len |= r_buf[1] << 8;

        printf("\nrcv len=%d\n", len);
        if (len > 0)
        {
						/**这里最好判断一下数据长度是否4的整数倍，留4个byte通过0x10命令接收*/
            cmd[0] = 0;
            tls_spi_read_with_cmd(cmd, 1, (u8 *) buf, (len - 1) / 4 * 4);
            cmd[0] = 0x10;
            tls_spi_read_with_cmd(cmd, 1, (u8 *) (buf + (len - 1) / 4 * 4),
                                  len - (len - 1) / 4 * 4);
        }
    }   /**end of if (r_buf[0] & 0x01)	*/
    else
    {
        return WM_FAILED;
    }

    return WM_SUCCESS;
}

int test_spi_transfer_data(char *buf, int len)
{
    u8 cmd[4];
    u8 r_buf[4];
    int count = 0;

    memset(cmd, 0, sizeof(cmd));
    memset(r_buf, 0, sizeof(r_buf));
    cmd[0] = 0x03;
    while (1)
    {
        tls_spi_read_with_cmd(cmd, 1, r_buf, 2);
        if (r_buf[0] & 0x01)
            break;
        count++;
        if (count > 300)
        {
            printf("\ncan not tx data\n");
            return WM_FAILED;
        }
        tls_os_time_delay(1);
    }

    cmd[0] = 0x90;      /**cmd */
    tls_spi_write_with_cmd(cmd, 1, (u8 *) buf, len);

    return WM_SUCCESS;
}


#define TEST_SPI_BUF_SIZE		1024
int master_spi_demo(int clk, int type)
{
    char *tx_buf = NULL;
    char *rx_buf = NULL;
    int i;
    int ret;

    if (clk < 0)
    {
        clk = 1000000;          /* default 1M */
    }
    if (-1 == type)
    {
        type = 0;
    }

    if (0 == type)
    {
        tls_spi_trans_type(0);
    }
    else
    {
        tls_spi_trans_type(2);
    }

    tls_spi_setup(TLS_SPI_MODE_0, TLS_SPI_CS_LOW, clk);

    tx_buf = tls_mem_alloc(TEST_SPI_BUF_SIZE);
    if (NULL == tx_buf)
    {
        printf("\nspi_demo tx mem err\n");
        return WM_FAILED;
    }

    test_spi_receive_data(tx_buf);

    for (i = 0; i < TEST_SPI_BUF_SIZE; i++)
    {
        tx_buf[i] = rand();
    }

    ret = test_spi_transfer_data(tx_buf, TEST_SPI_BUF_SIZE);
    if (WM_FAILED == ret)
    {
        tls_mem_free(tx_buf);
        printf("\nspi tx err\n");
        return WM_FAILED;
    }
    tls_os_time_delay(50);
    rx_buf = tls_mem_alloc(TEST_SPI_BUF_SIZE);
    if (NULL == rx_buf)
    {
        tls_mem_free(tx_buf);
        printf("\nspi_demo rx mem err\n");
        return WM_FAILED;
    }

    test_spi_receive_data(rx_buf);

    if (0 == memcmp(tx_buf, rx_buf, TEST_SPI_BUF_SIZE))
    {
        printf("\nsuccess\n");
    }
    else
    {
        printf("\nfail\n");
    }
    tls_mem_free(tx_buf);
    tls_mem_free(rx_buf);

    return WM_SUCCESS;
}
#endif

#define SPI_DATA_LEN    1508
int master_spi_send_data(int clk, int type)
{
    int *p;
    int i;
	char *tx_buf = NULL;

    if (clk < 0)
    {
        clk = 1000000;          /* default 1M */
    }
    if (-1 == type)
    {
        type = 0;
    }

    if (0 == type)
    {
        tls_spi_trans_type(0);
    }
    else
    {
        tls_spi_trans_type(2);
    }

    tls_spi_setup(TLS_SPI_MODE_0, TLS_SPI_CS_LOW, clk);

    tx_buf = tls_mem_alloc(SPI_DATA_LEN);
    if (NULL == tx_buf)
    {
        printf("\nspi_demo tx mem err\n");
        return WM_FAILED;
    }	

    memset(tx_buf,  0, SPI_DATA_LEN);
    strcpy(tx_buf, "data");
    p = (int *)&tx_buf[4];
    *p = 1500;
    p ++;
    for(i = 0;i < (SPI_DATA_LEN-8)/4;i ++)    
    {
        *p = 0x12345678;
         p ++;
    }
    printf("SPI Master send 1500 byte, modeA, little endian\n");    

	tls_spi_write(tx_buf, SPI_DATA_LEN);

    tls_mem_free(tx_buf);
	
    printf("after send\n");
	return WM_SUCCESS;
}

int master_spi_recv_data(int clk, int type)
{
    int *p;
    int i;
    int len;
    int errorflag = 0;
	char *tx_buf = NULL;
	char *rx_buf = NULL;

    if (clk < 0)
    {
        clk = 1000000;          /* default 1M */
    }
    if (-1 == type)
    {
        type = 0;
    }

    if (0 == type)
    {
        tls_spi_trans_type(0);
    }
    else
    {
        tls_spi_trans_type(2);
    }

    tls_spi_setup(TLS_SPI_MODE_0, TLS_SPI_CS_LOW, clk);

	printf("SPI Master receive 1500 byte, modeA, little endian\n");

    tx_buf = tls_mem_alloc(SPI_DATA_LEN);
    if (NULL == tx_buf)
    {
        printf("\nspi_demo tx mem err\n");
        return WM_FAILED;
    }

    memset(tx_buf,  0, SPI_DATA_LEN);
    strcpy(tx_buf, "up-m");
	p = (int *)&tx_buf[4];
    *p = 1500;
	tls_spi_write(tx_buf, SPI_DATA_LEN);

	tls_os_time_delay(100);			

    rx_buf = tls_mem_alloc(SPI_DATA_LEN);
    if (NULL == rx_buf)
    {
    	tls_mem_free(tx_buf);
        printf("\nspi_demo rx mem err\n");
        return WM_FAILED;
    }
    
    memset(rx_buf, 0, SPI_DATA_LEN);
    tls_spi_read(rx_buf, SPI_DATA_LEN);
    p = (int *)&rx_buf[0];
    len = *p;
    p ++;
    for(i = 0;i < len/4;i ++)
    {
        if(*(p + i) != 0x12345678)
        {
            errorflag ++;
            printf("[%d]=[%x]\n",i,  *(p + i));
            if(errorflag > 100)
                break;
        }
    }
    if(errorflag > 0)
    {
        printf("rcv spi data error\r\n");
    }
    else
    {
        printf("rcv data len: %d\n", len);
    } 
	
    tls_mem_free(tx_buf);
    tls_mem_free(rx_buf);

	return WM_SUCCESS;
}



#endif



