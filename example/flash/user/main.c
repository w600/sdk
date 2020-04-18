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
#include "wm_webserver.h"

//读取某一个扇区的内容
//在指定位置写入数据
//再次读取该位置数据

#define FLASH_TEST_ADDR     0xF0000

#define FLASH_TEST_LENGTH   100

void pre_gpio_config()
{
	
}

static void read_data(void)
{
    u8 buf[100];
    tls_fls_read(FLASH_TEST_ADDR, (u8 *)buf, FLASH_TEST_LENGTH);
    for(int i=0; i< FLASH_TEST_LENGTH; i++)
    {
        printf("%02x ", buf[i]);
    }
    printf("\r\n");
}

static void write_data(void)
{
    u8 buf[100];

    // tls_fls_erase(FLASH_TEST_ADDR/0x1000);    /* tls_fls_write will auto erase the sector */

    for(int i=0; i< FLASH_TEST_LENGTH; i++)
    {
        buf[i] = i;
    }
    tls_fls_write(FLASH_TEST_ADDR, (u8 *)buf, FLASH_TEST_LENGTH);
}

void UserMain(void)
{
    printf("\r\nw600 flash example, compile @%s %s\r\n", __DATE__, __TIME__);
    printf("read old data :\r\n");
    read_data();
    printf("write new data ...\r\n");
    write_data();
    printf("read new data :\r\n");
    read_data();
}
