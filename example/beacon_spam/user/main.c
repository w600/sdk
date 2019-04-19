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

uint8_t channel;
uint8_t count = 0;
int maxssids = 10; /* how much SSIDs we have */
char ssids[10][56] = {
                       ".01 新型创意广告机",
                       ".02 体积小巧，轻松携带",
                       ".03 走到哪，传到哪",
                       ".04 能宣传，能表白",
                       ".05 不要流量，无需联网",
                       ".06 轻松覆盖周边1W平米",
                       ".07 操作简单，使用方便",
                       ".08 拨打188xxxxxxxx订购",
                       ".09 可享受永久升级服务",
                       ".10 赶快行动吧！！！"
};

/* set the wifi channel  1~14*/
uint8_t channel_list[10] = { 1, 1, 1, 6, 6, 6, 6, 11, 11, 11};

//default mac ：74 68 69 6E 67 73
uint8_t mac_temp[6] = { 0x74, 0x68, 0x69, 0x6E, 0x67, 0x73 };

static tls_os_timer_t *beacon_spam_tmr = NULL;

uint8_t wifipkt[128] = { 0x80, 0x00, 0x00, 0x00,
                         /*4*/0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                         /*10*/0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                         /*16*/0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                         /*22*/0xc0, 0x6c,
                         /*24*/0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00,
                         /*32*/0x56, 0x00,
                         /*34*/0x01, 0x04,
                         /* SSID */
                         /*36*/0x00
};

uint8_t pktsuffix[] = {
                        0x01, 0x08, 0x82, 0x84,
                        0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, 0x03, 0x01,
                        0x04
};


void beacon_spam_init()
{
    //close station mode
    if (tls_wifi_get_listen_mode() != 0)
    {
        tls_wifi_set_listen_mode(0);
    }

    //set to station mode
    uint8_t wmode;
    int ret = tls_param_get(TLS_PARAM_ID_WPROTOCOL, (void *) &wmode, (bool) 0);
    if (ret != 0)
    {
        printf("tls_param_get ERROR !\r\n");
    }
    if (wmode != IEEE80211_MODE_INFRA)
    {
        wmode = IEEE80211_MODE_INFRA;
        ret = tls_param_set(TLS_PARAM_ID_WPROTOCOL, (void *) &wmode, (bool) 0);
    }

    //get chip mac
    uint8_t *mac = NULL;
    mac = wpa_supplicant_get_mac();
    if (mac != NULL)
    {
        if ((mac[0] != 0xff) && (mac[0] != 0x00))
        {
            memcpy(mac_temp, mac, 6);
            srand(mac_temp[5]);
            mac_temp[4] = rand()/256;
        }
        else
        {
            printf("tls_get_mac_addr: %02x%02x%02x%02x%02x%02x ! ! \r\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
    }
    else
    {
        printf("tls_get_mac_addr err !\r\n");
    }
}

static void beacon_spam_handle(void *ptmr, void *parg)
{
    static uint8_t rnd = 0;
    uint8_t i = 0;

    wifipkt[10] = wifipkt[16] = mac_temp[0];
    wifipkt[11] = wifipkt[17] = mac_temp[1];
    wifipkt[12] = wifipkt[18] = mac_temp[2];
    wifipkt[13] = wifipkt[19] = mac_temp[3];
    wifipkt[14] = wifipkt[20] = mac_temp[4];
    wifipkt[15] = wifipkt[21] = rnd + 0x10;

//    printf("rnd: %d\r\n", rnd);
//    printf("MAC: %02X%02X%02X%02X%02X%02X\r\n", wifipkt[10], wifipkt[11], wifipkt[12], wifipkt[13], wifipkt[14], wifipkt[15]);
    count = 37;
    wifipkt[count++] = strlen(ssids[rnd]);

    for (i = 0; i < strlen(ssids[rnd]); i++)
    {
        wifipkt[count++] = ssids[rnd][i];
    }

    for (i = 0; i < sizeof(pktsuffix); i++)
    {
        wifipkt[count++] = pktsuffix[i];
    }

    channel = channel_list[rnd];
    tls_wifi_change_chanel(channel - 1);

    wifipkt[count - 1] = channel;
    int ret = tls_wifi_send_data(NULL, wifipkt, count, NULL);
    if (ret != 0)
    {
        printf("send err : %d\r\n", ret);
    }

    if (++rnd >= maxssids)
        rnd = 0;
}

void UserMain(void)
{
    printf("\r\nw600 beacon spam example, compile @%s %s\r\n", __DATE__, __TIME__);
    beacon_spam_init();
    printf("task start ... \r\n");
    int err = tls_os_timer_create(&beacon_spam_tmr,
        beacon_spam_handle,
        (void *) 0,
        HZ / 100, /* 10 ms */
        TRUE,
        NULL);

    if (!err)
        tls_os_timer_start(beacon_spam_tmr);
    else
        printf("task start error !!!\r\n");

}
