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
#include "misc.h"
#include "wm_ieee80211.h"

#define DATA_LENGTH           112

static void sniffer_callback(struct ieee80211_hdr *hdr, u32 data_len, struct tls_wifi_ext_t *ext);
static void printDataSpan(uint16_t start, uint16_t size, uint8_t* data);
static uint8_t _current_channel = 1;

void pre_gpio_config()
{
	
}

static void wifi_set_channel(uint8_t chan)
{
    if(chan > 14) chan = 14;
    if(chan < 1) chan = 1;
//    printf("set channel: %d\r\n", chan);
    tls_wifi_change_chanel(chan -1);
    _current_channel = chan;
    return;
}

static void printDataSpan(uint16_t start, uint16_t size, uint8_t* data)
{
    for (uint16_t i = start; i < DATA_LENGTH && i < start + size; i++)
    {
        printf("%c", data[i]);
    }
}

static tls_os_timer_t *sniffer_timer = NULL;

static void sniffer_callback(struct ieee80211_hdr *hdr, u32 data_len, struct tls_wifi_ext_t *ext)
{
    if((ieee80211_is_mgmt(hdr->frame_control) != 0))
    {
        static u8 last_sa_addr_data[6] = {0};
        static u8 last_da_addr_data[6] = {0};
        u8 *curr_sa_addr_data = NULL;
        u8 *curr_da_addr_data = NULL;

        u8 data_diff = FALSE;

        char addr[] = "00:00:00:00:00:00";
        curr_sa_addr_data = ieee80211_get_SA(hdr);
        curr_da_addr_data = ieee80211_get_DA(hdr);

        for(int i=0; i< 6; i++)
        {
            if(*(curr_sa_addr_data + i) != *(last_sa_addr_data +i))
            {
                data_diff = TRUE;
                break;
            }

            if(*(curr_da_addr_data + i) != *(last_da_addr_data +i))
            {
                data_diff = TRUE;
                break;
            }
        }

        if(data_diff && ((hdr->frame_control & IEEE80211_FCTL_RETRY) == 0))
        {
            memcpy((u8 *)last_sa_addr_data, curr_sa_addr_data, 6);
            memcpy((u8 *)last_da_addr_data, curr_da_addr_data, 6);

            sprintf(addr, "%02X:%02X:%02X:%02X:%02X:%02X", *curr_sa_addr_data, *(curr_sa_addr_data+1), *(curr_sa_addr_data+2), *(curr_sa_addr_data+3), *(curr_sa_addr_data+4), *(curr_sa_addr_data+5));
            printf("%s|", addr);
            sprintf(addr, "%02X:%02X:%02X:%02X:%02X:%02X", *curr_da_addr_data, *(curr_da_addr_data+1), *(curr_da_addr_data+2), *(curr_da_addr_data+3), *(curr_da_addr_data+4), *(curr_da_addr_data+5));
            printf("%s|",addr);
            printf("%02d|", _current_channel);
            printf("TYPE:%02X|", hdr->frame_control & IEEE80211_FCTL_FTYPE);
            printf("SUB:%02X|", hdr->frame_control & IEEE80211_FCTL_STYPE);
//            printf("RET:%02X|", hdr->frame_control & IEEE80211_FCTL_RETRY);
            printf("RSSI:%03d", ext->rssi-0x100);
            printf("\r\n");
        }
    }
}

void sniffer_init()
{
    uint8_t wmode;

    //close sniffer mode
    if (tls_wifi_get_listen_mode() != 0)
    {
        printf(" close sniffer mode !\r\n");
        tls_wifi_set_listen_mode(0);
    }

    // set to station mode
    int ret = tls_param_get(TLS_PARAM_ID_WPROTOCOL, (void *) &wmode, (bool) 0);
    if (ret != 0)
    {
        printf("tls_param_get ERROR !");
        return;
    }
    if (wmode != IEEE80211_MODE_INFRA)
    {
        wmode = IEEE80211_MODE_INFRA;
        ret = tls_param_set(TLS_PARAM_ID_WPROTOCOL, (void *) &wmode, (bool) 0);
    }
    NVIC_SystemLPConfig(NVIC_LP_SLEEPDEEP, DISABLE);

    // close wifi power save
    tls_wifi_set_psflag(0, 0);

    extern int tls_wl_if_ps(int wake_up);

    tls_wl_if_ps(1);

    wifi_set_channel(1);

    //open listen mode
    if (tls_wifi_get_listen_mode() == 0)
    {
        tls_wifi_set_listen_mode(1);
    }
    //register the sinffer callback
//    tls_wifi_data_recv_cb_register((tls_wifi_data_recv_callback) sniffer_callback);
    tls_wifi_data_ext_recv_cb_register((tls_wifi_data_ext_recv_callback) sniffer_callback);
}

static void sniffer_timer_handle(void *ptmr, void *parg)
{
    uint8_t new_channel = _current_channel + 1;
    if (new_channel > 14)
    {
        new_channel = 1;
    }
    wifi_set_channel(new_channel);
}

void UserMain(void)
{
    printf("\r\nw600 sniffer example, compile @%s %s\r\n", __DATE__, __TIME__);

    sniffer_init();
    printf("task start ... \r\n");

    //start timer
    int err = tls_os_timer_create(&sniffer_timer,
        sniffer_timer_handle,
        (void *) 0,
        HZ*3,
        TRUE,
        NULL);

    if (!err)
        tls_os_timer_start(sniffer_timer);
    else
        printf("task start error !!!\r\n");
}
