/**************************************************************************
 * File Name                    : wm_wifi_oneshot.c
 * Author                       : WinnerMicro
 * Version                      :
 * Date                         : 05/30/2014
 * Description                  : Wifi one shot sample(UDP, PROBEREUEST)
 *
 * Copyright (C) 2014 Beijing Winner Micro Electronics Co.,Ltd.
 * All rights reserved.
 *
 ***************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wm_include.h"
#include "wm_mem.h"
#include "wm_type_def.h"
#if (GCC_COMPILE == 1)
#include "wm_ieee80211_gcc.h"
#else
#include "wm_ieee80211.h"
#endif
#include "wm_wifi.h"
#include "wm_wifi_oneshot.h"
#include "utils.h"
#include "wm_params.h"
#include "wm_osal.h"
#include "tls_wireless.h"
#include "wm_wl_task.h"
#include "wm_webserver.h"


#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define ONESHOT_DEBUG 0
#if ONESHOT_DEBUG
#define ONESHOT_DBG printf
#else
#define ONESHOT_DBG(s, ...)
#endif

#define ONESHOT_INFO 1
#if ONESHOT_INFO
#define ONESHOT_INF printf
#else
#define ONESHOT_INF(s, ...)
#endif

u32 oneshottime = 0;

volatile u8 guconeshotflag = 0;

/*Networking necessary information*/
volatile u8 gucssidokflag = 0;
u8 gucssidData[33] = {0};

static u8 gucbssidData[ETH_ALEN] = {0};
volatile u8 gucbssidokflag = 0;

volatile u8 gucpwdokflag = 0;
u8 gucpwdData[65] ={0};

static u8 gucCustomData[3][65] ={'\0'};

// Oneshot: 0 SoftAp: 1
static u8 gucConfigMode = 0;

static tls_wifi_oneshot_result_callback gpfResult = NULL;


#define ONESHOT_MSG_QUEUE_SIZE 32
tls_os_queue_t *oneshot_msg_q = NULL;

#define    ONESHOT_TASK_SIZE      1024

static OS_STK OneshotTaskStk[ONESHOT_TASK_SIZE];

u32 first_start_oneshot_flag = 0;
extern bool is_airkiss;

#if TLS_CONFIG_UDP_ONE_SHOT
#define TLS_ONESHOT_RESTART_TIME  5000*HZ/1000
#define TLS_ONESHOT_RETRY_TIME  10000*HZ/1000
#define TLS_ONESHOT_RECV_TIME   15000*HZ/1000
#define TLS_ONESHOT_SWITCH_TIMER_MAX (100*HZ/1000)
static tls_os_timer_t *gWifiSwitchChanTim = NULL;
static tls_os_timer_t *gWifiHandShakeTimOut = NULL;
static tls_os_timer_t *gWifiRecvTimOut = NULL;

#if (TLS_CONFIG_UDP_JD_ONESHOT || TLS_CONFIG_UDP_LSD_ONESHOT)
static u8 gucHandShakeOk = 0;
#endif

static u8 gSrcMac[ETH_ALEN] = {0,0,0,0,0,0};

#define HANDSHAKE_CNT 3
volatile u8 guchandshakeflag = 0;

#define TOTAL_CHAN_NUM 17
static u8 airwifichan[TOTAL_CHAN_NUM]={0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF, 0xF,0xF, 0xF};
static u8 airchantype[TOTAL_CHAN_NUM]={0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0, 0};
static u8 uctotalchannum = 0;

#if TLS_CONFIG_UDP_JD_ONESHOT
#define JD_VALID_DATA_OFFSET 8
#define TLS_UDP_JD_DATA_LEN 97
static u32 uljddatavalid[8] ={0,0,0,0,0,0,0,0};
static u8 *aujddata = NULL;
static u8 aujdDataLen[2] = {0xFF, 0xFF};/*SSID, PWD*/
static u8 ucjdataencodeMode = 0xFF;
static u8 jdhandshakecnt;
static u8 ucjdsyncode = 0x00;
#endif

#if TLS_CONFIG_UDP_LSD_ONESHOT
static u32 ullsddatavalid[8] ={0,0,0,0,0,0,0,0};
static u8 *aulsddata = NULL;
static u8 lsdhandshakecnt;
static u8 uclsddatalen = 0xFF;
static u8 uclsdsyncode = 0x64;
#endif
#endif

#if TLS_CONFIG_AP_MODE_ONESHOT
static u8 gucRawValid = 0;
static u8 *gaucRawData = NULL;

#define APSKT_MAX_ONESHOT_NUM (8)
#define APSKT_SSID_MAX_LEN (32)
#define ONESHOT_AP_NAME "softap"
#define SOCKET_SERVER_PORT 65532
#define SOCKET_RX_DATA_BUFF_LEN 255

struct tls_socket_desc *skt_descp = NULL;
typedef struct sock_recive{
    int socket_num;
	char *sock_rx_data;
	u8 sock_data_len;
}ST_Sock_Recive;
ST_Sock_Recive *sock_rx = NULL;
#endif

#if TLS_CONFIG_QQLINK_MODE_ONESHOT
extern bool tls_start_qq_link(void);
extern void tls_stop_qq_link(void);
extern void tls_qq_link_notify_hop(u32 channel);
extern void tls_process_qq_link_packet(const uint8_t *buff, uint32_t nlen);
#endif
extern void tls_wl_change_chanel(u32 chanid);
extern void tls_wl_change_channel_info(u32 chanid, u32 channel_type);
extern int tls_wifi_decode_new_oneshot_data(const u8 *encodeStr, u8 *outKey, u8 *outBssid, u8 *outSsid, u8 *outCustData);

#if (CONFIG_ONESHOT_MAC_FILTER || TLS_CONFIG_AP_MODE_ONESHOT || TLS_CONFIG_UDP_LSD_ONESHOT)
static __inline int tls_is_zero_ether_addr(const u8 *a)
{
	return !(a[0] | a[1] | a[2] | a[3] | a[4] | a[5]);
}
#endif

void tls_wifi_oneshot_result_cb_register(tls_wifi_oneshot_result_callback callback)
{
    gpfResult = callback;

    return;
}

void tls_wifi_get_oneshot_ssidpwd(u8 *ssid, u8 *pwd)
{
	if (ssid && (gucssidData[0] != '\0')){
		strcpy((char *)ssid, (char *)gucssidData);
	}

	if (pwd && (gucpwdData[0] != '\0')){
		strcpy((char *)pwd, (char *)gucpwdData);
	}
}

void tls_wifi_get_oneshot_customdata(u8 *data){
	if (guconeshotflag){
	  	if (data && (gucCustomData[0][0] != '\0')){
	  		strcpy((char *)data, (char *)gucCustomData[0]);
	  	}
	}else{
		gucCustomData[0][0]  = '\0';
	}
}
#if CONFIG_CONNECT_RANDOMTIME_AFTER_ONESHOT
extern int random_get_bytes(void *buf, size_t len);
extern int tls_get_mac_addr(u8 *mac);
u16 tls_oneshot_get_random_by_mac(void){
	u8 timeout = 50;
	u16 timeout1 = 50;
	u8 i = 0;
	u8 LoopCnt = 0;
	u8 mac_addr[6]={0,0,0,0,0,0};

   	tls_get_mac_addr(mac_addr);
	if (0 == mac_addr[5]){
		LoopCnt = 10;
	}else{
		LoopCnt = mac_addr[5];
	}

	for (i =0; i < LoopCnt; i++){
		if(random_get_bytes(&timeout, 1) == 0)
		{
			if (timeout < 10){
				timeout = 25;
			}
		}
	}

	timeout1 = timeout*2;

	return timeout1;
}
#endif


void tls_wifi_wait_disconnect(void)
{
//#if !CONFIG_UDP_ONE_SHOT
	struct tls_ethif *netif = NULL;

	netif = tls_netif_get_ethif();
	if (netif && (1 == netif->status)){
		tls_wifi_disconnect();
	}

	for(;;){
		netif = tls_netif_get_ethif();
		if (netif && (0 == netif->status)){
			tls_os_time_delay(50);
			break;
		}
		tls_os_time_delay(10);
	}
	//tls_os_time_delay(210);
//#endif
}

u8 tls_wifi_oneshot_connect_by_ssid_bssid(u8 *ssid, u8 *bssid, u8 *pwd)
{
    if (gpfResult)
        gpfResult(WM_WIFI_ONESHOT_TYPE_SSIDPWD);
#if TLS_CONFIG_AP_MODE_ONESHOT	
	if((1 == gucConfigMode)||(2 == gucConfigMode))
	{
		u8 wireless_protocol = IEEE80211_MODE_INFRA;

		tls_wifi_softap_destroy();
		tls_param_set(TLS_PARAM_ID_WPROTOCOL, (void*) &wireless_protocol, TRUE);
	}
	else
#endif	
	{	
		tls_netif_add_status_event(wm_oneshot_netif_status_event);
	}

	tls_wifi_set_oneshot_flag(0);

#if TLS_CONFIG_UDP_ONE_SHOT
	if (0 == gucConfigMode)
		tls_os_time_delay(TLS_ONESHOT_SWITCH_TIMER_MAX);
#endif

#if CONFIG_CONNECT_RANDOMTIME_AFTER_ONESHOT
	tls_os_time_delay(tls_oneshot_get_random_by_mac());
#endif

	return tls_wifi_connect_by_ssid_bssid(ssid, strlen((char *)ssid), bssid, pwd, (pwd == NULL) ? 0 : strlen((char *)pwd));
}
u8 tls_wifi_oneshot_connect_by_bssid(u8 *bssid, u8 *pwd)
{

    if (gpfResult)
        gpfResult(WM_WIFI_ONESHOT_TYPE_SSIDPWD);

#if TLS_CONFIG_AP_MODE_ONESHOT
	if((1 == gucConfigMode)||(2 == gucConfigMode))
	{
		u8 wireless_protocol = IEEE80211_MODE_INFRA;

		tls_wifi_softap_destroy();
		tls_param_set(TLS_PARAM_ID_WPROTOCOL, (void*) &wireless_protocol, TRUE);
	}else
#endif
	{
		tls_netif_add_status_event(wm_oneshot_netif_status_event);
	}

	tls_wifi_set_oneshot_flag(0);
#if CONFIG_CONNECT_RANDOMTIME_AFTER_ONESHOT
	tls_os_time_delay(tls_oneshot_get_random_by_mac());
#endif

#if TLS_CONFIG_UDP_ONE_SHOT
	if (0 == gucConfigMode)
		tls_os_time_delay(TLS_ONESHOT_SWITCH_TIMER_MAX);
#endif

	return tls_wifi_connect_by_bssid(bssid, pwd, (pwd == NULL) ? 0 : strlen((char *)pwd));
}

u8 tls_wifi_oneshot_connect(u8 *ssid, u8 *pwd)
{
    if (gpfResult)
        gpfResult(WM_WIFI_ONESHOT_TYPE_SSIDPWD);

#if TLS_CONFIG_AP_MODE_ONESHOT
	if((1 == gucConfigMode)||(2 == gucConfigMode))
	{
		u8 wireless_protocol = IEEE80211_MODE_INFRA;

		tls_wifi_softap_destroy();
		tls_param_set(TLS_PARAM_ID_WPROTOCOL, (void*) &wireless_protocol, TRUE);

		
	}else
#endif	
	{
		tls_netif_add_status_event(wm_oneshot_netif_status_event);
	}

	tls_wifi_set_oneshot_flag(0);
#if CONFIG_CONNECT_RANDOMTIME_AFTER_ONESHOT
	tls_os_time_delay(tls_oneshot_get_random_by_mac());
#endif

#if TLS_CONFIG_UDP_ONE_SHOT
	if (0 == gucConfigMode)
		tls_os_time_delay(TLS_ONESHOT_SWITCH_TIMER_MAX);
#endif

	return tls_wifi_connect(ssid, strlen((char *)ssid), pwd, (pwd==NULL) ? 0 : strlen((char *)pwd));
}


#if TLS_CONFIG_AP_MODE_ONESHOT
void tls_wifi_send_oneshotinfo(const u8 * ssid,u8 len, u32 send_cnt)
{
	int i = 0;
	int j = 0;
	u8 lenNum =0;
	u8 lenremain = 0;
	if (gaucRawData == NULL){
		gaucRawData = tls_mem_alloc(len+1);
	}

	if (gaucRawData){
		memcpy(gaucRawData, ssid, len);
		lenNum = len/APSKT_SSID_MAX_LEN;
		lenremain = len%APSKT_SSID_MAX_LEN;
		for (j = 0; j< send_cnt; j++){
			for (i = 0; i < lenNum; i++){
				tls_wifi_send_oneshotdata(NULL, (const u8 *)(&(gaucRawData[i*APSKT_SSID_MAX_LEN])), APSKT_SSID_MAX_LEN);
				tls_os_time_delay(10);
			}
			if (lenremain){
				tls_wifi_send_oneshotdata(NULL, (const u8 *)(&(gaucRawData[i*APSKT_SSID_MAX_LEN])), lenremain);
				tls_os_time_delay(10);
			}
		}
		tls_mem_free(gaucRawData);
		gaucRawData = NULL;
	}
}
#endif

u8 tls_wifi_decrypt_data(u8 *data){
	u16 datatype;
	u32 tagid = 0;
	u16 typelen[6]={0,0,0,0,0,0};
	volatile u16 rawlen = 0;
    u16 hdrlen = sizeof(struct ieee80211_hdr);
	int i = 0;
	int tmpLen = 0;
	u8 ret = 0;
	//u8 ucChanId = 0;


	//ucChanId = *(u16*)(data+hdrlen+4);/*Channel ID*/
	tagid = *(u16*)(data+hdrlen+6);/*TAG*/
	if (0xA55A == tagid){
		datatype = *(u16 *)(data+hdrlen+8); /*DataType*/
		tmpLen = hdrlen + 10;
		for (i = 0; i < 6; i++){
			if ((datatype>>i)&0x1){
				typelen[i] = *((u16*)(data+tmpLen));
				tmpLen += 2;
			}

		}
		rawlen = *((u16 *)(data+tmpLen));
		tmpLen += 2;

		gucssidokflag = 0;
		gucbssidokflag = 0;
		gucpwdokflag = 0;
		memset(gucssidData, 0, 33);
		memset(gucbssidData, 0, 6);
		memset(gucpwdData, 0, 65);
		for (i = 0; i < 6; i++){
			if ((datatype>>i)&0x1){
				if (i == 0){ /*PWD*/
					strncpy((char *)gucpwdData,(char *)(data+tmpLen), typelen[i]);
					ONESHOT_DBG("PWD:%s\n", gucpwdData);
					gucpwdokflag = 1;
					ret = 1;
				}else if (i == 1){/*BSSID*/
					memcpy((char *)gucbssidData,(char *)(data+tmpLen), typelen[i]);
					ONESHOT_DBG("gucbssidData:%x:%x:%x:%x:%x:%x\n", MAC2STR(gucbssidData));
					gucbssidokflag = 1;
					ret = 1;
				}else if (i == 2){/*SSID*/
					gucssidData[0] = '\0';
					memcpy((char *)gucssidData,(char *)(data+tmpLen), typelen[i]);
					ONESHOT_DBG("gucssidData:%s\r\n", gucssidData);
					gucssidokflag = 1;
					ret = 1;
				}else{/*3-5 USER DEF*/
					memcpy((char *)gucCustomData[i - 3], (char *)(data+tmpLen), typelen[i]);
					gucCustomData[i - 3][typelen[i]] = '\0';
					ret = 0;
					if (gpfResult)
					{
						gpfResult(WM_WIFI_ONESHOT_TYPE_CUSTOMDATA);
						tls_wifi_set_oneshot_flag(0);
				     }
				}
				tmpLen += typelen[i];
			}
		}
		if(1 == gucConfigMode)
		{
#if TLS_CONFIG_AP_MODE_ONESHOT
			if (ret && rawlen&&(gucRawValid==0)){
				gucRawValid = 1;
				tls_wifi_send_oneshotinfo((const u8 *)(data+tmpLen), rawlen, APSKT_MAX_ONESHOT_NUM);
			}
#endif
		}
	}
	return ret;
}


#if TLS_CONFIG_UDP_ONE_SHOT
static u8 *oneshot_bss = NULL;
#define ONESHOT_BSS_SIZE 4096

void tls_wifi_clear_oneshot_data(u8 iscleardata)
{
#if TLS_CONFIG_UDP_JD_ONESHOT
	jdhandshakecnt = 0;
	if (iscleardata)
	{
		memset(uljddatavalid, 0, 8);
		memset(aujdDataLen, 0xFF, 2);
		if(aujddata){
			memset(aujddata, 0, 128);
		}
	}
	ucjdataencodeMode = 0xFF;
#endif

#if TLS_CONFIG_UDP_LSD_ONESHOT
	lsdhandshakecnt = 0;
	if (iscleardata)
	{
		memset(ullsddatavalid, 0, 8);
		if (aulsddata){
			memset(aulsddata, 0, 256);
		}
	}
	uclsddatalen = 0xFF;
#endif
	gucbssidokflag = 0;
	gucssidokflag = 0;
	gucpwdokflag = 0;
}

#if CONFIG_ONESHOT_MAC_FILTER
//User should define the source mac address purposely.
static u8 gauSrcmac[ETH_ALEN]= {0xC4,0x07,0x2F,0x04,0x7A,0x69};
void tls_filter_module_srcmac_show(void){
	printf("num:%d\n", sizeof(gauSrcmac)/ETH_ALEN);
}

//only receive info from devices whose mac address is gauSrcmac
int tls_filter_module_srcmac(u8 *mac){
	int ret = 0;
	u8 localmac[6];

	if (0 == tls_is_zero_ether_addr(gauSrcmac)){
		tls_get_mac_addr((u8 *)(&localmac));
		if ((0 == memcmp(gauSrcmac, mac, ETH_ALEN))&&(0 != memcmp(localmac, mac, ETH_ALEN))){
			ret = 1;
			//break;
		}
	}else{
		ret = 1;
	}

	return ret;
}
#endif

#if (TLS_CONFIG_UDP_LSD_ONESHOT || TLS_CONFIG_UDP_JD_ONESHOT)

static __inline u8 tls_compare_ether_addr(const u8 *addr1, const u8 *addr2)
{
	return !((addr1[0] == addr2[0]) && (addr1[1] == addr2[1]) && (addr1[2] == addr2[2]) &&   \
		(addr1[3] == addr2[3]) && (addr1[4] == addr2[4]) && (addr1[5] == addr2[5]));
}


static __inline u8 tls_wifi_compare_mac_addr(u8 *macaddr){
	u8 tmpmacaddr[ETH_ALEN] = {0, 0,0,0,0,0};

	if (macaddr == NULL){
		return 0;
	}

	if (tls_compare_ether_addr(gSrcMac, tmpmacaddr) == 0){
		MEMCPY(gSrcMac, macaddr, ETH_ALEN);
		return 0;
	}

	if (tls_compare_ether_addr(gSrcMac, macaddr) == 0){
		return 1;
	}
	return 0;
}
#endif


static void wifi_change_chanel(u32 chanid, u8  bandwidth)
{
	tls_wl_change_channel_info(chanid, bandwidth);

#if TLS_CONFIG_QQLINK_MODE_ONESHOT
	tls_qq_link_notify_hop(chanid);
#endif
}

#if TLS_CONFIG_UDP_JD_ONESHOT
void tls_wifi_jd_set_syncode(u8 syncode){
	ucjdsyncode = syncode;
}
int tls_wifi_jd_check_condition(u8 *addr){
	/*multicast ip Addr range:239.118~239.121*/
	if ((0x01 != addr[0])||(0x00 != addr[1])||(0x5e != addr[2])){
		return -1;
	}

	if ((addr[3]<0x76)||(addr[3]>0x7A)){
		return -1;
	}
	if ((addr[4] == 0) || (addr[4] > (TLS_UDP_JD_DATA_LEN+6))){
		return -1;
	}
	return 0;
}

int tls_wifi_jd_oneshot(struct ieee80211_hdr *hdr){
	u8 *SrcMacAddr = NULL;
	u8 *DstMacAddr = NULL;
	u8 index = 0;
	u8 jdIndex = 0;
	u8 jdData = 0;
	u8 i = 0;
	u8 j = 0;
	u8 *BssidMacAddr = NULL;
	bool synflag = 0;

	DstMacAddr = ieee80211_get_DA(hdr);

	if (tls_wifi_jd_check_condition(DstMacAddr)<0){
		return 1;
	}


	SrcMacAddr = ieee80211_get_SA(hdr);
#if CONFIG_ONESHOT_MAC_FILTER
	if (0 == tls_filter_module_srcmac(SrcMacAddr)){
		return -1;
	}
#endif
	if (NULL == aujddata){
		return -1;
	}

	if (tls_wifi_compare_mac_addr(SrcMacAddr)){
		jdIndex = DstMacAddr[4];
		jdData	= DstMacAddr[5];
		if (jdIndex >= JD_VALID_DATA_OFFSET){		/*Save Data*/
			index = jdIndex - JD_VALID_DATA_OFFSET;
			if (0 == ((uljddatavalid[index/32]>>(index%32))&0x1)){
				aujddata[index] = jdData;
				uljddatavalid[index/32] |= 1 << (index%32);
			}
		}

		if ((jdIndex <= 5)&&(ucjdataencodeMode == 0xFF)){
			if (ucjdsyncode == jdData){
				ucjdataencodeMode = jdData;
			}
		}

		for (i = 0; i < 2; i++){
			if ((jdIndex == (i+6))&&((aujdDataLen[i] == 0xFF)||(aujdDataLen[i] != jdData))){
				if ((aujdDataLen[i] != 0xFF) && (aujdDataLen[i] != jdData)){
					for (j = 0; j < aujdDataLen[i]; j++){
						if (uljddatavalid[j/32]>>(j%32)&0x01){
							aujddata[j] = 0;
							uljddatavalid[j/32] &= ~(1<<(j%32));
						}
					}
				}

				if ((i==0)&&(jdData <= 32)){
					aujdDataLen[i] = jdData; /*SSID LEN*/
				}else if ((i == 1)&&(jdData <= 64)){
					aujdDataLen[i] = jdData; /*PWD LEN*/
				}
			}
		}

		synflag =  (DstMacAddr[3]== 0x76)&&(DstMacAddr[4]<=5)&&(ucjdsyncode == DstMacAddr[5]);
		synflag |= (DstMacAddr[3]== 0x77)&&(DstMacAddr[4]==6)&&(DstMacAddr[5]!=0);
		synflag |= (DstMacAddr[3]== 0x77)&&(DstMacAddr[4]==7);
		synflag |= (DstMacAddr[3]== 0x78);
		synflag |= (DstMacAddr[3]== 0x79);
		synflag |= (DstMacAddr[3]== 0x7A);
	}

	if (0 == guchandshakeflag){ /*sync*/
		if (synflag){
			++jdhandshakecnt;
		}
		ONESHOT_DBG("jdhandshakecnt:%d\n", jdhandshakecnt);
		if (jdhandshakecnt>=HANDSHAKE_CNT){

			if (tls_compare_ether_addr(gSrcMac, SrcMacAddr)){
				MEMCPY(gSrcMac, SrcMacAddr, ETH_ALEN);
			}


			gucHandShakeOk = 0;
			tls_oneshot_switch_channel_tim_temp_stop();
			guchandshakeflag = 1;
			if (ieee80211_has_tods(hdr->frame_control)){
				BssidMacAddr = hdr->addr1;
			}else if (ieee80211_has_fromds(hdr->frame_control)){
				BssidMacAddr = hdr->addr2;
			}
			if (BssidMacAddr){
				MEMCPY(gucbssidData, BssidMacAddr, ETH_ALEN);
			}
			if (tls_compare_ether_addr(gSrcMac, SrcMacAddr)){
				MEMCPY(gSrcMac, SrcMacAddr, ETH_ALEN);
			}
			ONESHOT_INF("[JD:%d]gSrcMac:%x:%x:%x:%x:%x:%x\n",tls_os_get_time(), MAC2STR(gSrcMac));
		}
	}else{	/*data handle*/
		if (tls_wifi_compare_mac_addr(SrcMacAddr)){
			if (synflag){
				++jdhandshakecnt;
			}
			if ((jdhandshakecnt >=(HANDSHAKE_CNT+10))&&(gucHandShakeOk == 0)){
				tls_oneshot_switch_channel_tim_stop();
				gucHandShakeOk = 1;
				ONESHOT_DBG("Stop timer hand shake timeout\r\n");
			}
		}


		if ((aujdDataLen[0] != 0xFF)&&(aujdDataLen[1] != 0xFF)){
			for (i = 0; i < (aujdDataLen[0] + aujdDataLen[1]); i++){
				if ((uljddatavalid[i/32]>>(i%32))&0x1){
					continue;
				}
				break;
			}

			if (i == (aujdDataLen[0] + aujdDataLen[1])){
				if (ucjdataencodeMode == ucjdsyncode){
					aujddata[aujdDataLen[0] + aujdDataLen[1]] = '\0';
					gucssidData[0] = '\0';
					memcpy(gucssidData, aujddata, aujdDataLen[0]);
					gucssidData[aujdDataLen[0]] = '\0';
					memcpy(gucpwdData, &aujddata[aujdDataLen[0]], aujdDataLen[1]);
					gucpwdData[aujdDataLen[1]] = '\0';
					ONESHOT_INF("[JDONESHOT]recv ok:%d,%d\n", tls_os_get_time(), tls_os_get_time()- oneshottime);
					ONESHOT_INF("[JDONESHOT]SSID:%s\n", gucssidData);
					ONESHOT_INF("[JDONESHOT]PASSWORD:%s\n", gucpwdData);
					tls_wifi_oneshot_connect(gucssidData, gucpwdData);
				}else{
					tls_wifi_clear_oneshot_data(1);
					guchandshakeflag = 0;
				}
				return 0;
			}
		}
	}
	return -1;
}
#endif
#if TLS_CONFIG_UDP_LSD_ONESHOT


static u8 smtcfg1array[4] = {61/*open*/,69/*wep*/,77/*aes*/,81/*tkip*/};
static u16 smtcfgArray = 0;
#define BROADCAST_HANDSHAKE_CNT 8
static u8 bdhandshakecnt[4];

#define DATA_VALID_LENGTH 4
#define DATA_SAVE_LENGTH  (3+ (DATA_VALID_LENGTH))

/*UDP ONESHOT*/
typedef struct WIFI_BSSID_STRU{
	u8 *DataBssid[2];
}WIFI_BSSID;
typedef struct WIFI_SSID_STRU{
	u8 *DataSsid[8];
}WIFI_SSID;
typedef struct WIFI_PWD_STRU{
	u8 *DataPwd[32];
}WIFI_PWD;
typedef struct WIFI_CUST_DATA_STRU{
	u8 *DataCustom[32];
}WIFI_CUST_DATA;

static u8 bssid_seq = 0;
static u8 bssid_seq_total_tmp = 0;
static u8 bssidData[7] = {0};/*Save the complete BSSID information*/
static WIFI_BSSID stDataBssid; /*Save BSSID data for each package*/

static WIFI_PWD gstData;
static u8 gaupwdData[65]={0};
static u8 gucpwdseq = 0;
static u8 gucpwdseqtotaltmp = 0;

static u8 ssid_seq = 0;
static u8 ssid_seq_total_tmp = 0;
static u8 ssidData[33] = {0};/*Save the complete SSID information*/
static WIFI_SSID stDataSsid; /*Save SSID data for each package*/

static u32 tag_recved[3] = {0,0,0};

static void tls_wifi_clear_oneshot_info(u8 cleardata)
{
	int i = 0;
	memset(bdhandshakecnt, 0, 4);
	tag_recved[0] = tag_recved[1] = tag_recved[2] = 0;
	if (cleardata){
		for (i= 0; i < bssid_seq_total_tmp; i++){
			if (stDataBssid.DataBssid[i] != NULL){
				tls_mem_free(stDataBssid.DataBssid[i]);
				stDataBssid.DataBssid[i] = NULL;
			}
		}
		bssid_seq = 0;
		bssid_seq_total_tmp = 0;
	}

	if (cleardata){
		for (i= 0; i < gucpwdseqtotaltmp; i++){
			if (gstData.DataPwd[i] != NULL){
				tls_mem_free(gstData.DataPwd[i]);
				gstData.DataPwd[i] = NULL;
			}
		}
		gucpwdseq = 0;
		gucpwdseqtotaltmp = 0;
	}

	if (cleardata){
		for (i= 0; i < ssid_seq_total_tmp; i++){
			if (stDataSsid.DataSsid[i] != NULL){
				tls_mem_free(stDataSsid.DataSsid[i]);
				stDataSsid.DataSsid[i] = NULL;
			}
		}
		ssid_seq = 0;
		ssid_seq_total_tmp = 0;
	}
}

int tls_wifi_ssid_resolve(u8 *data, u8 len, u8 seqnum, u8 seqtotal)
{
	u8 i = 0;

	if (ssid_seq_total_tmp == 0){
		ssid_seq_total_tmp = seqtotal;
	}

	/*clear save ssid's buf because total packet number changed*/
	if (ssid_seq_total_tmp != seqtotal){
		for (i= 0; i < ssid_seq_total_tmp; i++){
			if (stDataSsid.DataSsid[i] != NULL){
				tls_mem_free(stDataSsid.DataSsid[i]);
				stDataSsid.DataSsid[i] = NULL;
			}
		}
		ssid_seq = 0;
		ssid_seq_total_tmp = seqtotal;
	}

	if (stDataSsid.DataSsid[seqnum] == NULL){
		stDataSsid.DataSsid[seqnum] = tls_mem_alloc(len/2+1);
		if (stDataSsid.DataSsid[seqnum] == NULL){
			return 1;
		}

		MEMCPY(stDataSsid.DataSsid[seqnum], data, len);
		stDataSsid.DataSsid[seqnum][len] = '\0';
		ONESHOT_DBG("DataSsid[%d]:%s\n", seqnum, stDataSsid.DataSsid[seqnum]);
		ssid_seq++;
		if (ssid_seq == seqtotal){
			gucssidokflag = 1;
			for (i = 0; i< seqtotal; i++){
				strcat((char *)ssidData, (char *)stDataSsid.DataSsid[i]);
 			}
 			gucssidData[0] = '\0';
			if (strlen((char *)ssidData) > 32)
			{
				strncpy((char *)gucssidData,(char *)ssidData,32);
			}else{
				strcpy((char *)gucssidData,(char *)ssidData);
			}
			for (i = 0; i < ssid_seq_total_tmp; i++){
				if (NULL != stDataSsid.DataSsid[i]){
					tls_mem_free(stDataSsid.DataSsid[i]);
					stDataSsid.DataSsid[i] = NULL;
				}
			}
			memset(ssidData, 0 ,33);
			ssid_seq = 0;
			ssid_seq_total_tmp = 0;
		}
		return 0;
	}
	return 1;
}


int tls_wifi_bssid_resolve(u8 *data, u8 len, u8 seqnum, u8 seqtotal)
{
	u8 i = 0;

	if (bssid_seq_total_tmp == 0){
		bssid_seq_total_tmp = seqtotal;
	}

	/*clear save ssid's buf because total packet number changed*/
	if (bssid_seq_total_tmp != seqtotal){
		for (i= 0; i < bssid_seq_total_tmp; i++){
			if (stDataBssid.DataBssid[i] != NULL){
				tls_mem_free(stDataBssid.DataBssid[i]);
				stDataBssid.DataBssid[i] = NULL;
			}
		}
		bssid_seq = 0;
		bssid_seq_total_tmp = seqtotal;
	}

	if (stDataBssid.DataBssid[seqnum] == NULL){
		stDataBssid.DataBssid[seqnum] = tls_mem_alloc(len+1);
		if (stDataBssid.DataBssid[seqnum] == NULL){
			return 1;
		}

		MEMCPY(stDataBssid.DataBssid[seqnum], data, len);
		stDataBssid.DataBssid[seqnum][len] = '\0';

		bssid_seq++;
		if (bssid_seq == seqtotal){
			gucbssidokflag = 1;
			for (i = 0; i< seqtotal; i++){
				strcat((char *)bssidData, (char *)stDataBssid.DataBssid[i]);
			}
			MEMCPY(gucbssidData,bssidData, ETH_ALEN);
			for (i = 0; i < bssid_seq_total_tmp; i++){
				tls_mem_free(stDataBssid.DataBssid[i]);
				stDataBssid.DataBssid[i] = NULL;
			}
			memset(bssidData, 0 ,7);
			bssid_seq = 0;
			bssid_seq_total_tmp = 0;
		}
		return 0;
	}
	return 1;
}

int tls_wifi_pwd_resolve(u8 *data, u8 len, u8 seqnum, u8 seqtotal)
{
	u8 i = 0;

	if (gucpwdseqtotaltmp == 0){
		gucpwdseqtotaltmp = seqtotal;
	}
	/*clear save pwd's buf because total packet number changed*/
	if (gucpwdseqtotaltmp != seqtotal){
		for (i= 0; i < gucpwdseqtotaltmp; i++){
			if (gstData.DataPwd[i] != NULL){
				tls_mem_free(gstData.DataPwd[i]);
				gstData.DataPwd[i] = NULL;
			}
		}
		gucpwdseqtotaltmp = seqtotal;
		gucpwdseq = 0;
	}

	if (gstData.DataPwd[seqnum] == NULL){
		gstData.DataPwd[seqnum] = tls_mem_alloc(len+1);
		if (gstData.DataPwd[seqnum] == NULL){
			return 1;
		}

		MEMCPY(gstData.DataPwd[seqnum], data, len);
		gstData.DataPwd[seqnum][len] = '\0';

		gucpwdseq++;
		if (gucpwdseq == seqtotal){
			for (i = 0; i< seqtotal; i++){
				if (gstData.DataPwd[i][0] != '\0'){
					strcat((char *)gaupwdData, (char *)gstData.DataPwd[i]);
				}
			}
			if (strlen((char *)gaupwdData) > 64){
				strncpy((char *)gucpwdData,(char *)gaupwdData, 64);
			}else{
				strcpy((char *)gucpwdData,(char *)gaupwdData);
			}
			gucpwdokflag = 1;

			for (i = 0; i < gucpwdseqtotaltmp; i++){
				if (NULL != gstData.DataPwd[i]){
					tls_mem_free(gstData.DataPwd[i]);
					gstData.DataPwd [i] = NULL;
				}
			}
			memset(gaupwdData, 0 ,65);
			gucpwdseq = 0;
			gucpwdseqtotaltmp = 0;

			return 0;
		}

	}

	return 1;
}

int tls_wifi_customdata_resolve(u8 *data, u8 len, u8 seqnum, u8 seqtotal)
{
	static u8 customdata_seq = {0};
	static u8 cust_seq_total_tmp = {0};
	static u8 customData[65] ={0};
	static WIFI_CUST_DATA stDataCustom;

	u8 i = 0;

	if (cust_seq_total_tmp == 0){
		cust_seq_total_tmp = seqtotal;
	}
	/*clear save pwd's buf because total packet number changed*/
	if (cust_seq_total_tmp != seqtotal){
		for (i= 0; i < cust_seq_total_tmp; i++){
			if (stDataCustom.DataCustom[i] != NULL){
				tls_mem_free(stDataCustom.DataCustom[i]);
				stDataCustom.DataCustom[i] = NULL;
			}
		}
		cust_seq_total_tmp = seqtotal;
		customdata_seq = 0;
	}

	if (stDataCustom.DataCustom[seqnum] == NULL){
		stDataCustom.DataCustom[seqnum] = tls_mem_alloc(len+1);
		if (stDataCustom.DataCustom[seqnum] == NULL){
			return 1;
		}

		MEMCPY(stDataCustom.DataCustom[seqnum], data, len);
		stDataCustom.DataCustom[seqnum][len] = '\0';

		customdata_seq++;
		if (customdata_seq == seqtotal){
			for (i = 0; i< seqtotal; i++){
				if (stDataCustom.DataCustom[i][0] != '\0'){
					strcat((char *)customData, (char *)stDataCustom.DataCustom[i]);
				}
			}
			memset(gucCustomData[0], 0, 65);
			strcpy((char *)gucCustomData[0],(char *)customData);
			if (gpfResult)
			{
				gpfResult(WM_WIFI_ONESHOT_TYPE_CUSTOMDATA);
				tls_wifi_set_oneshot_flag(0);
			}

			for (i = 0; i < cust_seq_total_tmp; i++){
				if (NULL != stDataCustom.DataCustom[i]){
					tls_mem_free(stDataCustom.DataCustom[i]);
					stDataCustom.DataCustom[i] = NULL;
				}
			}
			memset(customData, 0 ,65);
			customdata_seq = 0;
			cust_seq_total_tmp = 0;
		}
		return 0;
	}
	return 1;
}

int tls_wifi_oneshot_packet_head_resolve(u8 *datasave)
{
	u8 seqNum = 0;
	u8 seqTotal  = 0;
	u8 len = 0;
	u8 tagId = 0xFF;

	tagId = (datasave[0]>>4)&0xF;
	if (tagId > 2){
		return -1;
	}

	seqTotal = (datasave[0]&0xF)+1;/*4bit 0-1,1-2*/
	seqNum = (datasave[1]>>4)&0xF;
	if (seqNum >= seqTotal){
		return -1;
	}

	if ((tag_recved[tagId]>>seqNum) & 0x1) /*is recved?*/
	{
		return -1;
	}

	len = datasave[1]&0xF;
	if ((len > DATA_VALID_LENGTH)||(((seqNum+1) != seqTotal)&&(len !=DATA_VALID_LENGTH))){
		return -1;
	}

	if ((seqTotal > 1)&&(seqNum > 0)&&(len == 0)){
		return -1;
	}
	return 0;
}


int tls_wifi_oneshotinfo_resolve_udp(u8 *datasave)
{
	u8 crc, calcrc;
	int ret = 1;
	u8 seqNum = 0;
	u8 seqTotal  = 0;
	u8 len = 0;
	u8 tagId = 0xFF;


	tagId = (datasave[0]>>4)&0xF;
	seqTotal = (datasave[0]&0xF)+1;/*4bit 0-1,1-2*/
	seqNum = (datasave[1]>>4)&0xF;

	if ((tag_recved[tagId]>>seqNum) & 0x1) /*is recved?*/
	{
		return -1;
	}

	len = datasave[1]&0xF;
	crc = *(datasave + 2 + len);
	calcrc = get_crc8(datasave,(2+len));

	if (crc == calcrc){
		switch (tagId){
			case 0:
				tag_recved[0] |= 1<<seqNum;
			    if (gucssidokflag == 0)
				{
					ret = tls_wifi_ssid_resolve((datasave+2), len, seqNum, seqTotal);
				}
				break;
			case 1:
				tag_recved[1] |= 1<<seqNum;
				if (gucpwdokflag == 0)
				{
					ret = tls_wifi_pwd_resolve((datasave+2), len, seqNum, seqTotal);
				}
				break;
			case 2:
				tag_recved[2] |= 1<<seqNum;
				ret = tls_wifi_customdata_resolve((datasave+2), len, seqNum, seqTotal);
				break;

			default:
				break;
		}
	}

	return ret;
}

void tls_find_target_bss(u8 *targetbssid)
{
	struct tls_scan_bss_t *bss = NULL;
	int i = 0;
	if (oneshot_bss)
	{
		bss = (struct tls_scan_bss_t *)oneshot_bss;
		for (i = 0;i < bss->count; i++)
		{
			if (0 == memcmp(bss->bss[i].bssid,targetbssid, ETH_ALEN))
			{
				if (bss->bss[i].ssid_len)
				{
					gucssidData[0] = '\0';
					MEMCPY(gucssidData, bss->bss[i].ssid, bss->bss[i].ssid_len);
					ONESHOT_DBG("find ssid:%s\r\n", gucssidData);
					gucssidokflag = 1;
				}
				break;
			}
		}
	}
}

u8 tls_wifi_lsd_broadcast(struct ieee80211_hdr *hdr, u32 data_len)
{
#define OFFSET_DATA 1     /*Real Data BASE VALUE*/
	u8 *broadcast = NULL;
	u32 frm_len = 0;
	u8 i = 0;

	static s8 databitcnt[2] = {4, 4};
	static u8 datasave[2][DATA_SAVE_LENGTH];
	static u8 datacnt[2] = {0, 0};
	static u8 syncnum = 0;
	static u32 seqnum[2] = {0xFFFFFFFF, 0xFFFFFFFF};
	u8 *SrcMacAddr = NULL;
	u8 datalen = 0;
	int dsflag = 0;

	SrcMacAddr = ieee80211_get_SA(hdr);
	broadcast = ieee80211_get_DA(hdr);
	if (0 == is_broadcast_ether_addr(broadcast)){
		return 1;
	}

	dsflag = ieee80211_has_tods(hdr->frame_control);
	if (ieee80211_is_data_qos(hdr->frame_control)){
		frm_len = data_len - 2;
	}else{
		frm_len = data_len;
	}

	if (0 == guchandshakeflag){	/*hand shake*/
		for (i = 0; i < 4; i++){
			if (frm_len == smtcfg1array[i]){
				if (tls_wifi_compare_mac_addr(SrcMacAddr)){
					++bdhandshakecnt[i];
					if (bdhandshakecnt[i] >= BROADCAST_HANDSHAKE_CNT){
						smtcfgArray = smtcfg1array[i] + OFFSET_DATA;
						syncnum = 0;
						datacnt[0] = datacnt[1] = 0;
						databitcnt[0] = databitcnt[1] = 4;
						seqnum[0] = seqnum[1] = 0;
						gucHandShakeOk = 0;
						tls_oneshot_switch_channel_tim_stop();
						if (ieee80211_has_fromds(hdr->frame_control)){
							MEMCPY(gucbssidData, hdr->addr2, ETH_ALEN);
						}else{
							MEMCPY(gucbssidData, hdr->addr1, ETH_ALEN);
						}

                        tls_find_target_bss(gucbssidData);
						gucbssidokflag = 1;
						ONESHOT_DBG("[BroadCast]sync time:%d\r\n", tls_os_get_time());
						ONESHOT_INF("[BroadCast]gSrcMac:%x:%x:%x:%x:%x:%x\n", MAC2STR(gSrcMac));
						guchandshakeflag = 1;
						break;
					}
				}
			}
		}
	}else{	/*recv data*/
		if (tls_wifi_compare_mac_addr(SrcMacAddr)){
			if (!smtcfgArray ||((frm_len < smtcfgArray)&&(frm_len != (smtcfgArray - OFFSET_DATA))) || (frm_len > (smtcfgArray+15))){
				return 1;
			}

			if (ieee80211_has_retry(hdr->frame_control)&&(seqnum[dsflag] == hdr->seq_ctrl)){
				return 1;
			}else{
				seqnum[dsflag] = hdr->seq_ctrl;
			}

			if (syncnum == 0){
				if((smtcfgArray == frm_len)&&(gucssidokflag == 0)){ /*TAG 0*/
					datasave[dsflag][datacnt[dsflag]] = 0<<4;
					databitcnt[dsflag] = 0;
					datacnt[dsflag] = 0;
					syncnum = 1;
				}else if(((smtcfgArray+1) == frm_len)&&(gucpwdokflag == 0)){ /*TAG 1*/
					datasave[dsflag][datacnt[dsflag]] = 1<<4;
					databitcnt[dsflag] = 0;
					datacnt[dsflag] = 0;
					syncnum = 1;
				}else if((smtcfgArray+2) == frm_len){ /*TAG 2*/
					datasave[dsflag][datacnt[dsflag]] = 2<<4;
					databitcnt[dsflag] = 0;
					datacnt[dsflag] = 0;
					syncnum = 1;
				}
				return 1;
			}

			if (frm_len == (smtcfgArray-OFFSET_DATA)){/*For non valid data, direct assignment*/
				datasave[dsflag][datacnt[dsflag]] |=  0xF<<(databitcnt[dsflag]);
				databitcnt[dsflag] -= 4;
				if (datacnt[dsflag] < 3){
					syncnum = 0;
					memset(datasave[dsflag], 0, DATA_SAVE_LENGTH);
					datacnt[dsflag] = 0;
					return 1;
				}else{
					datalen = datasave[dsflag][1]&0xF;
					if (datacnt[dsflag] < (datalen+3)){
						syncnum = 0;
						memset(datasave[dsflag], 0, DATA_SAVE_LENGTH);
						datacnt[dsflag] = 0;
						return 1;
					}else{
						tls_wifi_oneshotinfo_resolve_udp(datasave[dsflag]);
						syncnum = 0;
						memset(datasave[dsflag], 0, DATA_SAVE_LENGTH);
						datacnt[dsflag] = 0;
						databitcnt[dsflag] = 4;
					}
				}
			}else{
				datasave[dsflag][datacnt[dsflag]] |=  (frm_len - smtcfgArray)<<(databitcnt[dsflag]);
				databitcnt[dsflag] -= 4;
				if (databitcnt[dsflag] < 0){
					databitcnt[dsflag] = 4;
					datacnt[dsflag]++;
					if ((datacnt[dsflag] == 2) && tls_wifi_oneshot_packet_head_resolve(datasave[dsflag])){
						syncnum = 0;
						memset(datasave[dsflag], 0, DATA_SAVE_LENGTH);
						datacnt[dsflag] = 0;
					}else if (datacnt[dsflag] == DATA_SAVE_LENGTH){
						/*resolve data*/
						tls_wifi_oneshotinfo_resolve_udp(datasave[dsflag]);
						syncnum = 0;
						memset(datasave[dsflag], 0, DATA_SAVE_LENGTH);
						datacnt[dsflag] = 0;
					}
				}
			}
		}
	}

	if ((1== gucssidokflag) && (1 == gucpwdokflag)){
		ONESHOT_DBG("[BroadCast]recv ok:%d\r\n", tls_os_get_time()-oneshottime);
		if (gucbssidokflag&&gucssidokflag
			&& tls_oneshot_is_ssid_bssid_match(gucssidData, strlen((char *)gucssidData), gucbssidData)
		){
			ONESHOT_INF("[BroadCast]SSID:%s\n", gucssidData);
			ONESHOT_INF("[BroadCast]BSSID:%x:%x:%x:%x:%x:%x\n",	MAC2STR(gucbssidData));
			ONESHOT_INF("[BroadCast]PASSWORD:%s\n", gucpwdData);
			tls_wifi_oneshot_connect_by_ssid_bssid(gucssidData, gucbssidData, gucpwdData);
		}else if(gucssidokflag&&(gucssidData[0] != '\0')){
			ONESHOT_INF("[BroadCast]SSID:%s\n", gucssidData);
			ONESHOT_INF("[BroadCast]PASSWORD:%s\n", gucpwdData);
			tls_wifi_oneshot_connect(gucssidData, gucpwdData);
		}
	}


	return 1;
}

void tls_wifi_lsd_set_syncode(u8 syncode){
	uclsdsyncode = syncode;
}

int tls_wifi_lsd_probe(struct ieee80211_hdr *hdr)
{
    if ((IEEE80211_FCTL_VERS|IEEE80211_STYPE_CFACKPOLL) == (hdr->frame_control&(IEEE80211_STYPE_CFACKPOLL|IEEE80211_FCTL_VERS)))
    {
#if CONFIG_ONESHOT_MAC_FILTER
        if (1 == tls_filter_module_srcmac(hdr->addr2)){
#endif
            if (1 == tls_wifi_decrypt_data((u8 *)hdr))
            {
                if (((1== gucssidokflag)||(1 == gucbssidokflag)) && (1 == gucpwdokflag))
                {
                    ONESHOT_DBG("[PB]recv ok:%d\n", tls_os_get_time() - oneshottime);
                    if (gucbssidokflag
                        && gucssidokflag
                        && tls_oneshot_is_ssid_bssid_match(gucssidData, strlen((char *)gucssidData), gucbssidData))
                    {
                        ONESHOT_INF("[PB]SSID:%s\n", gucssidData);
                        ONESHOT_INF("[PB]BSSID:%x:%x:%x:%x:%x:%x\n",  gucbssidData[0],  gucbssidData[1],  gucbssidData[2],  gucbssidData[3],  gucbssidData[4],  gucbssidData[5]);
                        ONESHOT_INF("[PB]PASSWORD:%s\n", gucpwdData);
                        tls_wifi_oneshot_connect_by_ssid_bssid(gucssidData, gucbssidData, gucpwdData);
                    }
                    else if (1 == gucssidokflag)
                    {
                        ONESHOT_INF("[PB]SSID:%s\n", gucssidData);
                        ONESHOT_INF("[PB]PASSWORD:%s\n", gucpwdData);
                        tls_wifi_oneshot_connect(gucssidData, gucpwdData);
                    }
                    else if (gucbssidokflag)
                    {
                        if (0 == tls_is_zero_ether_addr(gucbssidData)){
                            ONESHOT_INF("[PB]BSSID:%x:%x:%x:%x:%x:%x\n",  gucbssidData[0],  gucbssidData[1],  gucbssidData[2],  gucbssidData[3],  gucbssidData[4],  gucbssidData[5]);
                            ONESHOT_INF("[PB]PASSWORD:%s\n", gucpwdData);
                            tls_wifi_oneshot_connect_by_bssid(gucbssidData,gucpwdData);
                        }
                    }
#if TLS_CONFIG_AP_MODE_ONESHOT
                    gucRawValid = 0;
#endif
                }
            }
#if CONFIG_ONESHOT_MAC_FILTER
        }
#endif
        return 1;
    }
    return 1;
}

int tls_wifi_lsd_oneshot(struct ieee80211_hdr *hdr){
	u8 *SrcMacAddr = NULL;
	u8 *DstMacAddr = NULL;
	u8 index = 0;
	u8 lsdIndex = 0;
	u8 lsdData1 = 0;
	u8 lsdData = 0;
	u8 i = 0;
	u8 *BssidMacAddr = NULL;
	int ret =0;

	DstMacAddr = ieee80211_get_DA(hdr);
	if ((0x01 != DstMacAddr[0])||(0x00 != DstMacAddr[1])||(0x5e != DstMacAddr[2])){/*multicast ip Addr range:239.0~239.xx ||(0x76 <= DstMacAddr[3])*/
		return -1;
	}

	if ((0 == DstMacAddr[3])&&(uclsdsyncode!= DstMacAddr[4])){/*Sync Frame Must be 1:00:5e:00:64:xx*/
		return -1;
	}

	SrcMacAddr = ieee80211_get_SA(hdr);
#if CONFIG_ONESHOT_MAC_FILTER
	if (0 == tls_filter_module_srcmac(SrcMacAddr)){
		return -1;
	}
#endif
	if (NULL == aulsddata){
		return -1;
	}

	if (tls_wifi_compare_mac_addr(SrcMacAddr)){
		lsdIndex = DstMacAddr[3];
		lsdData1 = DstMacAddr[4];
		lsdData	 = DstMacAddr[5];
		if (lsdIndex > 0){		/*Save Data*/
			index = lsdIndex-1;
			if (0 == ((ullsddatavalid[index/32]>>(index%32))&0x1)){
				aulsddata[2*index] = lsdData1;
				aulsddata[2*index+1] = lsdData;
				ullsddatavalid[index/32] |= 1 << (index%32);
			}
		}

		if ((lsdIndex == 0 )&&(lsdData1==uclsdsyncode)&&((uclsddatalen == 0xFF)||(lsdData != uclsddatalen))){
			if ((lsdData != uclsddatalen) && (uclsddatalen != 0xFF)){
				for (i = 0; i < uclsddatalen; i++){
					if (ullsddatavalid[i/32]>>(i%32)&0x01){
						aulsddata[2*i] = 0;
						aulsddata[2*i+1] = 0;
						ullsddatavalid[i/32] &= ~(1<<(i%32));
					}
				}
			}
			uclsddatalen = lsdData;
		}
	}

	if (0 == guchandshakeflag){ /*sync*/
		if ((0 == DstMacAddr[3])&&(uclsdsyncode == DstMacAddr[4])){
			++lsdhandshakecnt;

		}

		if (lsdhandshakecnt == 1){
			if (tls_compare_ether_addr(gSrcMac, SrcMacAddr)){
				MEMCPY(gSrcMac, SrcMacAddr, ETH_ALEN);
			}

			gucHandShakeOk = 0;
			tls_oneshot_switch_channel_tim_temp_stop();
		}

		if (lsdhandshakecnt >= HANDSHAKE_CNT){
			guchandshakeflag = 1;
			if (ieee80211_has_tods(hdr->frame_control)){
				BssidMacAddr = hdr->addr1;
			}else if (ieee80211_has_fromds(hdr->frame_control)){
				BssidMacAddr = hdr->addr2;
			}
			if (BssidMacAddr){
				MEMCPY(gucbssidData, BssidMacAddr, ETH_ALEN);
			}
			if (tls_compare_ether_addr(gSrcMac, SrcMacAddr)){
				MEMCPY(gSrcMac, SrcMacAddr, ETH_ALEN);
			}
			ONESHOT_DBG("[LSD BSSID]:"MACSTR"\n", MAC2STR(gucbssidData));
			ONESHOT_INF("[LSD:%d]gSrcMac:%x:%x:%x:%x:%x:%x\n",tls_os_get_time(), MAC2STR(gSrcMac));
		}
	}else{	/*data handle*/
		if (tls_wifi_compare_mac_addr(SrcMacAddr)){
			if ((DstMacAddr[4]<=5)&&(uclsdsyncode == DstMacAddr[5])){
				++lsdhandshakecnt;
			}
			if ((lsdhandshakecnt >= (HANDSHAKE_CNT+10) )&&(gucHandShakeOk == 0)){
				tls_oneshot_switch_channel_tim_stop();
				gucHandShakeOk = 1;
			}
		}

		if ((uclsddatalen != 0)&&(uclsddatalen != 0xFF)){
			for (i = 0; i < (uclsddatalen+1)/2; i++){
				if ((ullsddatavalid[i/32]>>(i%32))&0x1){
					continue;
				}
				break;
			}
			if (i == (uclsddatalen+1)/2){
				gucssidokflag = 0;
				gucbssidokflag = 0;
				gucpwdokflag = 0;
				memset(gucssidData, 0, 33);
				memset(gucbssidData, 0, 6);
				memset(gucpwdData, 0, 65);
			if (0 == gucbssidokflag){
				gucbssidokflag = 1;
				if (ieee80211_has_tods(hdr->frame_control)){
					BssidMacAddr = hdr->addr1;
				}else if (ieee80211_has_fromds(hdr->frame_control)){
					BssidMacAddr = hdr->addr2;
				}

				if (BssidMacAddr){
					MEMCPY(gucbssidData, BssidMacAddr, ETH_ALEN);
					}
				}
				aulsddata[uclsddatalen] ='\0';

				ret = tls_wifi_decode_new_oneshot_data(aulsddata,gucpwdData, gucbssidData, gucssidData, gucCustomData[0]);
				if (0==ret){
					ONESHOT_DBG("[LSD]recv ok:%d\n", tls_os_get_time() - oneshottime);
					if ((0 == tls_is_zero_ether_addr(gucbssidData))&&(gucssidData[0] != '\0')){
						gucbssidokflag = 1;
						gucssidokflag = 1;
						gucpwdokflag = 1;
					}else if (gucssidData[0] != '\0'){
						gucssidokflag = 1;
						gucbssidokflag = 0;
						gucpwdokflag = 1;
					}else if (gucCustomData[0][0] != '\0'){
						tls_wifi_clear_oneshot_data(1);
						guchandshakeflag = 0;
						if (gpfResult)
						{
						    gpfResult(WM_WIFI_ONESHOT_TYPE_CUSTOMDATA);
						    tls_wifi_set_oneshot_flag(0);
						}
					}

					if (((1== gucssidokflag)||(1 == gucbssidokflag)) && (1 == gucpwdokflag)){
						if (gucbssidokflag
							&&gucssidokflag
							&& tls_oneshot_is_ssid_bssid_match(gucssidData, strlen((char *)gucssidData), gucbssidData)){
							ONESHOT_INF("[LSD]SSID:%s\n", gucssidData);
							ONESHOT_INF("[LSD]BSSID:%x:%x:%x:%x:%x:%x\n",	gucbssidData[0],  gucbssidData[1],	gucbssidData[2],  gucbssidData[3],	gucbssidData[4],  gucbssidData[5]);
							ONESHOT_INF("[LSD]PASSWORD:%s\n", gucpwdData);
							tls_wifi_oneshot_connect_by_ssid_bssid(gucssidData, gucbssidData, gucpwdData);
						}else if(gucssidokflag&&(gucssidData[0] != '\0')){
							ONESHOT_INF("[LSD]SSID:%s\n", gucssidData);
							ONESHOT_INF("[LSD]PASSWORD:%s\n", gucpwdData);
							tls_wifi_oneshot_connect(gucssidData, gucpwdData);
						}
					}
				}else{

					tls_wifi_clear_oneshot_data(1);
					guchandshakeflag = 0;
				}
				return 0;
			}
		}
	}
	return -1;
}
#endif

/*END CONFIG_UDP_ONE_SHOT*/
#endif
#if TLS_CONFIG_AP_MODE_ONESHOT
int soft_ap_create(void)
{
	struct tls_softap_info_t apinfo;
	struct tls_ip_info_t ipinfo;
	u8 ret=0;
	u8 ssid_set = 0;
	char ssid[33];
	u8 mac_addr[6];

    tls_get_mac_addr(mac_addr);
    ssid[0]='\0';
    u8 ssid_len = sprintf(ssid, "%s_%02x%02x", ONESHOT_AP_NAME, mac_addr[4], mac_addr[5]);


	tls_param_get(TLS_PARAM_ID_BRDSSID, (void *)&ssid_set, (bool)0);
	if (0 == ssid_set)
	{
		ssid_set = 1;
		tls_param_set(TLS_PARAM_ID_BRDSSID, (void *)&ssid_set, (bool)1); /*Set BSSID broadcast flag*/
	}
	memset(&apinfo, 0, sizeof(struct tls_softap_info_t));
	MEMCPY(apinfo.ssid, ssid, ssid_len);
	apinfo.ssid[ssid_len]='\0';

	apinfo.encrypt = 0;  /*0:open, 1:wep64, 2:wep128*/
	apinfo.channel = 5; /*channel random*/
	/*ip information: ip address?ê?netmask?ê?dns*/
	ipinfo.ip_addr[0] = 192;
	ipinfo.ip_addr[1] = 168;
	ipinfo.ip_addr[2] = 1;
	ipinfo.ip_addr[3] = 1;
	ipinfo.netmask[0] = 255;
	ipinfo.netmask[1] = 255;
	ipinfo.netmask[2] = 255;
	ipinfo.netmask[3] = 0;
	MEMCPY(ipinfo.dnsname, "local.wm", sizeof("local.wm"));
	ret = tls_wifi_softap_create((struct tls_softap_info_t* )&apinfo, (struct tls_ip_info_t* )&ipinfo);
	//printf("\n ap create %s ! \n", (ret == WM_SUCCESS)? "Successfully" : "Error");

	return ret;
}
#if TLS_CONFIG_SOCKET_MODE
err_t  socket_recive_cb(u8 skt_num, struct pbuf *p, err_t err)
{
	int len = p->tot_len;
	int datalen = 0;
	char *pStr = NULL;
	char *pEnd;
	char *LenStr = NULL;
	int ret  = 0;
    //printf("socket recive data\n");
	if (0 == gucRawValid){
		gucRawValid = 1;
	    if(p->tot_len > SOCKET_RX_DATA_BUFF_LEN)
	    {
	    	len = SOCKET_RX_DATA_BUFF_LEN;
	    }
		pStr = tls_mem_alloc(len+1);
		if (pStr){
		    pbuf_copy_partial(p, pStr, len, 0);
			//printf("pStr:%s\n", pStr);
			pEnd = strstr(pStr, "\r\n");
			if (pEnd){
				datalen = pEnd - pStr;
				LenStr = tls_mem_alloc(datalen+1);
				memcpy(LenStr, pStr, datalen);
				LenStr[datalen] = '\0';
				ret = strtodec(&datalen,LenStr);
				tls_mem_free(LenStr);
				LenStr = NULL;
				if (ret == 0){
					//printf("trans datalen:%d\n", datalen);
					strncpy(sock_rx->sock_rx_data, pEnd + 2, datalen);
					sock_rx->sock_rx_data[datalen] = '\0';
					pEnd = NULL;
				    sock_rx->sock_data_len = datalen;
				   // printf("\nsock recive data = %s\n",sock_rx->sock_rx_data);
				   if (oneshot_msg_q)
				   {
				       tls_os_queue_send(oneshot_msg_q, (void *)AP_SOCK_S_MSG_SOCKET_RECEIVE_DATA, 0);
				   }
				}
	   		}
			tls_mem_free(pStr);
			pStr = NULL;
		}
	    if (p){
	       pbuf_free(p);
	    }
	}
    return ERR_OK;
}

int create_tcp_server_socket(void)
{
    skt_descp = (struct tls_socket_desc *)tls_mem_alloc(sizeof(struct tls_socket_desc));
    if(skt_descp == NULL)
    {
        return -1;
    }
    memset(skt_descp, 0, sizeof(struct tls_socket_desc));

    sock_rx = (ST_Sock_Recive *)tls_mem_alloc(sizeof(ST_Sock_Recive));
    if(sock_rx == NULL)
    {
        tls_mem_free(skt_descp);
        skt_descp = NULL;
        return -1;
    }
    memset(sock_rx, 0, sizeof(ST_Sock_Recive));

    sock_rx->sock_rx_data = tls_mem_alloc(SOCKET_RX_DATA_BUFF_LEN*sizeof(char));
    if(sock_rx->sock_rx_data == NULL)
    {
        tls_mem_free(sock_rx);
        tls_mem_free(skt_descp);
        sock_rx = NULL;
        skt_descp = NULL;
        return -1;
    }
    memset(sock_rx->sock_rx_data, 0, sizeof(255*sizeof(char)));

	skt_descp->protocol = SOCKET_PROTO_TCP;
	skt_descp->cs_mode = SOCKET_CS_MODE_SERVER;
	skt_descp->port = SOCKET_SERVER_PORT;
    skt_descp->recvf = socket_recive_cb;
	sock_rx->socket_num = tls_socket_create(skt_descp);
	//printf("sck_num =??%d\n",sock_rx->socket_num);
    return WM_SUCCESS;
}

void free_socket(void)
{
	if (sock_rx == NULL){
		return;
	}
	if (sock_rx->socket_num == 0){
		return ;
	}
    tls_socket_close(sock_rx->socket_num);
	sock_rx->socket_num = 0;
    if(NULL != skt_descp)
    {
        tls_mem_free(skt_descp);
        skt_descp = NULL;
    }

    if(NULL != sock_rx->sock_rx_data)
    {
        tls_mem_free(sock_rx->sock_rx_data);
        sock_rx->sock_rx_data = NULL;
		sock_rx->sock_data_len = 0;
    }

        tls_mem_free(sock_rx);
        sock_rx = NULL;
}
#endif
#endif

u8 tls_wifi_dataframe_recv(struct ieee80211_hdr *hdr, u32 data_len)
{
	if (tls_wifi_get_oneshot_flag()== 0){
		return 1;
	}

    //only receive data frame
	if (0 == ieee80211_is_data(hdr->frame_control)){
		return 1;
	}

#if TLS_CONFIG_QQLINK_MODE_ONESHOT
    tls_process_qq_link_packet((u8 *)hdr, data_len);
#endif
#if TLS_CONFIG_AIRKISS_MODE_ONESHOT
    tls_airkiss_recv((u8 *)hdr, data_len);
#endif
    
#if TLS_CONFIG_UDP_ONE_SHOT
#if TLS_CONFIG_UDP_JD_ONESHOT
	tls_wifi_jd_oneshot(hdr);
#endif
#if TLS_CONFIG_UDP_LSD_ONESHOT
   	tls_wifi_lsd_probe(hdr);
	tls_wifi_lsd_oneshot(hdr);
#endif
#if TLS_CONFIG_UDP_LSD_ONESHOT
	tls_wifi_lsd_broadcast(hdr, data_len);
#endif
#endif

	return 1;
}

void tls_oneshot_stop_clear_data(void)
{
#if TLS_CONFIG_UDP_ONE_SHOT
    {
        if (gWifiSwitchChanTim)
        {
            tls_os_timer_stop(gWifiSwitchChanTim);
        }
        if (gWifiHandShakeTimOut)
        {
            tls_os_timer_stop(gWifiHandShakeTimOut);
        }
        if (gWifiRecvTimOut)
        {
            tls_os_timer_stop(gWifiRecvTimOut);
        }
    }

	if (oneshot_bss){
		tls_mem_free(oneshot_bss);
		oneshot_bss = NULL;
	}
	
	if (0 == first_start_oneshot_flag){
		uctotalchannum = 0;
		memset(airwifichan, 0xF, TOTAL_CHAN_NUM);
		memset(airchantype, 0x0, TOTAL_CHAN_NUM);
	}

	guchandshakeflag = 0;

	memset(gSrcMac, 0, ETH_ALEN);
	tls_wifi_clear_oneshot_data(1);

#if TLS_CONFIG_UDP_LSD_ONESHOT
	/*broadcast*/
	smtcfgArray = 0;
	tls_wifi_clear_oneshot_info(1);
	if (aulsddata){
	    tls_mem_free(aulsddata);
		aulsddata = NULL;
	}
#endif

#if TLS_CONFIG_UDP_JD_ONESHOT
	if (aujddata){
		tls_mem_free(aujddata);
		aujddata = NULL;
	}
#endif
#endif

 	gucssidokflag = 0;
	gucbssidokflag = 0;
	gucpwdokflag = 0;

#if TLS_CONFIG_AP_MODE_ONESHOT
#if TLS_CONFIG_SOCKET_MODE
//	if(1 == gucConfigMode)
	{
		free_socket();
	}
#endif
#endif	

	tls_wifi_data_recv_cb_register(NULL);
	tls_wifi_scan_result_cb_register(NULL);
#if TLS_CONFIG_AIRKISS_MODE_ONESHOT
        tls_airkiss_stop();
#endif
#if TLS_CONFIG_QQLINK_MODE_ONESHOT
	tls_stop_qq_link();
#endif
}

void tls_oneshot_init_data(void)
{
	gucssidokflag = 0;
	gucbssidokflag = 0;
	gucpwdokflag = 0;
	memset(gucssidData, 0, 33);
	memset(gucbssidData, 0, 6);
	memset(gucpwdData, 0, 65);

#if TLS_CONFIG_UDP_ONE_SHOT
	guchandshakeflag = 0;
	if (0 == first_start_oneshot_flag){
		uctotalchannum = 0;
		memset(airwifichan, 0xF, TOTAL_CHAN_NUM);
		memset(airchantype, 0x0, TOTAL_CHAN_NUM);		
	}
	memset(gSrcMac, 0, ETH_ALEN);

#if TLS_CONFIG_UDP_JD_ONESHOT
	if (NULL == aujddata){
		aujddata = tls_mem_alloc(128);
	}
#endif
#if TLS_CONFIG_UDP_LSD_ONESHOT
	if (NULL == aulsddata){
		aulsddata = tls_mem_alloc(256);
	}
#endif

	tls_wifi_clear_oneshot_data(1);
#if TLS_CONFIG_UDP_LSD_ONESHOT
	/*broadcast mode*/
	smtcfgArray = 0;
	memset(bdhandshakecnt, 0, 4);
	tls_wifi_clear_oneshot_info(1);
#endif
#endif	
}

#if TLS_CONFIG_UDP_ONE_SHOT
void tls_oneshot_scan_result_cb(void)
{
	if (oneshot_msg_q)
	{
		tls_os_queue_send(oneshot_msg_q, (void *)ONESHOT_SCAN_FINISHED, 0);
	}
}
void tls_oneshot_scan_start(void)
{
	if (oneshot_msg_q)
	{
		tls_os_queue_send(oneshot_msg_q, (void *)ONESHOT_SCAN_START, 0);
	}
}
void tls_oneshot_scan_result_deal(void)
{
	int i = 0, j = 0;
	struct tls_scan_bss_t *bss = NULL;
	static u16 lastchanmap = 0;
	lastchanmap = 0; /*clear map*/
	uctotalchannum = 0;	
    /*scan chan to cfm chan switch*/
	if (NULL == oneshot_bss)
	{
		oneshot_bss = tls_mem_alloc(ONESHOT_BSS_SIZE);
	}else{
		memset(oneshot_bss, 0, sizeof(ONESHOT_BSS_SIZE));
	}


	if (oneshot_bss)
	{
		tls_wifi_get_scan_rslt(oneshot_bss, ONESHOT_BSS_SIZE);
		bss = (struct tls_scan_bss_t *)oneshot_bss;
		for (j = 1; j < 15; j++)
		{
			for (i = 0;i < bss->count; i++)
			{
				if ((((lastchanmap>>(j-1))&0x1)==0)&&(j == bss->bss[i].channel))
				{
					lastchanmap |= 1<<(j-1);
					if (j < 5)
					{
						airwifichan[uctotalchannum] = j-1;
						airchantype[uctotalchannum] = 3;
						uctotalchannum++;
					}else if (j < 8)
					{
						airwifichan[uctotalchannum] = j-1;
						airchantype[uctotalchannum] = 3;	
						uctotalchannum++;
						airwifichan[uctotalchannum] = j-1;
						airchantype[uctotalchannum] = 2;						
						uctotalchannum++;
					}else if (j < 14){
						airwifichan[uctotalchannum] = j-1;
						airchantype[uctotalchannum] = 2;	
						uctotalchannum++;
					}else{
						airwifichan[uctotalchannum] = j-1;
						airchantype[uctotalchannum] = 0;	
						uctotalchannum++;
					}
					break;
				}
			}
		}
	}
	if ((uctotalchannum == 0))
	{
		for (i = 0 ; i < 14; i++)
		{
			if (i < 4)
			{
				airwifichan[uctotalchannum] = i;
				airchantype[uctotalchannum] = 3;
				uctotalchannum++;
			}else if (i < 7)
			{
				airwifichan[uctotalchannum] = i;
				airchantype[uctotalchannum] = 3;	
				uctotalchannum++;
				airwifichan[uctotalchannum] = i;
				airchantype[uctotalchannum] = 2;						
				uctotalchannum++;
			}else if (i < 13){
				airwifichan[uctotalchannum] = i;
				airchantype[uctotalchannum] = 2;	
				uctotalchannum++;
			}else{
				airwifichan[uctotalchannum] = i;
				airchantype[uctotalchannum] = 0;	
				uctotalchannum++;
			}
		}
		//uctotalchannum = TOTAL_CHAN_NUM;
	}	

}


static void tls_find_ssid_nonascII_pos_and_count(u8 *ssid, u8 ssid_len, int *start_pos, u8 *nonascii_cnt, u32 *non_all_pos)
{
    int i = 0;
    int cnt = 0;
    int pos = -1;
    u32 allpos = 0;

    if (ssid == NULL)
    {
    	return;
    }

    for (i = 0; i < ssid_len; i++)
    {
        if ( ssid[i] >= 0x80 )
        {
            allpos |= 1<<i;
            cnt++;
            if (pos == -1)
            {
                pos = i;
            }
        }
    }

    if (nonascii_cnt)
    {   
        *nonascii_cnt = cnt;
    }

    if (start_pos)
    {
        *start_pos = pos;
    }
    if (non_all_pos)
    {
        *non_all_pos = allpos;
    }
}


int tls_oneshot_is_ssid_bssid_match(u8 *ssid, u8 ssid_len, u8 *bssid)
{
    int i = 0;
    u8  bssidmatch = 0;
    u8  ssidmatch = 0;
    int  cfgssid_pos = -1;
    u8  cfgssid_non_cnt = 0;	
    u32 cfgssid_nonall_pos = 0;	
    struct tls_scan_bss_t *bss = NULL;

    if (oneshot_bss)
    {
        bss = (struct tls_scan_bss_t *)oneshot_bss;
        for (i = 0; i < bss->count; i++)
        {
            if ((ssid_len == bss->bss[i].ssid_len) && (memcmp(bss->bss[i].ssid, ssid, ssid_len) == 0))
            {
                ssidmatch = 1;
                if (memcmp(bss->bss[i].bssid, bssid, ETH_ALEN) == 0)
                {
                    //printf("bssid and SSID match:%s\n", ssid); /*For ssid and bssid match, directly return*/
                    return 1;
                }
            }
        }

        if (1 == ssidmatch)
        {
            //printf("SSID match:%s\n", ssid);
            return 0; 
        }
        else
        {
            tls_find_ssid_nonascII_pos_and_count(ssid, ssid_len , &cfgssid_pos,  &cfgssid_non_cnt, &cfgssid_nonall_pos);
            if (cfgssid_non_cnt) 
            {
	            for (i = 0; i < bss->count; i++)
	            {
	            	if (memcmp(bss->bss[i].bssid, bssid, ETH_ALEN) == 0) /*Find match bssid for ssid not match*/
	            	{    
	            	    bssidmatch = 1;
	            	    break;
	            	}
	            }
	            
	            if (bssidmatch && bss->bss[i].ssid_len)  /*For bssid match and non-zero len ssid, update ssid info*/
	            {
	            	MEMCPY(ssid, bss->bss[i].ssid, bss->bss[i].ssid_len);
	            	*(ssid + bss->bss[i].ssid_len) = '\0';
	            	//printf("bssid match and SSID T:%s\n", ssid);
	            	return 1;
	            }
            }
        }
    }
    return 0;
}

#if AIRKISS_USE_SELF_WRITE
extern u8 get_crc_8(u8 *ptr, u32 len);
u8 tls_oneshot_is_ssid_crc_match(u8 crc, u8 *ssid, u8 *ssid_len)
{
    int i = 0;
    struct tls_scan_bss_t *bss = NULL;

    if (oneshot_bss)
    {
        bss = (struct tls_scan_bss_t*)oneshot_bss;
        for (i = 0; i < bss->count; i++)
        {
            if ((crc == get_crc_8(bss->bss[i].ssid, bss->bss[i].ssid_len))
            	&& (*ssid_len ==  bss->bss[i].ssid_len))
            {
            	MEMCPY(ssid, bss->bss[i].ssid, bss->bss[i].ssid_len);
            	*(ssid + bss->bss[i].ssid_len) = '\0';
//              *ssid_len = bss->bss[i].ssid_len;
            	return 1;
            }
        }
    }
    return 0;
}
#endif
void tls_oneshot_find_chlist(u8 *ssid, u8 ssid_len, u16 *chlist)
{
    int i = 0;
    struct tls_scan_bss_t *bss = NULL;

    if (oneshot_bss)
    {
        bss = (struct tls_scan_bss_t*)oneshot_bss;
        for (i = 0; i < bss->count; i++)
        {
            if ((ssid_len == bss->bss[i].ssid_len) && (memcmp(bss->bss[i].ssid, ssid, ssid_len) == 0))
            {
                *chlist |= 1<<(bss->bss[i].channel -1);
            }
        }
    }
}


void tls_oneshot_switch_channel_tim_start(void *ptmr, void *parg)
{
	if (oneshot_msg_q)
	{
		tls_os_queue_send(oneshot_msg_q, (void *)ONESHOT_SWITCH_CHANNEL, 0);
	}
}

void tls_oneshot_switch_channel_tim_stop(void)
{
	if (gWifiSwitchChanTim)
	{
		tls_os_timer_stop(gWifiSwitchChanTim);
	}

	if (oneshot_msg_q)
	{
		tls_os_queue_send(oneshot_msg_q, (void *)ONESHOT_STOP_CHAN_SWITCH, 0);
	}
}

void tls_oneshot_switch_channel_tim_temp_stop(void)
{
	if (gWifiSwitchChanTim)
	{
		tls_os_timer_stop(gWifiSwitchChanTim);
	}
	if (oneshot_msg_q)
	{	
		tls_os_queue_send(oneshot_msg_q, (void *)ONESHOT_STOP_TMP_CHAN_SWITCH, 0);
	}
}

void tls_oneshot_handshake_timeout(void *ptmr, void *parg)
{
	if (oneshot_msg_q)
	{
		tls_os_queue_send(oneshot_msg_q, (void *)ONESHOT_HANDSHAKE_TIMEOUT, 0);
	}
}

void tls_oneshot_recv_timeout(void *ptmr, void *parg)
{
	if (oneshot_msg_q)
	{
	    tls_os_queue_send(oneshot_msg_q, (void*)ONESHOT_RECV_TIMEOUT, 0);
	}
}
#endif
void tls_oneshot_data_clear(void)
{
	if (oneshot_msg_q)
	{
		tls_os_queue_send(oneshot_msg_q, (void *)ONESHOT_STOP_DATA_CLEAR, 0);
	}
}

#if TLS_CONFIG_WEB_SERVER_MODE
void tls_oneshot_send_web_connect_msg(void)
{
	if (oneshot_msg_q)
	{
		tls_os_queue_send(oneshot_msg_q, (void *)AP_WEB_S_MSG_RECEIVE_DATA, 0);
	}
}
#endif
void wm_oneshot_netif_status_event(u8 status )
{

	if (oneshot_msg_q)
	{
		switch(status)
		{
			case NETIF_IP_NET2_UP:
				tls_os_queue_send(oneshot_msg_q, (void *)AP_SOCK_S_MSG_SOCKET_CREATE, 0);
				break;

			case NETIF_WIFI_SOFTAP_FAILED:
				tls_os_queue_send(oneshot_msg_q, (void *)AP_SOCK_S_MSG_WJOIN_FAILD, 0);
				break;

			case NETIF_IP_NET_UP:
				tls_os_queue_send(oneshot_msg_q,(void *)ONESHOT_NET_UP,0);
				break;
				
			default:
				break;
		}
	}

}
#if TLS_CONFIG_SOCKET_RAW
void wm_oneshot_send_mac(void)
{
	int idx;
	int socket_num = 0;
	u8 mac_addr[8];
	struct tls_socket_desc socket_desc = {SOCKET_CS_MODE_CLIENT};
	socket_desc.cs_mode = SOCKET_CS_MODE_CLIENT;
	socket_desc.protocol = SOCKET_PROTO_UDP;
#if TLS_CONFIG_LWIP_VER2_0_3
	IP_ADDR4(&socket_desc.ip_addr, 255, 255, 255, 255);
#else
	for(idx = 0; idx < 4; idx++){
		socket_desc.ip_addr[idx] = 255;
	}
#endif
	socket_desc.port = 65534;
	socket_num = tls_socket_create(&socket_desc);
	memset(mac_addr,0,sizeof(mac_addr));
	tls_get_mac_addr(mac_addr);
	tls_os_time_delay(50);
	for(idx = 0;idx < 50;idx ++)
	{
		if (tls_wifi_get_oneshot_flag())
		{
			break;
		}
		tls_socket_send(socket_num,mac_addr, 6);
		tls_os_time_delay(50);
	}
	tls_socket_close(socket_num);
	socket_num = 0;
}
#else
void wm_oneshot_send_mac(void)
{
	int idx;
	int sock = 0;
	u8 mac_addr[8];
	struct sockaddr_in sock_addr;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sock < 0)
	{
		return;
	}
	memset(&sock_addr, 0, sizeof(struct sockaddr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = IPADDR_BROADCAST;
	sock_addr.sin_port = htons(65534);

	memset(mac_addr,0,sizeof(mac_addr));
	tls_get_mac_addr(mac_addr);
	tls_os_time_delay(50);
	for(idx = 0;idx < 50;idx ++)
	{
		if (tls_wifi_get_oneshot_flag())
		{
			break;
		}
		sendto(sock, mac_addr, 6, 0, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr));
		tls_os_time_delay(50);
	}
	closesocket(sock);
}
#endif

void tls_oneshot_task_handle(void *arg)
{
    void *msg;
#if TLS_CONFIG_UDP_ONE_SHOT
    static int chanCnt = 0;
#endif
    for(;;)
    {
        tls_os_queue_receive(oneshot_msg_q, (void **)&msg, 0, 0);
        switch((u32)msg)
        {
#if TLS_CONFIG_UDP_ONE_SHOT
            case ONESHOT_SCAN_START:
            if (0 == first_start_oneshot_flag){
			tls_wifi_scan_result_cb_register(tls_oneshot_scan_result_cb);
			while (WM_SUCCESS !=tls_wifi_scan())
			{
				tls_os_time_delay(1);
			}
            }else{
			    tls_oneshot_scan_result_cb();
            }
            break;
            case ONESHOT_SCAN_FINISHED:
            if (0 == first_start_oneshot_flag){
			    tls_oneshot_scan_result_deal();
            }
            chanCnt = 0;
            wifi_change_chanel(airwifichan[chanCnt], airchantype[chanCnt]);

#if TLS_CONFIG_AIRKISS_MODE_ONESHOT
            tls_airkiss_start();
#endif
            tls_wifi_data_recv_cb_register((tls_wifi_data_recv_callback)tls_wifi_dataframe_recv);	

            ONESHOT_DBG("scan finished time:%d,%d,%d\n",chanCnt , uctotalchannum,(tls_os_get_time() - oneshottime)*1000/HZ);
            /*start ONESHOT_TIMER_START*/
            if (gWifiSwitchChanTim)
            {
			    tls_os_timer_stop(gWifiSwitchChanTim);
			    tls_os_timer_change(gWifiSwitchChanTim, TLS_ONESHOT_SWITCH_TIMER_MAX);
            }
			
            if (gWifiRecvTimOut)
            {
                tls_os_timer_stop(gWifiRecvTimOut);
                tls_os_timer_change(gWifiRecvTimOut, TLS_ONESHOT_RECV_TIME);
            }
            break;

            case ONESHOT_SWITCH_CHANNEL:
            chanCnt++;
            if (chanCnt >= uctotalchannum)
            {
                chanCnt = 0;		
            }
			

            wifi_change_chanel(airwifichan[chanCnt], airchantype[chanCnt]);
            ONESHOT_DBG("chan:%d,bandwidth:%d\n", airwifichan[chanCnt], airchantype[chanCnt]);
#if TLS_CONFIG_AIRKISS_MODE_ONESHOT
		    tls_oneshot_airkiss_change_channel();
#endif

		    if (gWifiSwitchChanTim)
		    {
			    tls_os_timer_stop(gWifiSwitchChanTim);
			    tls_os_timer_change(gWifiSwitchChanTim, TLS_ONESHOT_SWITCH_TIMER_MAX);
		    }
            break;

            case ONESHOT_STOP_TMP_CHAN_SWITCH:
		    {
				if (gWifiSwitchChanTim)
				{
				    tls_os_timer_stop(gWifiSwitchChanTim);
				}
				if (gWifiHandShakeTimOut)
				{
				    tls_os_timer_stop(gWifiHandShakeTimOut);
				    tls_os_timer_change(gWifiHandShakeTimOut, TLS_ONESHOT_RESTART_TIME);
				}
            }
            break;	

            case ONESHOT_STOP_CHAN_SWITCH:
		    first_start_oneshot_flag = 0;
		    ONESHOT_DBG("stop channel time:%d, %d,%d\n",(chanCnt >=1)?chanCnt:(uctotalchannum -1), (chanCnt >= 1)?(airwifichan[chanCnt-1] +1):(airwifichan[uctotalchannum-1] +1), (tls_os_get_time() - oneshottime)*1000/HZ);
		    if (gWifiSwitchChanTim)
		    {
			    tls_os_timer_stop(gWifiSwitchChanTim);
		    }
				
		    if (gWifiHandShakeTimOut)
		    {
		        tls_os_timer_stop(gWifiHandShakeTimOut);
		    }
				
			if (gWifiRecvTimOut)
			{
				tls_os_timer_stop(gWifiRecvTimOut);
				tls_os_timer_change(gWifiRecvTimOut, TLS_ONESHOT_RECV_TIME);
			}

			
            break;
            
            case ONESHOT_HANDSHAKE_TIMEOUT:
                if (gWifiSwitchChanTim)
                {
                    tls_os_timer_stop(gWifiSwitchChanTim);
                    tls_os_timer_change(gWifiSwitchChanTim, TLS_ONESHOT_SWITCH_TIMER_MAX);
                }
           break;

           case ONESHOT_RECV_TIMEOUT:
           first_start_oneshot_flag = 0;
           ONESHOT_DBG("timeout to oneshot\n");
#if TLS_CONFIG_AIRKISS_MODE_ONESHOT
           tls_oneshot_airkiss_change_channel();
#endif
           tls_wifi_set_listen_mode(0);
           tls_oneshot_stop_clear_data();
           tls_wifi_set_oneshot_flag(1);
           break;
#endif            
           case ONESHOT_STOP_DATA_CLEAR:
           ONESHOT_DBG("stop oneshot to connect:%d\n", (tls_os_get_time() - oneshottime)*1000/HZ);
           tls_oneshot_stop_clear_data();
           break;
		
           case ONESHOT_NET_UP:
           printf("oneshot net up\n");
           tls_netif_remove_status_event(wm_oneshot_netif_status_event);
           if (0 == gucConfigMode) {
#if TLS_CONFIG_AIRKISS_MODE_ONESHOT
               if (is_airkiss)
               {
                   oneshot_airkiss_send_reply();
               }else
#endif
               {		
                   wm_oneshot_send_mac();
               }
           }

           break;

#if TLS_CONFIG_AP_MODE_ONESHOT
#if TLS_CONFIG_SOCKET_MODE
           case AP_SOCK_S_MSG_SOCKET_RECEIVE_DATA:
           if (1 == gucConfigMode)
           {
               int ret = 0;
               /*Receive data, self processing*/
               gucssidData[0] = '\0';
               memset(gucbssidData, 0, 6);
               ret = tls_wifi_decode_new_oneshot_data((const u8 *)sock_rx->sock_rx_data,gucpwdData, gucbssidData, gucssidData, NULL);
               if (0 == ret){
                   if ((0 == tls_is_zero_ether_addr(gucbssidData))&&(gucssidData[0] == '\0')){
                       gucbssidokflag = 1;
                       gucpwdokflag = 1;
                   }else{
                       gucssidokflag = 1;
                       gucpwdokflag = 1;
                   }
    
                   tls_wifi_send_oneshotinfo((const u8 *)sock_rx->sock_rx_data, sock_rx->sock_data_len, APSKT_MAX_ONESHOT_NUM);
                   if (((1== gucssidokflag)||(1 == gucbssidokflag)) && (1 == gucpwdokflag)){
                       if (gucbssidokflag){
                           ONESHOT_INF("[SOCKB]BSSID:%x:%x:%x:%x:%x:%x\n",  gucbssidData[0],  gucbssidData[1],  gucbssidData[2],  gucbssidData[3],  gucbssidData[4],  gucbssidData[5]);
                           ONESHOT_INF("[SOCKB]PASSWORD:%s\n", gucpwdData);
                           tls_wifi_oneshot_connect_by_bssid(gucbssidData, gucpwdData);
                       }else {
                           ONESHOT_INF("[SOCKS]SSID:%s\n", gucssidData);
                           ONESHOT_INF("[SOCKS]PASSWORD:%s\n", gucpwdData);
                           tls_wifi_oneshot_connect(gucssidData, gucpwdData);
                       }
                   }
               }
               gucRawValid = 0;
           }
           break;
#endif	

#if TLS_CONFIG_WEB_SERVER_MODE
           case AP_WEB_S_MSG_RECEIVE_DATA:        
           if (2 == gucConfigMode)
           {
               tls_os_time_delay(HZ*5);
               httpd_deinit();
            
               ONESHOT_INF("[WEB]SSID:%s\n", gucssidData);
               ONESHOT_INF("[WEB]PASSWORD:%s\n", gucpwdData);
               tls_wifi_oneshot_connect(gucssidData, gucpwdData);
           }
           break;
#endif

           case AP_SOCK_S_MSG_SOCKET_CREATE:
#if TLS_CONFIG_WEB_SERVER_MODE
           if (2 == gucConfigMode)
           {
               tls_webserver_init();
           }
#endif

#if TLS_CONFIG_SOCKET_MODE
           if (1 == gucConfigMode)
           {
               create_tcp_server_socket();
           }
#endif
           break;
#if  TLS_CONFIG_SOCKET_MODE
           case AP_SOCK_S_MSG_WJOIN_FAILD:
           if (1 == gucConfigMode)
           {
               if((sock_rx)&&(sock_rx->socket_num > 0))
               {
                   free_socket();
                   sock_rx->socket_num = 0;
               }
           }
           break;
#endif		
#endif		
           default:
           break;	   
        }
    
    }
}


void tls_oneshot_task_create(void)
{
	if (NULL == oneshot_msg_q){
	
		memset(&OneshotTaskStk[0], 0, sizeof(OS_STK)*ONESHOT_TASK_SIZE);
		
		tls_os_queue_create(&oneshot_msg_q, ONESHOT_MSG_QUEUE_SIZE);
		
		tls_os_task_create(NULL, NULL,
				tls_oneshot_task_handle,
						NULL,
						(void *)&OneshotTaskStk[0], 		 /* 任务栈的起始地址 */
						ONESHOT_TASK_SIZE * sizeof(u32), /* 任务栈的大小	   */
						TLS_ONESHOT_TASK_PRIO,
						0);
	}
}

void tls_wifi_start_oneshot(void)
{
	tls_oneshot_stop_clear_data();
	tls_oneshot_init_data();
	tls_oneshot_task_create();
	tls_netif_remove_status_event(wm_oneshot_netif_status_event);

	if(0 == gucConfigMode)
	{
#if TLS_CONFIG_UDP_ONE_SHOT	
		if (NULL == gWifiSwitchChanTim){
			tls_os_timer_create(&gWifiSwitchChanTim,tls_oneshot_switch_channel_tim_start, NULL,TLS_ONESHOT_SWITCH_TIMER_MAX,FALSE,NULL);
		}

		if (NULL == gWifiHandShakeTimOut)
		{
			tls_os_timer_create(&gWifiHandShakeTimOut,tls_oneshot_handshake_timeout, NULL,TLS_ONESHOT_RETRY_TIME,FALSE,NULL);
		}
		if (NULL == gWifiRecvTimOut)
		{
		    tls_os_timer_create(&gWifiRecvTimOut, tls_oneshot_recv_timeout, NULL, TLS_ONESHOT_RETRY_TIME, FALSE, NULL);        
		}		
		tls_oneshot_scan_start();
#endif		
	}
	else{
#if TLS_CONFIG_AP_MODE_ONESHOT
		tls_netif_add_status_event(wm_oneshot_netif_status_event);
		soft_ap_create();
#endif
	}

#if TLS_CONFIG_QQLINK_MODE_ONESHOT
	tls_start_qq_link();
#endif
}


/***************************************************************************
* Function: tls_wifi_set_oneshot_flag
*
* Description: This function is used to set oneshot flag.
*
* Input: flag 0:one shot  closed
* 		      1:one shot  open
* Output: None
*
* Return: None
*
* Date : 2014-6-11
****************************************************************************/
void tls_wifi_set_oneshot_flag(u8 flag)
{
	if (1 == flag)
	{
		oneshottime = tls_os_get_time();
		ONESHOT_DBG("wait oneshot[%d] ...\n",oneshottime);

		guconeshotflag = flag;
		tls_wifi_disconnect();
		tls_wifi_softap_destroy();	
		if ((1 == gucConfigMode) ||(2 == gucConfigMode)) /*ap mode*/
		{
			tls_wifi_set_listen_mode(0);
		}
		else /*udp mode*/
		{
			tls_wifi_set_listen_mode(1);
		}
		tls_wifi_start_oneshot();
	}
	else
	{
		if((1 == gucConfigMode) ||(2 == gucConfigMode))
		{
#if TLS_CONFIG_AP_MODE_ONESHOT
			if (guconeshotflag)
			{
				tls_wifi_softap_destroy();
			}
#endif
		}
		guconeshotflag = flag;
		tls_wifi_set_listen_mode(0);
		tls_oneshot_data_clear();
	}
}

/***************************************************************************
* Function: 	tls_wifi_get_oneshot_flag
*
* Description: This function is used to get oneshot flag.
*
* Input:  		None
*
* Output: 	None
*
* Return:
*			0:one shot  closed
* 		    	1:one shot  open
*
* Date : 2014-6-11
****************************************************************************/
int tls_wifi_get_oneshot_flag(void)
{
	return guconeshotflag;
}

/***************************************************************************
* Function: tls_wifi_set_oneshot_config_mode
*
* Description: This function is used to set oneshot config mode.
*
* Input: flag 0:one shot config
* 		     1:softap socket config
*		     2:softap webserver config
* Output: None
*
* Return: None
*
* Date : 2016-01-05
****************************************************************************/
void tls_wifi_set_oneshot_config_mode(u8 flag)
{
    switch (flag)
    {
        case 0:/*UDP*/
        case 1:/*AP+socket*/
        case 2:/*AP+WEBSERVER*/
            gucConfigMode = flag;
        break;

        default:
            printf("net cfg mode not support\n");
        break;
    }
}

u8 tls_wifi_get_oneshot_config_mode(void)
{
	return gucConfigMode;
}

