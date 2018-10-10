/*****************************************************************************
*
* File Name : wm_apsta_demo.c
*
* Description: apsta demo function
*
* Copyright (c) 2015 Winner Micro Electronic Design Co., Ltd.
* All rights reserved.
*
* Author : LiLimin
*
* Date : 2015-3-24
*****************************************************************************/
#include <string.h>
#include "wm_include.h"
#include "wm_netif.h"
#include "wm_demo.h"
#include "tls_common.h"
#include "lwip/netif.h"
#include "wm_sockets.h"
#include "lwip/inet.h"
#if TLS_CONFIG_LWIP_VER2_0_3

#else
#include "sockets.h"
#endif

#if DEMO_APSTA

#define         APSTA_DEMO_TASK_PRIO             38
#define         APSTA_DEMO_TASK_SIZE             256
#define         APSTA_DEMO_QUEUE_SIZE            4

static bool ApstaDemoIsInit = false;
static OS_STK   ApstaDemoTaskStk[APSTA_DEMO_TASK_SIZE];
static tls_os_queue_t *ApstaDemoTaskQueue = NULL;

#define         APSTA_DEMO_CMD_SOFTAP_CREATE        0x0
#define         APSTA_DEMO_CMD_STA_JOIN_NET         0x1
#define         APSTA_DEMO_CMD_SOCKET_DEMO          0x2
#define         APSTA_DEMO_CMD_SOFTAP_CLOSE         0x3
#define         APSTA_DEMO_CMD_STA_DISCONNECT       0x4

#define         APSTA_DEMO_SOCKET_DEMO_REMOTE_PORT  65530
#define         APSTA_DEMO_SOCKET_DEMO_LOCAL_PORT   65531

static char apsta_demo_ssid[33];
static char apsta_demo_pwd[65];
static char apsta_demo_apssid[33];

extern struct netif *tls_get_netif(void);
extern u8 *wpa_supplicant_get_mac(void);
extern u8 *hostapd_get_mac(void);

static void apsta_demo_client_event(u8 *mac, enum tls_wifi_client_event_type event)
{
    printf("client "MACSTR" is %s\r\n", MAC2STR(mac), event ? "offline" : "online");
}

static void apsta_demo_net_status(u8 status)
{
    struct netif *netif = tls_get_netif();

	switch(status)
	{
	    case NETIF_WIFI_JOIN_FAILED:
	        printf("sta join net failed\n");
			break;
		case NETIF_WIFI_DISCONNECTED:
	        printf("sta net disconnected\n");
			break;
		case NETIF_IP_NET_UP:
#ifdef TLS_CONFIG_LWIP_VER2_0_3
              printf("\nsta ip: %d.%d.%d.%d\n",  ip4_addr1(&netif->ip_addr),ip4_addr2(&netif->ip_addr),
                 ip4_addr3(&netif->ip_addr),ip4_addr4(&netif->ip_addr));
#else
			printf("sta ip: %d.%d.%d.%d.\n", ip4_addr1(&netif->ip_addr.addr),
                                             ip4_addr2(&netif->ip_addr.addr),
                                             ip4_addr3(&netif->ip_addr.addr),
                                             ip4_addr4(&netif->ip_addr.addr));
#endif
            tls_os_queue_send(ApstaDemoTaskQueue, (void *)APSTA_DEMO_CMD_SOCKET_DEMO, 0);
			break;
	    case NETIF_WIFI_SOFTAP_FAILED:
            printf("softap create failed\n");
	        break;
        case NETIF_WIFI_SOFTAP_CLOSED:
            printf("softap closed\n");
            tls_os_queue_send(ApstaDemoTaskQueue, (void *)APSTA_DEMO_CMD_STA_DISCONNECT, 0);
	        break;
        case NETIF_IP_NET2_UP:
#ifdef TLS_CONFIG_LWIP_VER2_0_3
             printf("\nsoftap ip: %d.%d.%d.%d\n",  ip4_addr1(&netif->next->ip_addr),ip4_addr2(&netif->next->ip_addr),
         		ip4_addr3(&netif->next->ip_addr),ip4_addr4(&netif->next->ip_addr));
#else
              printf("softap ip: %d.%d.%d.%d.\n", ip4_addr1(&netif->next->ip_addr.addr),
              									ip4_addr2(&netif->next->ip_addr.addr),
              									ip4_addr3(&netif->next->ip_addr.addr),
              									ip4_addr4(&netif->next->ip_addr.addr));
#endif
            tls_os_queue_send(ApstaDemoTaskQueue, (void *)APSTA_DEMO_CMD_STA_JOIN_NET, 0);
	        break;
		default:
			break;
	}
}


int soft_ap_demo(char *apssid)
{
	struct tls_softap_info_t apinfo;
	struct tls_ip_info_t ipinfo;
	u8 ret=0;
	u8 ssid_set = 0;

	u8* ssid = "soft_ap_demo";
	u8 ssid_len = strlen("soft_ap_demo");

	tls_wifi_set_oneshot_flag(0);          /*clear oneshot flag*/

	tls_param_get(TLS_PARAM_ID_BRDSSID, (void *)&ssid_set, (bool)0);
	if (0 == ssid_set){
		ssid_set = 1;
		tls_param_set(TLS_PARAM_ID_BRDSSID, (void *)&ssid_set, (bool)1); /*set flag to broadcast BSSID*/
	}
	if (apssid){
		ssid_len = strlen(apssid);
		MEMCPY(apinfo.ssid, apssid, ssid_len);
		apinfo.ssid[ssid_len]='\0';
	}else{
		MEMCPY(apinfo.ssid, ssid, ssid_len);
		apinfo.ssid[ssid_len]='\0';
	}
	
	apinfo.encrypt = 0;  /*0:open, 1:wep64, 2:wep128*/
	apinfo.channel = 11; /*channel*/
	apinfo.keyinfo.format = 1; /*format:0,hex, 1,ascii*/
	apinfo.keyinfo.index = 1;  /*wep index*/
	apinfo.keyinfo.key_len = strlen("1234567890123"); /*key length*/
	MEMCPY(apinfo.keyinfo.key, "1234567890123", strlen("1234567890123"));
	/*ip information:ip address,mask, DNS name*/
	ipinfo.ip_addr[0] = 192;
	ipinfo.ip_addr[1] = 168;
	ipinfo.ip_addr[2] = 8;
	ipinfo.ip_addr[3] = 1;
	ipinfo.netmask[0] = 255;
	ipinfo.netmask[1] = 255;
	ipinfo.netmask[2] = 255;
	ipinfo.netmask[3] = 0;
	MEMCPY(ipinfo.dnsname, "local.wm", sizeof("local.wm"));
	ret = tls_wifi_softap_create((struct tls_softap_info_t* )&apinfo, (struct tls_ip_info_t* )&ipinfo);
	printf("\n ap create %s ! \n", (ret == WM_SUCCESS)? "Successfully" : "Error");

	return ret;
}


static void apsta_demo_socket_demo(void)
{
    int i;
    int ret;
    int skt;
    u8  *mac;
    u8  *mac2;
    struct netif *netif;
    struct sockaddr_in addr;

    netif = tls_get_netif();

    /* 向sta所在网络发送广播包 */
	  printf("broadcast send mac in sta's bbs...\n");
    skt = socket(AF_INET, SOCK_DGRAM, 0);
    if (skt < 0)
        return;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip_addr_get_ip4_u32(&netif->ip_addr);
    addr.sin_port = htons(APSTA_DEMO_SOCKET_DEMO_LOCAL_PORT);

    ret = bind(skt, (struct sockaddr *)&addr, sizeof(addr));
    if (0 != ret)
    {
        close(skt);
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);/* x.x.x.255就不需要前面的绑定了 */
    addr.sin_port = htons(APSTA_DEMO_SOCKET_DEMO_REMOTE_PORT);

    mac   = wpa_supplicant_get_mac();

    for (i = 0; i < 20; i++)
    {
        sendto(skt, mac, ETH_ALEN, 0, (struct sockaddr *)&addr, sizeof(addr));
        tls_os_time_delay(10);
    }

    close(skt);


    /* 向softap所在网络发送广播包 */
	printf("broadcast send mac in softap's bbs...\n");
    skt = socket(AF_INET, SOCK_DGRAM, 0);
    if (skt < 0)
        return;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip_addr_get_ip4_u32(&netif->next->ip_addr);
    addr.sin_port = htons(APSTA_DEMO_SOCKET_DEMO_LOCAL_PORT);

    ret = bind(skt, (struct sockaddr *)&addr, sizeof(addr));
    if (0 != ret)
    {
        close(skt);
        return;
    }

	ret = setsockopt(skt, IPPROTO_IP, IP_MULTICAST_IF, &addr.sin_addr, sizeof(struct in_addr));
	if(0 != ret)
	{
        close(skt);
        return;		
	}

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);/* x.x.x.255就不需要前面的绑定了 */
    addr.sin_port = htons(APSTA_DEMO_SOCKET_DEMO_REMOTE_PORT);

    mac2 = hostapd_get_mac();

    for (i = 0; i < 300; i++)
    {
        sendto(skt, mac2, ETH_ALEN, 0, (struct sockaddr *)&addr, sizeof(addr));
        tls_os_time_delay(1 * HZ);
    }

    close(skt);

	printf("send mac end.\n");
		
	tls_os_queue_send(ApstaDemoTaskQueue, (void *)APSTA_DEMO_CMD_SOFTAP_CLOSE, 0);
    return;
}

static void apsta_demo_task(void *p)
{
    int ret;
    void *msg;

    for( ; ; )
    {
        ret = tls_os_queue_receive(ApstaDemoTaskQueue, (void **)&msg, 0, 0);
        if (!ret)
        {
            switch((u32)msg)
            {
                case APSTA_DEMO_CMD_STA_JOIN_NET:
                    ret = tls_wifi_connect((u8 *)apsta_demo_ssid, strlen(apsta_demo_ssid), (u8 *)apsta_demo_pwd, strlen(apsta_demo_pwd));
                    if (WM_SUCCESS == ret)
                        printf("\nplease wait connect net......\n");
                    else
                        printf("\napsta connect net failed, please check configure......\n");
                break;
                case APSTA_DEMO_CMD_SOFTAP_CREATE:
                    tls_wifi_softap_client_event_register(apsta_demo_client_event);
                    soft_ap_demo(&apsta_demo_apssid[0]);
                break;
                case APSTA_DEMO_CMD_SOCKET_DEMO:
                    apsta_demo_socket_demo();
                break;
                case APSTA_DEMO_CMD_SOFTAP_CLOSE:
                    tls_wifi_softap_destroy();
                break;
                case APSTA_DEMO_CMD_STA_DISCONNECT:
                    tls_wifi_disconnect();
                break;
                default:
                break;
            }
        }
    }
}


//apsta联网demo
//命令示例:t-apsta("ssid","pwd", "apsta");
int apsta_demo(char *ssid, char *pwd, char *apssid)
{
//    int ret = -1;

    memset(apsta_demo_ssid, 0, sizeof(apsta_demo_ssid));
    memset(apsta_demo_pwd, 0, sizeof(apsta_demo_pwd));
    
    strcpy(apsta_demo_ssid, ssid);
    printf("\nsta_ssid=%s\n", apsta_demo_ssid);
    
    strcpy(apsta_demo_pwd, pwd);
    printf("\nsta_password=%s\n", apsta_demo_pwd);

    strcpy(apsta_demo_apssid, apssid);
    printf("\nap_ssid=%s\n", apsta_demo_apssid);

    if (!ApstaDemoIsInit)
    {
        tls_os_task_create(NULL, NULL, apsta_demo_task,
                   (void *)0, (void *)ApstaDemoTaskStk,
                   APSTA_DEMO_TASK_SIZE * sizeof(u32),
                   APSTA_DEMO_TASK_PRIO, 0);
        
        tls_os_queue_create(&ApstaDemoTaskQueue, APSTA_DEMO_QUEUE_SIZE);
        
        tls_netif_add_status_event(apsta_demo_net_status);
        
        ApstaDemoIsInit = true;
    }
    tls_os_queue_send(ApstaDemoTaskQueue, (void *)APSTA_DEMO_CMD_SOFTAP_CREATE, 0);

    return WM_SUCCESS;
}
#endif
