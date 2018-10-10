


/* lwIP includes */
#include "lwip/sys.h"
#include "lwip/api.h"
#include "lwip/tcpip.h"
#include "lwip/memp.h"
#include "lwip/stats.h"
#include "lwip/dhcp.h"
#include "lwip/dns.h"
#include "netif/ethernetif.h"
#include "ethernet.h"
#include "wm_params.h"
#include "wm_mem.h"
#include <string.h>
#if TLS_CONFIG_AP
#include "dhcp_server.h"
#include "dns_server.h"
#include "lwip/alg.h"
#include "tls_wireless.h"
#endif
#if TLS_CONFIG_SOCKET_RAW
#include "tls_netconn.h"
#endif
#if TLS_CONFIG_RMMS
#include "tls_sys.h"
#include "rmms.h"
#endif
#include "wm_wifi.h"
extern int tls_wifi_get_oneshot_flag(void);
extern int tls_dhcp_get_ip_timeout_flag(void);

static struct tls_ethif *ethif = NULL;
static struct netif *nif = NULL;
static struct tls_netif_status_event netif_status_event;
static void netif_status_changed(struct netif *netif)
{
    struct tls_netif_status_event *status_event;
    if (netif_is_up(netif))
    {
    dl_list_for_each(status_event, &netif_status_event.list, struct tls_netif_status_event, list)
    {
            if(status_event->status_callback)
        {
        	if (0 == tls_wifi_get_oneshot_flag())
			{
                    if (tls_dhcp_get_ip_timeout_flag() &&((netif->ip_addr.addr == 0) ||(netif->ip_addr.addr == 0xFFFFFFFF)))
                    {
                        status_event->status_callback(NETIF_WIFI_JOIN_FAILED);
                    }else{
	                    status_event->status_callback(NETIF_IP_NET_UP);
                    }
	            }
            }
        }
    }
}

#if TLS_CONFIG_AP
static struct tls_ethif *ethif2 = NULL;
static void netif_status_changed2(struct netif *netif)
{
    struct tls_netif_status_event *status_event;

    if (netif_is_up(netif))
	            {
        dl_list_for_each(status_event, &netif_status_event.list, struct tls_netif_status_event, list)
        {
            if(status_event->status_callback)
            {
            	status_event->status_callback(NETIF_IP_NET2_UP);
        	}
        }
    }
}
#endif

static void wifi_status_changed(u8 status)
{
    struct tls_netif_status_event *status_event;
    dl_list_for_each(status_event, &netif_status_event.list, struct tls_netif_status_event, list)
    {
        if(status_event->status_callback != NULL)
        {
            switch(status)
            {
                case WIFI_JOIN_SUCCESS:
                    status_event->status_callback(NETIF_WIFI_JOIN_SUCCESS);
                    break;
                case WIFI_JOIN_FAILED:
                    status_event->status_callback(NETIF_WIFI_JOIN_FAILED);
                    break;
                case WIFI_DISCONNECTED:
                    status_event->status_callback(NETIF_WIFI_DISCONNECTED);
                    break;
#if TLS_CONFIG_AP
                case WIFI_SOFTAP_SUCCESS:
                    status_event->status_callback(NETIF_WIFI_SOFTAP_SUCCESS);
                    break;
                case WIFI_SOFTAP_FAILED:
                    status_event->status_callback(NETIF_WIFI_SOFTAP_FAILED);
                    break;
                case WIFI_SOFTAP_CLOSED:
                    status_event->status_callback(NETIF_WIFI_SOFTAP_CLOSED);
                    break;
#endif
                default:
                    break;
            }
        }
    }
}
/*************************************************************************** 
* Function: Tcpip_stack_init
*
* Description: This function is init ip stack. 
* 
* Input: 
*		ipaddr:  
*		netmask: 
*       gateway: 
* Output: 
* 
* Return: 
*		netif: Init IP Stack OK
*       NULL : Init IP Statck Fail Because no memory
* Date : 2014-6-4 
****************************************************************************/ 
struct netif *Tcpip_stack_init()
{
#if TLS_CONFIG_AP
    struct netif *nif4apsta = NULL;
#endif

	/*Register Ethernet Rx Data callback From wifi*/
	tls_ethernet_data_rx_callback(ethernetif_input);
#if TLS_CONFIG_AP_OPT_FWD
	tls_ethernet_ip_rx_callback(alg_input);
#endif
	
    /* Setup lwIP. */
    tcpip_init(NULL, NULL);

#if TLS_CONFIG_AP
    /* add net info for apsta's ap */
    nif4apsta = (struct netif *)tls_mem_alloc(sizeof(struct netif));
    if (nif4apsta == NULL)
        return NULL;
#endif

    /*Add Net Info to Netif, default */
    nif = (struct netif *)tls_mem_alloc(sizeof(struct netif));
    if (nif == NULL)
    {
#if TLS_CONFIG_AP
        tls_mem_free(nif4apsta);
#endif
        return NULL;
    }

#if TLS_CONFIG_AP
    memset(nif4apsta, 0, sizeof(struct netif));
    //nif->next = nif4apsta;
    netifapi_netif_add(nif4apsta, IPADDR_ANY, IPADDR_ANY, IPADDR_ANY, NULL, ethernetif_init, tcpip_input);
    netif_set_status_callback(nif4apsta, netif_status_changed2);
#endif

    memset(nif, 0, sizeof(struct netif));
    netifapi_netif_add(nif, IPADDR_ANY,IPADDR_ANY,IPADDR_ANY,NULL,ethernetif_init,tcpip_input);
    netifapi_netif_set_default(nif);
    dl_list_init(&netif_status_event.list);
    netif_set_status_callback(nif, netif_status_changed);
    tls_wifi_status_change_cb_register(wifi_status_changed);
    return nif;
}

#ifndef TCPIP_STACK_INIT
#define TCPIP_STACK_INIT Tcpip_stack_init
#endif

/*************************************************************************** 
* Function: tls_ethernet_init 
* Description: Initialize ethernet. 
* 
* Input: ipcfg: Ip parameters. 
*           wireless_protocol: See #define TLS_PARAM_IEEE80211_XXXX
* 
* Output: None
* 
* Return: 0: Succeed. 
* 
* Date : 2014-6-10 
****************************************************************************/
int tls_ethernet_init()
{
    if(ethif)
        tls_mem_free(ethif);
    ethif = tls_mem_alloc(sizeof(struct tls_ethif));
    memset(ethif, 0, sizeof(struct tls_ethif));

#if TLS_CONFIG_AP
    if(ethif2)
        tls_mem_free(ethif2);
    ethif2 = tls_mem_alloc(sizeof(struct tls_ethif));
    memset(ethif2, 0, sizeof(struct tls_ethif));
#endif
    TCPIP_STACK_INIT();
#if TLS_CONFIG_SOCKET_RAW
    tls_net_init();
#endif
    return 0;
}

/*************************************************************************** 
* Function: tls_netif_get_ethif 
* Description: Get the ip parameters stored in tls_ethif struct.
* 
* Input: None
* 
* Output: None
* 
* Return: Pointer to struct tls_ethif. 
* 
* Date : 2014-6-10  
****************************************************************************/ 
struct tls_ethif *tls_netif_get_ethif(void)
{
    ip_addr_t dns1,dns2;
    MEMCPY((char *)&ethif->ip_addr.addr, &nif->ip_addr.addr, 4);
    MEMCPY((char *)&ethif->netmask.addr, &nif->netmask.addr, 4);
    MEMCPY((char *)&ethif->gw.addr, &nif->gw.addr, 4);
    dns1 = dns_getserver(0);
    MEMCPY(&ethif->dns1.addr, (char *)&dns1.addr, 4);
    dns2 = dns_getserver(1);
    MEMCPY(&ethif->dns2.addr, (char *)&dns2.addr, 4);
	ethif->status = netif_is_up(nif);//nif->flags&NETIF_FLAG_UP;
    return ethif;
}

/*************************************************************************** 
* Function: tls_dhcp_start 
* Description: Start DHCP negotiation for a network interface.
* 
* Input: None
* 
* Output: None
* 
* Return: 0: Succeed; minus: Failed. 
* 
* Date : 2014-6-10  
****************************************************************************/
err_t tls_dhcp_start(void)
{
	
	if (nif->flags & NETIF_FLAG_UP) 
	  nif->flags &= ~NETIF_FLAG_UP;
	
    return netifapi_dhcp_start(nif);
}

/*************************************************************************** 
* Function: tls_dhcp_stop 
* Description: Remove the DHCP client from the interface.
* 
* Input: None
* 
* Output: None
* 
* Return: 0: Succeed; minus: Failed. 
* 
* Date : 2014-6-10  
****************************************************************************/ 
err_t tls_dhcp_stop(void)
{
    return netifapi_dhcp_stop(nif);
}

/*************************************************************************** 
* Function: tls_netif_set_addr 
* Description: Change IP address configuration for a network interface (including netmask
*                   and default gateway).
* 
* Input: ipaddr:      the new IP address
*           netmask:  the new netmask
*           gw:           the new default gateway
* 
* Output: None
* 
* Return: 0: Succeed; minus: Failed. 
* 
* Date : 2014-6-10  
****************************************************************************/ 
err_t tls_netif_set_addr(ip_addr_t *ipaddr, ip_addr_t *netmask, ip_addr_t *gw)
{
    return netifapi_netif_set_addr(nif, ipaddr, netmask, gw);
}

/*************************************************************************** 
* Function: tls_netif_set_addr 
* Description: Initialize one of the DNS servers.
* 
* Input: numdns:     the index of the DNS server to set must be < DNS_MAX_SERVERS
*           dnsserver:  IP address of the DNS server to set
* 
* Output: None
* 
* Return: None
* 
* Date : 2014-6-10  
****************************************************************************/ 
void tls_netif_dns_setserver(u8_t numdns, ip_addr_t *dnsserver)
{
    dns_setserver(numdns, dnsserver);
}

/*************************************************************************** 
* Function: tls_netif_set_up 
* Description: Bring an interface up, available for processing traffic.
* 
* Input: None
* 
* Output: None
* 
* Return: 0: Succeed; minus: Failed. 
* 
* Date : 2014-6-10  
****************************************************************************/ 
err_t tls_netif_set_up(void)
{
    return netifapi_netif_set_up(nif);
}

/*************************************************************************** 
* Function: tls_netif_set_down 
* Description: Bring an interface down, disabling any traffic processing.
* 
* Input: None
* 
* Output: None
* 
* Return: 0: Succeed; minus: Failed. 
* 
* Date : 2014-6-10  
****************************************************************************/ 
err_t tls_netif_set_down(void)
{
    return netifapi_netif_set_down(nif);
}

/*************************************************************************** 
* Function: tls_netif_add_status_event 
* Description: Add netif status changed callback to event list, if exists, do nothing.
* 
* Input: event_fn: A pointer to tls_netif_status_event_fn.
* 
* Output: None
* 
* Return: 0: Succeed; minus: Failed. 
* 
* Date : 2014-6-10  
****************************************************************************/ 
err_t tls_netif_add_status_event(tls_netif_status_event_fn event_fn)
{
    u32_t cpu_sr;
    struct tls_netif_status_event *evt;
    //if exist, remove from event list first.
    tls_netif_remove_status_event(event_fn);
    evt = tls_mem_alloc(sizeof(struct tls_netif_status_event));
    if(evt==NULL)
        return -1;
    memset(evt, 0, sizeof(struct tls_netif_status_event));
    evt->status_callback = event_fn;
    cpu_sr = tls_os_set_critical();
    dl_list_add_tail(&netif_status_event.list, &evt->list);
    tls_os_release_critical(cpu_sr);

	return 0;
}

/*************************************************************************** 
* Function: tls_netif_remove_status_event 
* Description: Remove netif status changed callback from event list, if not exists, do nothing.
* 
* Input: event_fn: A pointer to tls_netif_status_event_fn.
* 
* Output: None
* 
* Return: 0: Succeed; minus: Failed. 
* 
* Date : 2014-6-10  
****************************************************************************/ 
err_t tls_netif_remove_status_event(tls_netif_status_event_fn event_fn)
{
    struct tls_netif_status_event *status_event;
    bool is_exist = FALSE;
    u32_t cpu_sr;
    if(dl_list_empty(&netif_status_event.list))
        return 0;
    dl_list_for_each(status_event, &netif_status_event.list, struct tls_netif_status_event, list)
    {
        if(status_event->status_callback == event_fn)
        {
            is_exist = TRUE;
            break;
        }
    }
    if(is_exist)
    {
        cpu_sr = tls_os_set_critical();
        dl_list_del(&status_event->list);
        tls_os_release_critical(cpu_sr);
        tls_mem_free(status_event);
    }
		return 0;
}

#if TLS_CONFIG_RMMS
/*************************************************************************** 
* Function: tls_rmms_start
* Description: Start remote manager server.
* 
* Input:  None
* 
* Output: None
* 
* Return: The rmms error code:
*             RMMS_ERR_SUCCESS - No error
*             RMMS_ERR_MEM - Out of memory
*             RMMS_ERR_LINKDOWN - The NIF is inactive
* 
* Date : 2015-7-20
****************************************************************************/
s8_t tls_rmms_start(void)
{
    return RMMS_Init(nif);
}

/*************************************************************************** 
* Function: tls_rmms_stop
* Description: Disable remote manager server.
* 
* Input:  None
* 
* Output: None
* 
* Return: None
* 
* Date : 2015-7-20
****************************************************************************/
void tls_rmms_stop(void)
{
    RMMS_Fini();
}
#endif

#if TLS_CONFIG_AP
struct tls_ethif * tls_netif_get_ethif2(void)
{
    ip_addr_t dns1,dns2;
    MEMCPY((char *)&ethif2->ip_addr.addr, &nif->next->ip_addr.addr, 4);
    MEMCPY((char *)&ethif2->netmask.addr, &nif->next->netmask.addr, 4);
    MEMCPY((char *)&ethif2->gw.addr, &nif->next->gw.addr, 4);
    dns1.addr = nif->next->ip_addr.addr;
    MEMCPY(&ethif2->dns1.addr, (char *)&dns1.addr, 4);
    dns2.addr = 0;
    MEMCPY(&ethif2->dns2.addr, (char *)&dns2.addr, 4);
	ethif2->status = netif_is_up(nif->next);
    return ethif2;
}

INT8S tls_dhcps_start(void)
{
    return DHCPS_Start(nif->next);
}
void tls_dhcps_stop(void)
{
    DHCPS_Stop();
}

INT8S tls_dnss_start(INT8U * DnsName)
{
    return DNSS_Start(nif->next, DnsName);
}
void tls_dnss_stop(void)
{
    DNSS_Stop();
}
struct ip_addr *tls_dhcps_getip(const u8_t *mac)
{
	return DHCPS_GetIpByMac(mac);
}

err_t tls_netif2_set_up(void)
{
    return netifapi_netif_set_up(nif->next);
}

/*************************************************************************** 
* Function: tls_netif2_set_down
* Description: Bring an interface down, disabling any traffic processing.
* 
* Input:  None
* 
* Output: None
* 
* Return: 0: Succeed; minus: Failed. 
* 
* Date : 2015-3-10
****************************************************************************/
err_t tls_netif2_set_down(void)
{
    return netifapi_netif_set_down(nif->next);
}

/*************************************************************************** 
* Function: tls_netif2_set_addr
* Description: Change IP address configuration for a network interface (including netmask
*                   and default gateway).
* 
* Input: ipaddr:      the new IP address
*        netmask:     the new netmask
*        gw:          the new default gateway
* 
* Output: None
* 
* Return: 0: Succeed; minus: Failed. 
* 
* Date : 2015-3-10
****************************************************************************/
err_t tls_netif2_set_addr(ip_addr_t *ipaddr,
                          ip_addr_t *netmask,
                          ip_addr_t *gw)
{
    return netifapi_netif_set_addr(nif->next, ipaddr, netmask, gw);
}
#endif

struct netif *tls_get_netif(void)
{
    return nif;
}
