 
#ifndef ETHERNET_H
#define ETHERNET_H

#include "lwip/ip_addr.h"
#include "list.h"
#include "wm_netif.h"

#define ETHERNET_CONF_ETHADDR0    0x00
#define ETHERNET_CONF_ETHADDR1    0x01
#define ETHERNET_CONF_ETHADDR2    0x02
#define ETHERNET_CONF_ETHADDR3    0x03
#define ETHERNET_CONF_ETHADDR4    0x04
#define ETHERNET_CONF_ETHADDR5    0x55

/*! IP Address (192.168.0.2) */
//! @{
#define ETHERNET_CONF_IPADDR0          192
#define ETHERNET_CONF_IPADDR1          168
#define ETHERNET_CONF_IPADDR2            1
#define ETHERNET_CONF_IPADDR3            2
//! @}

/*! HOST IP Address (192.168.0.1) */
//! @{
#define ETHERNET_CONF_GATEWAY_ADDR0    192
#define ETHERNET_CONF_GATEWAY_ADDR1    168
#define ETHERNET_CONF_GATEWAY_ADDR2      1
#define ETHERNET_CONF_GATEWAY_ADDR3      1
//! @}

/*! The network mask being used. */
//! @{
#define ETHERNET_CONF_NET_MASK0        255
#define ETHERNET_CONF_NET_MASK1        255
#define ETHERNET_CONF_NET_MASK2        255
#define ETHERNET_CONF_NET_MASK3          0
//! @}

struct tls_netif_status_event
{
    struct dl_list list;
    tls_netif_status_event_fn status_callback;
};

#endif


