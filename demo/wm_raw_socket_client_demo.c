/***************************************************************************** 
* 
* File Name : wm_socket_raw_demo.c 
* 
* Description: raw socket demo function 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-6-2 
*****************************************************************************/ 
#include <string.h>
#include "wm_include.h"

u8 RemoteIp[4] = {192,168,1,199};	//demo作为client时，远程服务器的IP

#if DEMO_RAW_SOCKET_CLIENT
#define    DEMO_RAW_SOCK_C_TASK_SIZE      256
tls_os_queue_t *demo_raw_sock_c_q = NULL;
static OS_STK DemoRawSockCTaskStk[DEMO_RAW_SOCK_C_TASK_SIZE]; 

extern ST_Demo_Sys gDemoSys;
extern int opentx;
struct tls_socket_desc raw_socket_c_desc;

static void demo_raw_sock_c_task(void *sdata);


err_t  raw_sk_client_recv(u8 skt_num, struct pbuf *p, err_t err)
{
	int offset = 0;
	//printf("socket_recv : %s\n", p->payload); 

	do
	{
		gDemoSys.sock_data_len = pbuf_copy_partial(p, gDemoSys.sock_rx, DEMO_BUF_SIZE, offset);
		if(gDemoSys.sock_data_len == 0)
			break;
		offset += gDemoSys.sock_data_len;
		if(opentx)
			tls_os_queue_send(demo_raw_sock_c_q, (void *)DEMO_MSG_SOCKET_RECEIVE_DATA, 0);
	}while(offset < p->tot_len);
	
	gDemoSys.recvlen += p->tot_len;
	printf("\ntotallen=%d\n",gDemoSys.recvlen);
	if (p)
            pbuf_free(p);
	return ERR_OK;
}

err_t raw_sk_client_connected(u8 skt_num,  err_t err)
{
	printf("connected socket num=%d,err=%d\n", skt_num,err);
	if(ERR_OK == err)
	{
		gDemoSys.socket_num = skt_num;
		gDemoSys.socket_ok = TRUE;
		gDemoSys.is_raw = 1;
	//	OSQPost(demo_raw_sock_c_q,(void *)DEMO_MSG_OPEN_UART);
	}
	
	return ERR_OK;
}

void  raw_sk_client_err(u8 skt_num, err_t err)
{
	gDemoSys.socket_ok = FALSE;
	//printf("err socket num=%d,err=%d\n", skt_num,err);
	tls_os_queue_send(demo_raw_sock_c_q, (void *)DEMO_MSG_SOCKET_ERR, 0);
}

err_t raw_sk_client_poll(u8 skt_num)
{
	//printf("socketpoll skt_num : %d\n", skt_num);
	return ERR_OK;
}

err_t raw_sk_client_accept(u8 skt_num, err_t err)
{
	printf("accept socket num=%d, err= %d\n", skt_num, err);
	if(ERR_OK == err)
	{
		gDemoSys.socket_num = skt_num;
		gDemoSys.socket_ok = TRUE;
		gDemoSys.is_raw = 1;
	//	OSQPost(demo_raw_sock_c_q,(void *)DEMO_MSG_OPEN_UART);
		
		return ERR_OK;
	}
	return err;
}

void create_raw_socket_client_demo(void)
{	
	int idx;
	struct tls_ethif * ethif;
	
	ethif = tls_netif_get_ethif();
	printf("\nip=%d.%d.%d.%d\n",  ip4_addr1(ip_2_ip4(&ethif->ip_addr)),ip4_addr2(ip_2_ip4(&ethif->ip_addr)),
		ip4_addr3(ip_2_ip4(&ethif->ip_addr)),ip4_addr4(ip_2_ip4(&ethif->ip_addr)));


	DemoRawSockOneshotSendMac();
	
	memset(&raw_socket_c_desc, 0, sizeof(struct tls_socket_desc));
	raw_socket_c_desc.recvf = raw_sk_client_recv;
	raw_socket_c_desc.errf = raw_sk_client_err;
	raw_socket_c_desc.pollf = raw_sk_client_poll;

	raw_socket_c_desc.cs_mode = SOCKET_CS_MODE_CLIENT;
	raw_socket_c_desc.connf = raw_sk_client_connected;

	raw_socket_c_desc.protocol = SOCKET_PROTO_TCP;
	for(idx = 0; idx < 4; idx++){
		raw_socket_c_desc.ip_addr[idx] = RemoteIp[idx];
	}
	raw_socket_c_desc.port = RemotePort;

	printf("\nserver ip=%d.%d.%d.%d,port=%d\n",RemoteIp[0],RemoteIp[1],RemoteIp[2],RemoteIp[3],raw_socket_c_desc.port);
	if(gDemoSys.socket_ok != TRUE)
	{
		tls_socket_create(&raw_socket_c_desc);
	}
}



int CreateRawSockClientDemoTask(char *buf)
{
	tls_os_queue_create(&demo_raw_sock_c_q, DEMO_QUEUE_SIZE);
	tls_os_task_create(NULL, NULL,
			demo_raw_sock_c_task,
                    (void *)&gDemoSys,
                    (void *)DemoRawSockCTaskStk,          /* 任务栈的起始地址 */
                    DEMO_RAW_SOCK_C_TASK_SIZE * sizeof(u32), /* 任务栈的大小     */
                    DEMO_RAW_SOCKET_C_TASK_PRIO,
                    0);

	return WM_SUCCESS;
}


static void raw_sock_c_net_status_changed_event(u8 status )
{
	switch(status)
	{
		case NETIF_WIFI_JOIN_FAILED:
			tls_os_queue_send(demo_raw_sock_c_q, (void *)DEMO_MSG_WJOIN_FAILD, 0);
			break;
		case NETIF_WIFI_JOIN_SUCCESS:
			tls_os_queue_send(demo_raw_sock_c_q, (void *)DEMO_MSG_WJOIN_SUCCESS, 0);
			break;
		case NETIF_IP_NET_UP:
			tls_os_queue_send(demo_raw_sock_c_q, (void *)DEMO_MSG_SOCKET_CREATE, 0);
			break;
		default:
			break;
	}
}

static void demo_raw_sock_c_task(void *sdata)
{
	ST_Demo_Sys *sys = (ST_Demo_Sys *)sdata;
	void *msg;
	struct tls_ethif * ethif = tls_netif_get_ethif();
	
	printf("\nraw sock c task\n");
//用于socket接收数据使用
	sys->sock_rx = tls_mem_alloc(DEMO_BUF_SIZE);
	if(NULL == sys->sock_rx)
	{
		printf("\nmalloc socket rx fail\n");
		return;
	}
	memset(sys->sock_rx, 0, DEMO_BUF_SIZE);	
//////	
	if(ethif->status)	//已经在网
	{
		tls_os_queue_send(demo_raw_sock_c_q, (void *)DEMO_MSG_SOCKET_CREATE, 0);
	}
	else
	{
		struct tls_param_ip ip_param;
		
		tls_param_get(TLS_PARAM_ID_IP, &ip_param, TRUE);
		ip_param.dhcp_enable = TRUE;
		tls_param_set(TLS_PARAM_ID_IP, &ip_param, TRUE);
		tls_wifi_set_oneshot_flag(1);		/*一键配置使能*/
		printf("\nwait one shot......\n");
	}
	tls_netif_add_status_event(raw_sock_c_net_status_changed_event);
	for(;;) 
	{
		tls_os_queue_receive(demo_raw_sock_c_q, (void **)&msg, 0, 0);
	//	printf("\n raw s c msg =%d\n",msg);
		switch((u32)msg)
		{
			case DEMO_MSG_WJOIN_SUCCESS:
				break;
				
			case DEMO_MSG_SOCKET_CREATE:
				create_raw_socket_client_demo();
				break;
				
			case DEMO_MSG_WJOIN_FAILD:
				if(sys->socket_num > 0)
				{
					sys->socket_num = 0;
					sys->socket_ok = FALSE;
				}
				break;

			case DEMO_MSG_SOCKET_RECEIVE_DATA:
				/*收到数据，自行处理*/
#if	(TLS_CONFIG_UART)
				tls_uart_tx(sys->sock_rx,sys->sock_data_len);	/*发到串口上显示*/
#endif				
				break;

			case DEMO_MSG_SOCKET_ERR:
				tls_os_time_delay(200);
				printf("\nsocket err\n");
				tls_socket_create(&raw_socket_c_desc);
				break;

			default:
				break;
		}
	}

}

#endif


int socket_raw_send_data_demo(ST_Demo_Sys *sys)
{
	int err = 0;
#if (DEMO_RAW_SOCKET_CLIENT || DEMO_RAW_SOCKET_SERVER)	
	u16 len,wptr;	
	
	if(NULL == sys)
		return -1;
	
	wptr = sys->wptr;
	if(sys->rptr < wptr)
	{
		len = wptr - sys->rptr;
		MEMCPY(sys->txbuf,sys->rxbuf + sys->rptr,len);
		sys->rptr += len;		
		//printf("uart receive: %s\n",  sys->txbuf);
		err = tls_socket_send(sys->socket_num, sys->txbuf , len);
		sys->translen += len;
		//printf("\n1=%d\n",sys->translen);
		sys->overflag = 0;
	}
	else if(sys->rptr > wptr ||(sys->rptr == wptr && sys->overflag))
	{
		len = DEMO_BUF_SIZE - sys->rptr;
		MEMCPY(sys->txbuf,sys->rxbuf + sys->rptr,len);
		MEMCPY(sys->txbuf + len, sys->rxbuf, wptr);
		len += wptr;
		sys->rptr = wptr;
		//printf("uart receive: %s\n",  sys->txbuf);
		err = tls_socket_send(sys->socket_num, sys->txbuf , len);
		sys->translen += len;
		//printf("\n2=%d\n",sys->translen);
		sys->overflag = 0;
	}
#endif
	return err;
}


