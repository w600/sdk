
#include <string.h>
#include "wm_include.h"
#include "wm_cloud.h"

#if DEMO_CLOUD

#define beep 2
#define DEMO_TASK_SIZE 256
tls_os_queue_t *demo_cloud_q = NULL;
static OS_STK DemocloudTaskStk[DEMO_TASK_SIZE];
tls_os_timer_t *cloudtimer = NULL;
u8 randcount=0;

static void demo_cloud_task(void *sdata);
#if DEMO_CONSOLE
extern void DemoStdSockOneshotSendMac(void);
#endif
int CraeteCloudDemoTask(void)
{
	if(demo_cloud_q)
		return WM_SUCCESS;
	tls_os_queue_create(&demo_cloud_q, DEMO_QUEUE_SIZE);
	tls_os_task_create(NULL,"Cloud",
		demo_cloud_task,
		NULL,
		(void *)DemocloudTaskStk,
		DEMO_TASK_SIZE*sizeof(u32),
		DEMO_CLOUD_TASK_PRIO,
		0);
	return WM_SUCCESS;
}

static void cloud_net_status_changed_event(u8 status)
{
	u8 auto_reconnect = WIFI_AUTO_CNT_ON;
	switch(status)
	{
		case NETIF_WIFI_JOIN_FAILED:
			tls_os_queue_send(demo_cloud_q, (void *)DEMO_MSG_WJOIN_FAILD, 0);
			break;
		case NETIF_WIFI_JOIN_SUCCESS:
			tls_os_queue_send(demo_cloud_q, (void *)DEMO_MSG_WJOIN_SUCCESS, 0);
			break;
		case NETIF_IP_NET_UP:
			tls_wifi_auto_connect_flag(WIFI_AUTO_CNT_FLAG_SET, &auto_reconnect);
			tls_wifi_set_oneshot_flag(0);
			tls_os_queue_send(demo_cloud_q, (void *)DEMO_MSG_SOCKET_CREATE, 0);
			break;
		case NETIF_WIFI_DISCONNECTED:
			tls_os_queue_send(demo_cloud_q,(void *)DEMO_MSG_WJOIN_FAILD, 0);
		default:
			break;
	}
}

static void CloudTimerProc(void *ptmr, void *parg)
{

	CloudData cloud_data;
	
	memset(&cloud_data,0,sizeof(CloudData));
	char * names[] = {"current_temp","current_hum","current_light"};
	char * values0[] = {"0","55","65535"};
	char * values1[] = {"10","37","65535"};
	char * values2[] = {"20","85","56443"};

	cloud_data.names = names;
	cloud_data.arg = NULL;
	cloud_data.opt = UPLOAD_REQ;
	cloud_data.cnt = 3;

	
	
	if(randcount == 0)
	{
		cloud_data.values = values0;
		randcount += 1;
	}
	else if(randcount == 1)
	{
		cloud_data.values = values1;
		randcount += 1;
	}
	else if(randcount == 2)
	{
		cloud_data.values = values2;
		randcount = 0;
	}

	if(tls_gpio_read(beep))
	{
		cloud_data.values[2] = "65535";
	}
	else
	{
		cloud_data.values[2] = "0";
	}

	tls_cloud_upload_data((CloudData *)&cloud_data);
}

int cloud_set_cb(CloudData* data)
{
	CloudData* rx_data = (CloudData *)data;
	u8 i;
	
	
	switch(rx_data->opt)
	{
		case UPLOAD_RESP:
			
			break;
		case CONTROL_REQ:
			for(i=0;i<rx_data->cnt;i++)
			{
				if(strstr("beep_switch",rx_data->names[i]) != NULL)
				{
					printf("current beep values = %s   cnt = %d",rx_data->values[0],rx_data->cnt);
					if(strstr("1",rx_data->values[i]) != NULL)
					{
						tls_gpio_write(beep,1);
						printf("\n\nlight on led\n\n");
					}
					else
					{
						tls_gpio_write(beep,0);
						printf("\n\nlight off led\n\n");
					}
					rx_data->opt = CONTROL_RESP;
					rx_data->result = 0;
					break;
				}
			}
			break;
		case SNAPSHOT_REQ:
			
			break;
		default:
			break;
	}

	return 0;
}



static void demo_cloud_task(void *sdata)
{
	void *msg;
	int err = 0;
	u8 auto_reconnect = WIFI_AUTO_CNT_OFF;
	struct tls_param_ip ip_param;

	struct tls_ethif * ethif = tls_netif_get_ethif();

	printf("\ndemo cloud task\n");
	tls_wifi_set_oneshot_flag(0);
	if(ethif->status)
	{
		tls_os_queue_send(demo_cloud_q,(void *)DEMO_MSG_SOCKET_CREATE,0);
	}
	else
	{
		tls_wifi_auto_connect_flag(WIFI_AUTO_CNT_FLAG_SET, &auto_reconnect);
		tls_wifi_disconnect();
		tls_param_get(TLS_PARAM_ID_IP, &ip_param, TRUE);
		ip_param.dhcp_enable = TRUE;
		tls_param_set(TLS_PARAM_ID_IP, &ip_param, TRUE);
		tls_wifi_set_oneshot_flag(1);
		printf("\nwait one shot......\n");
	}
	tls_netif_add_status_event(cloud_net_status_changed_event);
	tls_cloud_set_callback(cloud_set_cb);

	tls_gpio_cfg(beep,TLS_GPIO_DIR_OUTPUT,TLS_GPIO_ATTR_FLOATING);
	tls_gpio_write(beep, 0);

	err = tls_os_timer_create(&cloudtimer,
				            CloudTimerProc,
				            NULL,
				            1000, 
				            TRUE,
				            NULL);
		if(TLS_OS_SUCCESS!= err)
		{
			printf("\ncloudtimer creat fail\n");
		}


	for(;;)
	{
		tls_os_queue_receive(demo_cloud_q,(void **)&msg, 0, 0);

		switch((u32)msg)
		{
			case DEMO_MSG_WJOIN_SUCCESS:
				break;
				
			case DEMO_MSG_SOCKET_CREATE:
#if DEMO_CONSOLE
				DemoStdSockOneshotSendMac();
#endif
				tls_cloud_init("IJFTAR");
				if(TLS_OS_SUCCESS == err)
				{
					tls_os_timer_start(cloudtimer);
				}
				break;
				
			case DEMO_MSG_WJOIN_FAILD:
				tls_cloud_finish(0);
				if(TLS_OS_SUCCESS == err)
				{
					tls_os_timer_stop(cloudtimer);
				}
				break;

			case DEMO_MSG_SOCKET_ERR:
				printf("\nsocket err\n");
				if(TLS_OS_SUCCESS == err)
				{
					tls_os_timer_stop(cloudtimer);
				}
				break;
			default:
				break;
		}
	}
}

#endif


