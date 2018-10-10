#include "wm_config.h"
#if TLS_CONFIG_CLOUD
#include <string.h>
#include "lwip/inet.h"
#include "wm_debug.h"
#include "cJSON.h"
#include "wm_cloud.h"
#include "wm_demo.h"
#define SOCK_USER_PARAM  0x60606060
extern u8 *wpa_supplicant_get_mac(void);
#define USER_PRINT printf
SOCKET * tls_lsd_get_device_found_socket(void)
{
	SOCKET * ret = NULL;
	struct sockaddr_in sin;
	unsigned short local_port;
	local_port = 4321;
//	CHAR    *pDstStart;
//	char server[128] = {0};
//	char port[11] = {0};
//	unsigned long serverAddr = 0;

	memset(&sin, 0, sizeof(struct sockaddr));
	// ??socket
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(local_port);
	if(ret == NULL)
		ret = tls_mem_alloc(sizeof(SOCKET));
	if(ret == NULL)
	{
		goto end;
	}		
	memset(ret, 0, sizeof(SOCKET));
	ret->sock_addr = tls_mem_alloc(sizeof(struct sockaddr));
	if(ret->sock_addr == NULL)
	{
		goto end;
	}	
	memcpy(ret->sock_addr, &sin, sizeof(struct sockaddr));
	ret->sock_type = 0;//UDP
	ret->socket_num = -1;
	ret->user_param = (void*)SOCK_USER_PARAM;
	return ret;
end:
	if(ret)
		tls_mem_free(ret);
	return NULL;
}

int tls_cloud_get_custom_sockets(SOCKET** sockets, int count)
{
	SOCKET * sock = NULL;
	*sockets = NULL;
	sock = tls_lsd_get_device_found_socket();
	if(sock != NULL)
	{
		*sockets = sock;
		return 1;
	}
	return 0;
}


static void udp_recv_data_handler(CloudReadData *data)
{
	char * recvbuf = data->read_data;
	cJSON *jsRet;
	cJSON *json;
	cJSON *pdata;
	u8 cmd,product_type;
		//cJSON *jsRet;
		char *databuf;
		u8 mac_addr[20];
        u8 *mac=NULL;
	CloudDeviceInfo device_info;
	int addrlen = sizeof(struct sockaddr);
//	printf("recvbuf=%s\n", recvbuf);
	json = cJSON_Parse(recvbuf);
	if(json)
	{
		pdata = cJSON_GetObjectItem(json, "cmd");
		USER_PRINT("houxf cmd=%x\r\n", pdata->valueint);
		cmd=pdata->valueint;
		pdata = cJSON_GetObjectItem(json, "product_type");
		USER_PRINT("houxf product_type=%d\r\n", pdata->valueint);
		product_type=pdata->valueint;		
		cJSON_Delete(json); 
	}
	
	else
	{
		printf("houxf cJSON_Parse error\r\n");
		goto out;
	}
    if(product_type==DEVICE_TYPE||product_type==DEVICE_TYPE_ALL)
    {
    	if(cmd==1)
    	{
    	
    		memset(mac_addr, 0, sizeof(mac_addr));
#if 0
    		tls_get_mac_addr(mac_addr);
    		sprintf(mac_addr, "%02X%02X%02X%02X%02X%02X", 
    		mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
#endif
#if 1
            mac = wpa_supplicant_get_mac();
            sprintf((char*)mac_addr, "%02X%02X%02X%02X%02X%02X", 
    		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
#endif            
    		USER_PRINT("houxf debug vendorID:%s\r\n", mac_addr);
    		jsRet = cJSON_CreateObject();
    		if(jsRet)
    		{
    			cJSON_AddNumberToObject(jsRet, "cmd", 2);
    			cJSON_AddNumberToObject(jsRet, "product_type", DEVICE_TYPE);		
    			cJSON_AddStringToObject(jsRet, "mac",(const char*)mac_addr);			
			tls_cloud_get_device_info(&device_info);
			cJSON_AddStringToObject(jsRet, "access_token", (const char*)device_info.access_token);
			cJSON_AddStringToObject(jsRet, "did", (const char*)device_info.device_id);
    			databuf = cJSON_PrintUnformatted(jsRet);
    			data->sin_recv.sin_port=htons(4322);
    			tls_cloud_socket_sendto(data->socket, databuf,strlen(databuf), 0, (struct sockaddr *)&data->sin_recv, addrlen);
    			if(databuf)
    			tls_mem_free(databuf);
    			cJSON_Delete(jsRet); 
    		}	
    	}
    }
out:
	return;
}

void tls_lsd_read_data_handler(void * the_data)
{
	CloudReadData *data = (CloudReadData *)the_data;
//	printf("read_data_handler data->socket->sock_type=%d\n", data->socket->sock_type);
	if(data->socket->sock_type == 0)
		udp_recv_data_handler(data);
	//else
		//tcp_recv_data_handler(data);
}
int tls_cloud_socket_data_handler(CloudReadData* data)
{
	if(data->socket->user_param == SOCK_USER_PARAM)
		tls_lsd_read_data_handler(data);
	return 0;
}
#endif

