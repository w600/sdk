#include "wm_include.h"

#if TLS_CONFIG_DLNA
#include <ithread.h>
#include <upnp.h>

#include "logging.h"
#include "output_gstreamer.h"
#include "upnp_if.h"
#include "upnp_device.h"
#include "upnp_renderer.h"
#include "httpparser.h"
#include "httpreadwrite.h"
#include "upnpdebug.h"
#include "wm_upnp_task.h"
#include "wm_dlna_dmr.h"

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

typedef struct download_context
{
	char * dest;
	int  downsize;
	u8  seekactive;
	dmr_download_finish_callback download_callback;
}DOWNLOAD_CONTEXT;

static SOCKINFO http_down_sock_info;
static http_parser_t http_down_parser;

static dmr_action_callback play_callback = NULL;
static dmr_action_callback stop_callback = NULL;
static dmr_action_callback seek_callback = NULL;
static dmr_action_callback pause_callback = NULL;
static dmr_play_progress_callback play_progress_callback = NULL;

#define DOWNLOAD_BUFFER_LEN 1024
static char DOWNLOAD_BUFFER[DOWNLOAD_BUFFER_LEN];
static int downtotalsize = 0;
unsigned int seekoffset = 0;
static u8 dmrInt = 0;

void tls_dmr_set_play_callback(dmr_action_callback callback)
{
	play_callback = callback;
}

void tls_dmr_set_stop_callback(dmr_action_callback callback)
{
	stop_callback = callback;
}

void tls_dmr_set_seek_callback(dmr_action_callback callback)
{
	seek_callback = callback;
}

void tls_dmr_set_pause_callback(dmr_action_callback callback)
{
	pause_callback = callback;
}

void tls_dmr_set_play_progress_callback(dmr_play_progress_callback callback)
{
	play_progress_callback = callback;
}

int tls_dmr_init(const char *friendly_name, const char *uuid)
{
	int rc;
	int result = -1;
	struct device *upnp_renderer;
	char ip_address[INET_ADDRSTRLEN] = { '\0' };
	struct tls_ethif * ethif;
	ethif = tls_netif_get_ethif();
	if(ethif->status == 0)
	{
		printf("DMR init failed. Net work is not ready.\n");
		return result;
	}
	http_down_sock_info.socket = INVALID_SOCKET;
	upnp_renderer = upnp_renderer_new(friendly_name, uuid);
	if (upnp_renderer == NULL) {
		goto out;
	}
#ifdef TLS_CONFIG_LWIP_VER2_0_3
	sprintf(ip_address, "%d.%d.%d.%d",ip4_addr1(ip_2_ip4(&ethif->ip_addr)),ip4_addr2(ip_2_ip4(&ethif->ip_addr)),
		ip4_addr3(ip_2_ip4(&ethif->ip_addr)),ip4_addr4(ip_2_ip4(&ethif->ip_addr)));	
#else
	sprintf(ip_address, "%d.%d.%d.%d",ip4_addr1(&ethif->ip_addr.addr),ip4_addr2(&ethif->ip_addr.addr),
		ip4_addr3(&ethif->ip_addr.addr),ip4_addr4(&ethif->ip_addr.addr));
#endif	
	rc = upnp_device_init(upnp_renderer, ip_address);
	if (rc != 0) {
		goto out;
	}

	printf("Ready for rendering..\n");
	result = 0;
	dmrInt = 1;
out:
	return result;
}

int tls_dmr_destroy(void)
{
	dmrInt = 2;
	int ret = upnp_device_destroy();
	if(ret)
		return ret;
	upnp_renderer_destroy();
	dmrInt = 0;
	return 0;
}
static float dmr_get_progress()
{
	float val = 0;
	http_parser_t *response = &http_down_parser;
	if(response->content_length > 0 && play_progress_callback)
	{
		val = play_progress_callback(response->content_length);
		val = ((val * (response->content_length) + seekoffset) / (response->content_length + seekoffset));
	}
	return val;
}
int dmr_http_download(void * ctx)
{
	DOWNLOAD_CONTEXT * downctx = (DOWNLOAD_CONTEXT *)ctx;
	int num_read, offset = 0;
	SOCKINFO *info = &http_down_sock_info;
	http_parser_t *response = &http_down_parser;
	char * dest_buf = downctx->dest;
	//int pos = 0;
	int timeout;
	if(dest_buf == NULL)
		dest_buf = DOWNLOAD_BUFFER;
	if(downctx->downsize > DOWNLOAD_BUFFER_LEN)
		downctx->downsize = DOWNLOAD_BUFFER_LEN;
	//int currDownSize;
	if(response->msg.msg.buf && (response->msg.msg.length > response->entity_start_position))
	{
		offset = response->msg.msg.length - response->entity_start_position;
		offset = MIN(offset, downctx->downsize);
		MEMCPY(dest_buf, response->msg.msg.buf + response->entity_start_position, offset);
		response->entity_start_position += offset;
		if(response->msg.msg.length <= response->entity_start_position)
		{
			httpmsg_destroy(&response->msg);
		}
	}
	while (TRUE) {
		if(info->socket == INVALID_SOCKET || offset == downctx->downsize)
			break;
		if(response->content_length && (downtotalsize >= response->content_length))
		{
			sock_destroy(info, SD_BOTH);
			break;
		}
		timeout = HTTP_DEFAULT_TIMEOUT;
		num_read = sock_read(info, dest_buf + offset, downctx->downsize - offset, &timeout);
		if(num_read > 0)
		{
			downtotalsize += num_read;
			offset += num_read;
		}
		else
		{
			sock_destroy(info, SD_BOTH);
			break;
		}
		if(offset >= downctx->downsize)
			break;
	}
	UpnpPrintf(UPNP_ALL, MSERV, __FILE__, __LINE__,
		"download len=%d, downctx->totalsize=%d\n",
		offset, downtotalsize);
	if(downctx->download_callback)
		downctx->download_callback(dest_buf, offset);
	tls_mem_free(ctx);
	if(response->content_length > 0 && play_progress_callback)
	{
		float * val = NULL;
		val = tls_mem_alloc(sizeof(float));
		if(val)
		{
			//if(downtotalsize >= response->content_length)
			//	*val = 1.0;
			//else
				*val = dmr_get_progress();
#if 0
			if (upnp_callback_with_block(UPNP_COMMON_TASK, (start_routine)change_play_progress, (void *)(val), 0) != ERR_OK){
				UpnpPrintf(UPNP_ALL, MSERV, __FILE__, __LINE__,
					"callback change_play_progress error\n");
				tls_mem_free(val);
			}
#else
			change_play_progress(val);
#endif
		}
	}
	return UPNP_E_SUCCESS;
}

int dmr_start_http_download(void* arg)
{
	char* urlbuf = (char*)arg;
	uri_type url;
	SOCKET conn_fd;
	membuffer start_msg;
	int ret_code, err_code;
	int timeout;
	const char *CRLF = "\r\n";
	uri_type * destination_url;
	SOCKINFO *info = &http_down_sock_info;
	http_parser_t *response = &http_down_parser;

	destination_url = tls_mem_alloc(sizeof(uri_type));
	if(destination_url == NULL)
		return UPNP_E_OUTOF_MEMORY;
	ret_code = parse_uri(urlbuf, strlen(urlbuf), destination_url);
	if(ret_code!=HTTP_SUCCESS)
	{
		UpnpPrintf(UPNP_ALL, HTTP, __FILE__, __LINE__,
			"parse_uri error url=%s\n",
			urlbuf);
		printf("parse_uri error url=%s\n",
			urlbuf);
		tls_mem_free(destination_url);
		return UPNP_E_OUTOF_MEMORY;
	}
	/* connect */
	UpnpPrintf(UPNP_ALL, HTTP, __FILE__, __LINE__,
		"connecting to: %.*s\n",
		(int)destination_url->hostport.text.size,
		destination_url->hostport.text.buff);
	printf("connecting to: %.*s\n",
		(int)destination_url->hostport.text.size,
		destination_url->hostport.text.buff);

	conn_fd = http_Connect(destination_url, &url);
	if (conn_fd < 0)
	{
		printf("failed connect to: %.*s\n",
		(int)destination_url->hostport.text.size,
		destination_url->hostport.text.buff);
		tls_mem_free(destination_url);
		/* return UPNP error */
		return UPNP_E_SOCKET_CONNECT;
	}
	UpnpPrintf(UPNP_ALL, HTTP, __FILE__, __LINE__,
			"http_Connect socket=%d\n",
			conn_fd);
	printf("http_Connect socket=%d\n",
			conn_fd);
	ret_code = sock_init(info, conn_fd);
	if (ret_code) {
		tls_mem_free(destination_url);
		sock_destroy(info, SD_BOTH);
		return ret_code;
	}
	/* make start line and HOST header */
	membuffer_init(&start_msg);
	//printf("seekoffset=%d\n", seekoffset);
	ret_code = http_MakeMessage(
			&start_msg, 1, 1,
			"q" "sdsc" "sc",
			HTTPMETHOD_GET, &url,
			"Range: bytes=", seekoffset, "-",
			"Connection: Keep-Alive");
	if (ret_code) {
		printf("http_MakeMessage error ret_code=%d\n", ret_code);
		tls_mem_free(destination_url);
		membuffer_destroy(&start_msg);
		sock_destroy(info, SD_BOTH);
		return UPNP_E_OUTOF_MEMORY;
	}
	timeout = HTTP_DEFAULT_TIMEOUT;
	/* send msg (note: end of notification will contain "\r\n" twice) */
	ret_code = http_SendMessage(info, &timeout,
		"bb",
		start_msg.buf, start_msg.length,
		CRLF, strlen(CRLF));
	if (ret_code) {
		printf("http_SendMessage error ret_code=%d\n", ret_code);
		tls_mem_free(destination_url);
		membuffer_destroy(&start_msg);
		sock_destroy(info, SD_BOTH);
		return ret_code;
	}
	timeout = HTTP_DEFAULT_TIMEOUT;
	ret_code = http_RecvMessage(info, response,
		HTTPMETHOD_HEAD, &timeout, &err_code);
	UpnpPrintf(UPNP_ALL, HTTP, __FILE__, __LINE__,
		"http_RecvMessage ret_code=%d, content_length=%d, response->msg.msg.length=%d, parser->entity_start_position=%d, parser->msg.amount_discarded=%d\n", 
		ret_code,
		response->content_length,
		response->msg.msg.length,
		response->entity_start_position,
		response->msg.amount_discarded);
	if (ret_code) {
		printf("http_RecvMessage error ret_code=%d\n", ret_code);
		tls_mem_free(destination_url);
		membuffer_destroy(&start_msg);
		sock_destroy(info, SD_BOTH);
		httpmsg_destroy(&response->msg);
		return ret_code;
	}

	if(response->msg.msg.length <= response->entity_start_position)
	{
		httpmsg_destroy(&response->msg);
	}
	tls_mem_free(destination_url);
	membuffer_destroy(&start_msg);
	downtotalsize = 0;
	if(play_callback)
		play_callback();
	return UPNP_E_SUCCESS;
}

int dmr_stop_http_download(void* arg)
{
	SOCKINFO *info = &http_down_sock_info;
	if(stop_callback)
		stop_callback();
	seekoffset = 0;
	UpnpPrintf(UPNP_INFO, MSERV, __FILE__, __LINE__,
		"sock_destroy: Socket %d\n", info->socket);
	sock_destroy(info, SD_BOTH);
	return UPNP_E_SUCCESS;
}

static int dmr_download_data(u8 seekactive, char * dest, int downsize, dmr_download_finish_callback download_callback)
{
	DOWNLOAD_CONTEXT * ctx;
	ctx = tls_mem_alloc(sizeof(DOWNLOAD_CONTEXT));
	if(ctx == NULL)
		return ERR_MEM;
	memset(ctx, 0, sizeof(DOWNLOAD_CONTEXT));
	ctx->dest = dest;
	ctx->downsize = downsize;
	ctx->seekactive = seekactive;
	ctx->download_callback = download_callback;
	if(upnp_callback_with_block(UPNP_HD_TASK, (start_routine)dmr_http_download, (void *)ctx, 0) != ERR_OK)
	{
		tls_mem_free(ctx);
		return ERR_MEM;
	}
	return ERR_OK;
}
extern char* gsuri;
int dmr_seek_http_download(void * arg)
{
	SOCKINFO *info = &http_down_sock_info;
	http_parser_t *response = &http_down_parser;
	float *per = (float*)arg;
	if(seek_callback == NULL)
	{	
		tls_mem_free(arg);
		return 0;
	}
	//本次seekoffset = per * (上次的总长度+ 上次的seekoffset)
	seekoffset = (int)((*per) * (response->content_length + seekoffset));
	tls_mem_free(arg);
	seek_callback();
	sock_destroy(info, SD_BOTH);
	//printf("dmr_seek_http_download seekoffset=%d per=%f  content_len=%d\n", seekoffset, (*per), response->content_length);
	if(upnp_callback_with_block(UPNP_HD_TASK, (start_routine)dmr_start_http_download, (void *)gsuri, 0) != ERR_OK)
	{
		return ERR_MEM;
	}
	//dmr_download_data(1, seekoffset, NULL);
	return 0;
}

int dmr_pause_http_download(void * arg)
{
	SOCKINFO *info = &http_down_sock_info;
	http_parser_t *response = &http_down_parser;
	float per = 0;
	if(pause_callback == NULL)
	{
		return 0;
	}
	per = dmr_get_progress();
	seekoffset = per * (response->content_length + seekoffset);
	pause_callback();
	sock_destroy(info, SD_BOTH);
	return 0;
}

int tls_dmr_download_data(char * dest, int downsize, dmr_download_finish_callback download_callback)
{
	if(dmrInt != 1)
		return UPNP_E_FINISH;
	return dmr_download_data(0, dest, downsize, download_callback);
}

#endif

