/***************************************************************************** 
* 
* File Name : wm_spi_codec_demo.c 
* 
* Description: ntp demo function 
* 
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd. 
* All rights reserved. 
* 
* Author : dave
* 
* Date : 2014-10-28 
*****************************************************************************/ 
#include "wm_include.h"
#include "wm_demo.h"
#include "wm_dlna_dmr.h"
#include <string.h>
#include "VS10XX.h"
#if DEMO_DLNA_DMR
#define    MUSIC_BUF_MAX_INDX     60 /*要扩大音箱的BUF,修改此宏*/
#define    HTTP_CLIENT_BUFFER_SIZE   512
#define    MUSI_BUF_SIZE  (HTTP_CLIENT_BUFFER_SIZE*MUSIC_BUF_MAX_INDX)
#define	ONE_TIME_DOWN		HTTP_CLIENT_BUFFER_SIZE

static tls_os_queue_t * sd_down_mbox = NULL;
#define UPNP_SD_STK_SIZE  200 //spi write down
OS_STK         sd_down_task_stk[UPNP_SD_STK_SIZE];

#define CODEC_PLAY	1	
#define CODEC_STOP	2

u8 playstatus = 0;
u32 SendCnt;
u32 writeCnt;
u32 towriteCnt;
char  MusicData[MUSI_BUF_SIZE];
static int mute = 0;
static int volume = 25;


#define CODEC_TIMER        10000
#define VS_WRITE_CNT	32	//codec一次接收32个字节是安全的，多了可能会出问题

static int spi_send_audio(char * buf,int len )
{
	if(tls_gpio_read(VS_DQ) !=0)
	{	
		//printf(".");
		codec_data_cs_low();
		tls_spi_write(buf, len);		
		codec_data_cs_high();
		return VS_WRITE_CNT;
	}
	return 0;
}

static void download_finish_callback(char * buf, int datalen)
{
#if 0
	int pos = writeCnt%MUSI_BUF_SIZE;
	if(datalen <= 0)
	{
		printf("\ndownload_finish_callback datalen=%d\n",datalen);
		return;
	}
	if(pos + datalen > MUSI_BUF_SIZE)
	{
		//printf("\nwrite err\n");
		memcpy(&MusicData[pos], buf, MUSI_BUF_SIZE - pos);
		memcpy(&MusicData[0], buf, datalen + pos - MUSI_BUF_SIZE);
	}
	else
		memcpy(&MusicData[pos], buf, datalen);
#endif
	writeCnt += datalen;
	//printf("down finish datalen=%d, writeCnt=%d\n", datalen, writeCnt);
}

static void httpdownloaddata(int downsize)
{
	int pos = 0;
	int cur_down_size = 0;
	while(downsize > 0)
	{
		pos = towriteCnt%MUSI_BUF_SIZE;
		if(downsize >  1024 )
		{
			cur_down_size = 1024;
		}
		else
		{
			cur_down_size = downsize;
		}
		if(pos + cur_down_size > MUSI_BUF_SIZE)
		{
			tls_dmr_download_data(&MusicData[pos], MUSI_BUF_SIZE-pos, download_finish_callback);
			tls_dmr_download_data(MusicData, cur_down_size-MUSI_BUF_SIZE+pos, download_finish_callback);
		}
		else
		{
			tls_dmr_download_data(&MusicData[pos], cur_down_size, download_finish_callback);
		}
		towriteCnt += cur_down_size;
		downsize -= cur_down_size;
	}
}


static int spitocodec(void)
{
	int index;
	int pos;
	int ret;
	int cnt = 0;
	int datalen;
	int bufempty;
	int sd_down_len = 0;
	datalen = writeCnt - SendCnt;	//允许传输的最大数据
	//printf("\ndatalen=%d\n",datalen);
	if(datalen >= VS_WRITE_CNT)
	{
		pos = SendCnt%MUSI_BUF_SIZE;
		while(1)
		{
			if(pos+VS_WRITE_CNT > MUSI_BUF_SIZE)
			{
				printf("\ntrans err\n");
			}
			ret = spi_send_audio(MusicData+pos+cnt,VS_WRITE_CNT);
			//printf("\npos==%d\n",pos);
			cnt += ret;
			//printf("\npos==%d,cnt==%d\n",pos,cnt);
			if(0 == ret)		//codec不需要数据了
			{
				//printf(" trans cnt=%d\n",cnt);
				break;
			}
			if(cnt >= datalen)	//只有最后一包才会是大于，正常是等于
			{
				bufempty = 1;
				printf("\n no data for trans\n");
				break;
			}
			if(pos + cnt >= MUSI_BUF_SIZE)
			{
				//printf("\nread loop to the start pos=%d,cnt=%d\n",pos,cnt);
				if(pos + cnt > MUSI_BUF_SIZE)
				{
					printf("\nread err\n");
				}
				SendCnt += cnt;
				sd_down_len += cnt;
				pos = 0;
				datalen -= cnt;
				cnt = 0;				
			}
		}
		SendCnt += cnt;
		sd_down_len += cnt;
	}
	else
	{
		bufempty = 1;
	}

	//printf("spitocodec sd_down_len=%d, SendCnt=%d\n", sd_down_len, SendCnt);
	if(sd_down_len > 0)
	{
		//printf("\nbuf is empty,wait 1s\n");
		//printf("\ndown flag=%d\n",httpdownflag);
		
		httpdownloaddata(sd_down_len);	
	}

	return 0;
	
}


void codec_timer_cb(void)
{
	static u8 i = 0;

	tls_timer_stop();
	//printf("\ntimer come");
	if(playstatus != CODEC_PLAY)
	{
		printf("\nthe codec is stoped,close timer\n");
		return;
	}
	if(tls_gpio_read(VS_DQ) ==0)	//说明codec暂时不需要数据
	{
		//printf(" 0\n");
	}
	else
	{
		//printf(" 1\n");
		if(writeCnt > SendCnt)	//缓存buffer不为空
			tls_os_queue_send(sd_down_mbox, (void *)0, 0);
	}
	
	tls_timer_start(CODEC_TIMER);
}


static void httpstopdownloadmusic()
{
	printf("\nhttp stop down load music s=%d,w=%d\n",SendCnt,writeCnt);
	playstatus = CODEC_STOP;
}

static void first_download_finish_callback(char * buf, int datalen)
{
	int pos;

	if(playstatus == CODEC_PLAY)
		return;
	
	if(datalen > 0){
		//memcpy(&MusicData[pos], buf, datalen);
		writeCnt += datalen;
	}
	printf("\nfirst download finish\n");
	pos = writeCnt%MUSI_BUF_SIZE;
	if(writeCnt<MUSI_BUF_SIZE)
	{
		if(datalen > 0)
			tls_dmr_download_data(&MusicData[pos],ONE_TIME_DOWN, first_download_finish_callback);
		return;
	}
	printf("\nstart music\n");
	//tls_sys_clk_set(2);	//设置cpu频率到160M，暂时不需要
	VS_HD_Reset();	//硬复位							 				  		 	  
	VS_Soft_Reset();  			//软复位
	//set10XX();        				//设置音量等信息
	vs_set_vol(volume);
	tls_spi_setup(TLS_SPI_MODE_0, TLS_SPI_CS_LOW, 5000000);	// 5M ，codec能接受6M之内的CLK
	playstatus = CODEC_PLAY;

	tls_timer_start(CODEC_TIMER);
}

static void httpdownloadmusic()
{
	printf("httpdownloadmusic enter\n");
	httpstopdownloadmusic();
	writeCnt = 0;
	towriteCnt = 0;
	SendCnt = 0;
	tls_dmr_download_data(MusicData, ONE_TIME_DOWN, first_download_finish_callback);

}

static float get_grogress(int totlen)
{
	//printf("SendCnt %d totlen %d\n", SendCnt, totlen);
	return ((float)SendCnt) / totlen;
}


static void
sd_down_thread(void *arg)
{
	void * msg;
	while(TRUE)
	{
		tls_os_queue_receive(sd_down_mbox, &msg, 0, 0);
		if(playstatus != CODEC_PLAY)
		{
			tls_os_time_delay(100);	
		//	printf("stoped\n");
		}
		else
		{
			if(tls_gpio_read(VS_DQ) !=0)
			{
				spitocodec();
			}
		}		
	}
}
static void mute_callback(enum dmr_control_type type, const char* channel, int* value)
{
	printf("mute callback : type = %s , channel = %s, value = %d\n", (type == 0 ? "GET" : "SET"), channel, *value);
	if(type == CONTROL_GET)
		*value = mute;
	else
	{
		mute = *value;
		if(mute)
			vs_mute();
		else
			vs_set_vol(volume);
	}
}
static void volume_callback(enum dmr_control_type type, const char* channel, int* value)
{
	printf("volume callback : type = %s , channel = %s, value = %d\n", (type == 0 ? "GET" : "SET"), channel, *value);
	if(type == CONTROL_GET)
		*value = 100 - volume;
	else
	{
		volume = 100 - *value;
		vs_set_vol(volume);
	}
}
static void volumedb_callback(enum dmr_control_type type, const char* channel, int* value)
{
	printf("volumedb callback : type = %s , channel = %s, value = %d\n", (type == 0 ? "GET" : "SET"), channel, *value);
}
static void loudness_callback(enum dmr_control_type type, const char* channel, int* value)
{
	printf("loudness callback : type = %s , channel = %s, value = %d\n", (type == 0 ? "GET" : "SET"), channel, *value);
}

void InitMediaRender(void)
{
	tls_os_status_t status;
	VS_Init();

	status = tls_os_queue_create(&sd_down_mbox, 64, 0);
	if (status != TLS_OS_SUCCESS) {
		return -1;
	}


	tls_timer_irq_register(codec_timer_cb);

	 tls_os_task_create(NULL, NULL,
                       sd_down_thread,
                       NULL,
                       (void *)sd_down_task_stk,
                       UPNP_SD_STK_SIZE * sizeof(u32),
                       DEMO_DMR_TASK_PRIO,
                       0);
}

extern u8 *wpa_supplicant_get_mac(void);
int  CreateMediaRender(char * buf)
{	
	int ret = 0;
	u8 uuid[17] = {0};
	u8 *mac = wpa_supplicant_get_mac();
	sprintf((char *)uuid, "%02x%02x%02x%02x%02x%02x-dmr", 
	mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); 
	ret = tls_dmr_init((char *)uuid, (char *)uuid);	
	if(ret)
		return ret;
	tls_dmr_set_play_callback(httpdownloadmusic);
	tls_dmr_set_stop_callback(httpstopdownloadmusic);
	tls_dmr_set_seek_callback(httpstopdownloadmusic);
	tls_dmr_set_pause_callback(httpstopdownloadmusic);
	tls_dmr_set_play_progress_callback(get_grogress);

	tls_dmr_set_mute_callback(mute_callback);
	tls_dmr_set_volume_callback(volume_callback);
	tls_dmr_set_volumedb_callback(volumedb_callback);
	tls_dmr_set_loudness_callback(loudness_callback);
	return 0;
}

int DestroyMediaRender(char* buf)
{
	tls_dmr_set_play_callback(NULL);
	tls_dmr_set_stop_callback(NULL);
	tls_dmr_set_seek_callback(NULL);
	tls_dmr_set_pause_callback(NULL);
	tls_dmr_set_play_progress_callback(NULL);

	tls_dmr_set_mute_callback(NULL);
	tls_dmr_set_volume_callback(NULL);
	tls_dmr_set_volumedb_callback(NULL);
	tls_dmr_set_loudness_callback(NULL);

	tls_dmr_destroy();
	return 0;
}

#endif

