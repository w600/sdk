/*****************************************************************************
*
* File Name : wm_demo_cmd.h
*
* Description: demo command header
*
* Copyright (c) 2014 Winner Micro Electronic Design Co., Ltd.
* All rights reserved.
*****************************************************************************/
#ifndef __WM_DEMO_CMD_H__
#define __WM_DEMO_CMD_H__

#include <string.h>
#include "wm_include.h"
#include "wm_watchdog.h"

/*****************************************************************
	EXTERN FUNC
*****************************************************************/
extern int demo_connect_net(void *,...);
extern int demo_oneshot(void *, ...);
extern int demo_socket_config(void *, ...);
extern int demo_webserver_config(void *, ...);
extern int demo_create_softap(void *,...);
extern int uart_demo(void *,...);
extern int ntp_demo(void *, ...);
extern int ntp_set_server_demo(void *, ...);
extern int ntp_query_cfg(void *, ...);
extern int flash_demo(void *, ...);
extern int Socket_Client_Demo(void *, ...);
extern int sck_c_send_data_demo(void *, ...);
extern int socket_server_demo(void *, ...);
extern int sck_s_send_data_demo(void *, ...);
extern int socket_udp_demo(void *,...);
extern int udp_send_data_demo(void *,...);

extern int apsta_demo(char *ssid, char *pwd, char *ssid_new);
extern int gpio_demo(void *, ...);
extern int gpio_isr_test(void *, ...);
extern int pwm_demo(void *, ...);
extern int crypt_hard_demo(void *, ...);
extern int wm_7816_demo(void *, ...);
extern int rsa_demo(void *, ...);
extern int slave_spi_demo(void *, ...);
//extern int master_spi_demo(void *, ...);
extern int master_spi_recv_data(void *, ...);
extern int master_spi_send_data(void *, ...);
extern int pmu_timer0_demo(void *, ...);
extern int pmu_timer1_demo(void *, ...);
extern int rtc_demo(void *, ...);
extern int timer_demo(void *, ...);
extern int http_fwup_demo(void *, ...);
extern int http_get_demo(void *, ...);
extern int http_post_demo(void *, ...);
extern int http_put_demo(void *, ...);
extern int socket_server_demo(void *, ...);
extern int sck_s_send_data_demo(void *, ...);
extern int CreateMCastDemoTask(void *, ...);
extern int adc_demo(void *, ...);

extern int demo_wps_pbc(void *, ...);
extern int demo_wps_pin(void *, ...);
extern int demo_wps_get_pin(void *, ...);


extern int demo_iperf_auto_test(void *, ...);
extern int CreateSSLServerDemoTask(void *, ...);
extern int lwsDemoTest(void *, ...);
extern int tls_i2s_demo(void *, ...); 
extern int i2c_demo(void *, ...);
extern int scan_demo(void *, ...);



/*****************************************************************
		LOCAL FUNC
*****************************************************************/
static void demo_console_show_info(char *buf);
static int demo_console_show_help(void *p, ...);
static int  demo_sys_reset(void *p, ...);

/*****************************************************************
		LOCAL TYPE
*****************************************************************/
typedef struct demo_console_st
{
    int rx_data_len;
	u8 *rx_buf;		/*uart rx*/
	u16 rptr;
	u8 MsgNum;
}Demo_Console;

struct demo_console_info_t
{
	char *cmd;
	int (*callfn)(void * ,...);
	short type;/* perbit: 0-string, 1-number */
	short param_cnt;
	char *info;
};

#define DEMO_CONSOLE_CMD		1		//被解析成cmd
#define DEMO_CONSOLE_SHORT_CMD	2		//CMD的一部分，没有解析完
#define DEMO_CONSOLE_WRONG_CMD  3

#define DEMO_BUF_SIZE		TLS_UART_RX_BUF_SIZE

const char HTTP_POST[] = "t-httppost";
const char HTTP_PUT[] = "t-httpput";


struct demo_console_info_t  console_tbl[] =
{
	//To Do When Add New Demo
#if DEMO_CONNECT_NET
	{"t-connect", 	demo_connect_net, 0, 2, "Test connecting ap;t-connect(\"ssid\",\"pwd\"); For open ap, pwd should be empty"},
	{"t-oneshot",     demo_oneshot,  0, 0, "Test Oneshot  configuration"},
//	{"t-socketcfg",  demo_socket_config, 0, 0, "Test socket configuration"},
	{"t-webcfg",      demo_webserver_config, 0, 0, "Test web server configuration"},	
#endif

#if DEMO_SOFT_AP
	{"t-softap", 	demo_create_softap, 0x1C, 5, "Test softap create & station join monitor;"},
#endif

#if DEMO_APSTA
	{"t-apsta", 	apsta_demo, 0x0, 3, "Test connecting with AP by apsta mode;"},
#endif

#if DEMO_UARTx
	{"t-uart", 	uart_demo, 0x7, 3, "Test uart tx/rx; For example t-uart=(9600,0,0),baudrate 9600 ,parity none and 1 stop bit"},
#endif

#if DEMO_MASTER_SPI
	{"t-mspi-s", 	master_spi_send_data, 0x3, 2,   "Test SPI Master sending data(Note: need another module acts as a client device)"},
	{"t-mspi-r", 	master_spi_recv_data, 0x3, 2,   "Test SPI Master receiving data(Note: need another module acts as a client device)"},
#endif

#if DEMO_SLAVE_SPI
    {"t-sspi", 	slave_spi_demo, 0x1, 1,   "Test slave HSPI,t-sspi=(0),(Note: need another module support as a master device)"},
#endif

#if DEMO_FLASH
	{"t-flash", 	flash_demo,		0x0, 0, 	"Test Read/Write Flash "},
#endif

#if DEMO_STD_SOCKET_CLIENT
	{"t-sockc", 	Socket_Client_Demo,	0x1,    2, "Test data stream as [STANDARD SOCKET] CLIENT(working after connecting with AP successfully)"},
	{"t-skcsnd", 	sck_c_send_data_demo,	0x3,    2, "Test socket client send data, len:send len, uart_trans: is or not use uart retransmission"},
#endif

#if DEMO_STD_SOCKET_SERVER
	{"t-socks", 	socket_server_demo,	0x1,    1, "Test data stream as [STANDARD SOCKET] SERVER(working after connecting with AP successfully)"},
	{"t-skssnd", 	sck_s_send_data_demo,	0x7,    3, "Test socket server send data skt_no:socket num, len:send len, uart_trans: is or not use uart retransmission"},
#endif

#if DEMO_UDP
    {"t-udp",   	socket_udp_demo,	0x3,    3, "Test data stream as UDP(working after connecting with AP successfully)"},
    {"t-sndudp",   	udp_send_data_demo,	0x1,    1, "Test udp send data"},
#endif

#if DEMO_HTTP
	{"t-httpfwup",  http_fwup_demo,	0x0,    1, "Test firmware update via HTTP, like this t-httpfwup=(http://192.168.1.100:8080/WM_W600_SEC.img)"},
	{"t-httpget", 	http_get_demo,	0x0,    1, "Test HTTP get method, like this t-httpget"},
	{(char*)HTTP_POST,  http_post_demo,	0x0,    1, "Test HTTP post method, like this t-httppost=(user=winnermicro)"},
	{(char*)HTTP_PUT,   http_put_demo,  0x0,    1, "Test HTTP put method, like this t-httpput=(user=winnermicro)"},
#endif

#if DEMO_GPIO
    {"t-gpioirq", 	gpio_isr_test,	0x0,    0, "Test gpio interrupt services"},
    {"t-gpio", 	    gpio_demo,	    0x0,    0, "Test gpio read and write"},
#endif

#if DEMO_NTP
    {"t-ntp", 	ntp_demo, 0x0, 0,   "Test NTP"},
    {"t-setntps", ntp_set_server_demo, 0x0, 3, "Set NTP server ip;For example:t-setntps(\"cn.ntp.org.cn\", \"ntp.sjtu.edu.cn\", \"192.168.1.101\"),max server num is 3"},
	{"t-queryntps", ntp_query_cfg, 0x0, 0, "Query the NTP server domain"},
#endif

#if DEMO_PWM
    {"t-pwm",   	pwm_demo,	0x1F,    5, "Test PWM output, for example t-pwm=(0,20,99,1,0) to test ALLSYC mode."},
#endif

#if DEMO_I2S
    {"t-i2s",   	tls_i2s_demo,	0x3F,    6, "Test I2S module, for example t-i2s=(0,1,44100,16,0,0) to send data."},
#endif

#if DEMO_I2C
    {"t-i2c",   	i2c_demo,	0x1,    1, "Test I2C module, for example t-i2c to W&R AT24CXX."},
#endif

#if DEMO_PMU
    {"t-pmuT0",   	pmu_timer0_demo,	0x1,    1, "Test power management unit with timer0"},
    {"t-pmuT1",   	pmu_timer1_demo,	0x1,    1, "Test power management unit with timer1"},
#endif

#if DEMO_UDP_MULTI_CAST
	{"t-mcast",	CreateMCastDemoTask,	0x0,    1, "Test Multicast data stream"},
#endif

#if DEMO_ENCRYPT
	{"t-crypt",   	crypt_hard_demo,	0x0,    0, "Test Encryption/Decryption API"},
#endif

#if DEMO_RSA
	{"t-rsa",   	rsa_demo,	0x0,    0, "Test RSA Encryption/Decryption API"},
#endif

#if DEMO_7816
	{"t-7816", 	wm_7816_demo,	0x0,	0, "Test 7816 tx/rx function"},
#endif

#if DEMO_RTC
    {"t-rtc",  rtc_demo,   0x0,    0, "Test rtc"},
#endif

#if DEMO_ADC
    {"t-adc",  adc_demo,   0x0,    0, "Test adc"},
#endif

#if DEMO_TIMER
    {"t-timer",  timer_demo,   0x0,    0, "Test timer"},
#endif

#if DEMO_WPS
	{"t-wps-get-pin",  demo_wps_get_pin,   0x0,    0, "Test WPS get pin"},
	{"t-wps-start-pin",  demo_wps_pin,   0x0,    0, "Test WPS start pin"},
	{"t-wps-start-pbc",  demo_wps_pbc,   0x0,    0, "Test WPS start pbc"},
#endif

#if DEMO_IPERF_AUTO_TEST
	{"t-iperf",  demo_iperf_auto_test,   0x7E,    7, "Iperf auto test"},
#endif
#if DEMO_SSL_SERVER
	{"t-ssl-server",  CreateSSLServerDemoTask,   0x0,    1, "Test ssl server,remember to turn on TLS_CONFIG_SERVER_SIDE_SSL"},
#endif
#if DEMO_WEBSOCKETS
	{"t-websockets", lwsDemoTest, 0x0,    0, "websockets demo test"},
#endif

#if DEMO_SCAN
		{"t-scan",	scan_demo,	0x0,	0,  "Test wifi scan"},
#endif


	//控制台上显示的最后一个命令，如果要让命令显示在控制台上，需要放在该行的上面
	{"demohelp", 	demo_console_show_help,	0,0,	"Display Help information"},
	//下面的命令用于内部测试，不显示在控制台上
	{"reset", 		demo_sys_reset, 0, 0, "Reset System"},
	//最后一个命令，检索命令时判断结束标识
	{"lastcmd", 	NULL,	0,0,			"Table Terminal Flag; MUST BE THE LAST ONE"}
};

static void demo_console_show_info(char *buf)
{
	char *p = NULL;
	char *p1 = NULL;

	p = buf;
	p1 = strchr(p, '\n');
	if(NULL == p1)
	{
		printf("%s\n",p);
		return;
	}

	while(p1 != NULL)
	{
		*p1 = '\0';
		printf("%s\n",p);
		printf("%-30s","   ");
		p = p1 + 1;
		p1 = strchr(p, '\n');
	}
	printf("%s\n",p);
}

static int demo_console_show_help(void *p, ...)
{
	int i;

	printf("\n%-10s","Sequence");
	printf("%-20s","Command");
	printf("%s","Description");
	printf("\n------------------------------------------------------------------------------------\n");
	for(i = 0; ;i ++)
	{
		printf("%-10d",i+1);
		printf("%-20s",console_tbl[i].cmd);
		//printf("%s\n",console_tbl[i].info);
		demo_console_show_info(console_tbl[i].info);
		if(0 == strcmp(console_tbl[i].cmd,"demohelp"))
			break;
	}
	printf("------------------------------------------------------------------------------------\n");

	return WM_SUCCESS;
}

int demo_sys_reset(void *p, ...)
{
	tls_sys_reset();
	return WM_SUCCESS;
}

#endif /*__WM_DEMO_CMD_H__*/

