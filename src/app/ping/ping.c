#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "wm_include.h"
#include "lwip/inet.h"
#include "lwip/icmp.h"
#include "lwip/ip.h"
#include "ping.h"

#define OWNER_PING_ID   12345
#define PING_DATA_LEN   32
#define PACKET_SIZE     64
#define MAX_NO_PACKETS  3
#define ICMP_HEAD_LEN   8

#define         PING_TEST_START            0x1

#define         TASK_PING_PRIO             35
#define         TASK_PING_STK_SIZE         256
#define         PING_QUEUE_SIZE            4
#define         PING_STOP_TIMER_DELAY      (2 * HZ)
#define         PING_ABORT_TIMER_DELAY     (1 * HZ)
#if TLS_CONFIG_WIFI_PING_TEST
static bool     ping_task_running = FALSE;
static OS_STK   TaskPingStk[TASK_PING_STK_SIZE];
static tls_os_queue_t *ping_msg_queue = NULL;
static tls_os_timer_t *ping_test_stop_timer;
static tls_os_timer_t *ping_test_abort_timer;
static u8 ping_test_running = FALSE;
static u8 ping_test_abort = FALSE;
static struct ping_param g_ping_para;
static u32 received_cnt = 0;
static u32 send_cnt     = 0;

static u16 ping_test_chksum(u16 *addr,int len)
{
    int nleft=len;
    int sum=0;
    u16 *w=addr;
    u16 answer=0;

    /*把ICMP报头二进制数据以2字节为单位累加起来*/
    while(nleft>1)
    {
        sum+=*w++;
        nleft-=2;
    }
    /*若ICMP报头为奇数个字节，会剩下最后一字节。把最后一个字节视为一个2字节数据的高字节，这个2字节数据的低字节为0，继续累加*/
    if( nleft==1)
    {
        *(u8 *)(&answer)=*(u8 *)w;
        sum+=answer;
    }
    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    answer=~sum;
    return answer;
}

/*设置ICMP报头*/
static int ping_test_pack(int pack_no, char *sendpacket)
{
    int packsize;
    struct icmp_echo_hdr *icmp;
    u32 *tval;

    icmp = (struct icmp_echo_hdr *)sendpacket;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->chksum = 0;
    icmp->seqno = pack_no;
    icmp->id = OWNER_PING_ID;
    tval = (u32 *)(icmp + 1);/* icmp data */
    *tval = tls_os_get_time();    /*记录发送时间*/
//	printf("send time:%d\n", *tval);
    memset(tval + 1, 0xff, PING_DATA_LEN - sizeof(u32));/* 填充剩下的28个字符 */
    packsize = ICMP_HEAD_LEN + PING_DATA_LEN;//8 + 32;
    icmp->chksum = ping_test_chksum((u16 *)icmp, packsize); /*校验算法*/
    return packsize;
}

/*剥去ICMP报头*/
static void ping_test_unpack(char *buf, int len, u32 tvrecv, struct sockaddr_in *from)
{
    int iphdrlen;
    struct ip_hdr *ip;
    struct icmp_echo_hdr *icmp;
    u32 *tvsend;
    u32 rtt;

    ip = (struct ip_hdr *)buf;
    iphdrlen = (ip->_v_hl & 0x0F) * 4;    /*求ip报头长度,即ip报头的长度标志乘4*/
    icmp = (struct icmp_echo_hdr *)(buf + iphdrlen); /*越过ip报头,指向ICMP报头*/
    len -= iphdrlen;            /*ICMP报头及ICMP数据报的总长度*/
    if(len < ICMP_HEAD_LEN)                /*小于ICMP报头长度则不合理*/
    {
        printf("ICMP packets's length is less than 8\n");
        return;
    }

    /*确保所接收的是我所发的的ICMP的回应*/
    if((icmp->type == ICMP_ER) &&
       (icmp->id == OWNER_PING_ID))
    {
        tvsend=(u32 *)(icmp + 1); /* icmp data */
        rtt = (tvrecv - (*tvsend)) * (1000/HZ);
        /*显示相关信息*/
        if (0 == rtt)
            printf("%d byte from %s: icmp_seq=%u ttl=%d rtt<%u ms\n",
                    len - ICMP_HEAD_LEN, inet_ntoa(from->sin_addr),
                    icmp->seqno, ip->_ttl, 1000/HZ);
        else
            printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%u ms\n",
                    len - ICMP_HEAD_LEN, inet_ntoa(from->sin_addr),
                    icmp->seqno, ip->_ttl, rtt);
        received_cnt++;
    }

    return;
}

static int ping_test_init(struct sockaddr_in *dest_addr)
{
    u32 addr;
    int socketid;
    char *hostname = NULL;
    struct hostent *host = NULL;

    send_cnt = 0;
    received_cnt = 0;

    socketid = socket(AF_INET, SOCK_RAW, IP_PROTO_ICMP);
    if(socketid < 0)
    {
        printf("create socket failed.\r\n");
        return -1;
    }

    hostname = g_ping_para.host;
    addr = inet_addr(hostname);
    /*判断是主机名还是ip地址*/
    if(INADDR_NONE == addr)/*是主机名*/
    {
        host = gethostbyname(hostname);
        if(NULL == host)
        {
            printf("can not get host ip.\r\n");
            closesocket(socketid);
            return -1;
        }
        memcpy((char *)&dest_addr->sin_addr, host->h_addr, host->h_length);
        printf("\nPING %s(%s): %d bytes data in ICMP packets.\r\n",
                hostname, inet_ntoa(dest_addr->sin_addr), PING_DATA_LEN);
    }
    else/*是ip地址*/
    {
        memcpy((char *)&dest_addr->sin_addr, (char *)&addr, sizeof(addr));
        printf("\nPING %s: %d bytes data in ICMP packets.\r\n",
                hostname, PING_DATA_LEN);
    }

    dest_addr->sin_family = AF_INET;
    return socketid;
}

static void ping_test_stat(void)
{
    printf("\n--------------------PING statistics-------------------\n");
    printf("%u packets transmitted, %u received , %u(%.3g%%) lost.\n",
            send_cnt,  received_cnt, send_cnt>=received_cnt ? send_cnt - received_cnt:0,
            send_cnt>=received_cnt ?((double)(send_cnt - received_cnt)) / send_cnt * 100:0);

    return;
}

static void ping_test_recv(int socket, struct sockaddr_in *dest_addr)
{
    int n, fromlen;
    struct sockaddr_in from;
    u32 tvrecv;
    char recvpacket[PACKET_SIZE];
    fd_set read_set;
    struct timeval tv;
    int ret;

    for ( ; ; )
    {
        FD_ZERO(&read_set);
        FD_SET(socket, &read_set);
        tv.tv_sec  = 0;
        tv.tv_usec = 1;

        ret = select(socket + 1, &read_set, NULL, NULL, &tv);
        if (ret > 0)
        {
            if (FD_ISSET(socket, &read_set))
            {
                fromlen=sizeof(from);
                memset(recvpacket, 0, PACKET_SIZE);
                n = recvfrom(socket, recvpacket, sizeof(recvpacket), 0, (struct sockaddr *)&from, (socklen_t *)&fromlen);
                if(n < 0)
                {
                    //printf("%d: recvfrom error\r\n", received_cnt + 1);
                    break;
                }

                tvrecv = tls_os_get_time(); /*记录接收时间*/
                ping_test_unpack(recvpacket, n, tvrecv, &from);

                FD_CLR(socket, &read_set);
            }
            else
            {
                break;
            }
        }
        else
        {
            break;
        }
    }

    return;
}

static void ping_test_send(int socket, struct sockaddr_in *dest_addr)
{
    int packetsize;
    char sendpacket[PACKET_SIZE];

//    if ((0 == g_ping_para.cnt) && (MAX_NO_PACKETS == send_cnt))
//    {
//        return;
//    }

	if((0 != g_ping_para.cnt) && (send_cnt >= g_ping_para.cnt))
	{
		return;
	}
	
    memset(sendpacket, 0, PACKET_SIZE);
    packetsize = ping_test_pack(send_cnt, sendpacket); /*设置ICMP报头*/
    if(sendto(socket, sendpacket, packetsize, 0, (struct sockaddr *)dest_addr, sizeof(*dest_addr)) < 0)
    {    
        //printf("%d: send icmp echo failed\r\n", send_cnt + 1);
        return;
    }
    send_cnt++;

//    if ((0 == g_ping_para.cnt) && (MAX_NO_PACKETS == send_cnt))
	if((0 != g_ping_para.cnt) && (send_cnt >= g_ping_para.cnt))
        tls_os_timer_start(ping_test_stop_timer);

    return;
}

static void ping_test_run(void)
{
    int socketid;
    struct sockaddr_in dest_addr;
	u32 lastTime = 0;
	u32 curTime = 0;

    memset(&dest_addr, 0, sizeof(dest_addr));
    socketid = ping_test_init(&dest_addr);
    if (socketid < 0)
        return;

    ping_test_abort = FALSE;
    ping_test_running = TRUE;

    for ( ; ; )
    {
        if (!ping_test_running)
            break;

        if (!ping_test_abort)
        {
        	curTime = tls_os_get_time();
			if((curTime-lastTime) >= (g_ping_para.interval/(1000/HZ)))
			{
//           		tls_os_time_delay(g_ping_para.interval / (1000/HZ));/* ms */
	            ping_test_send(socketid, &dest_addr);
				lastTime = tls_os_get_time();
			}
        }
        ping_test_recv(socketid, &dest_addr);
    }

    tls_os_timer_stop(ping_test_stop_timer);
    closesocket(socketid);

    ping_test_stat();

    return;
}

static void ping_test_task(void *data)
{
    void *msg;

    for( ; ; ) 
	{
		tls_os_queue_receive(ping_msg_queue, (void **)&msg, 0, 0);

		switch((u32)msg)
		{
			case PING_TEST_START:
			    ping_test_run();
				break;

			default:
				break;
		}
	}
}

static void ping_test_stop_timeout(void *ptmr, void *parg)
{
    ping_test_stop();

    return;
}

static void ping_test_abort_timeout(void *ptmr, void *parg)
{
    ping_test_running = FALSE;

    return;
}

void ping_test_create_task(void)
{
    if (ping_task_running)
        return;

    tls_os_task_create(NULL, NULL, ping_test_task,
                       (void *)0, (void *)TaskPingStk,
                       TASK_PING_STK_SIZE * sizeof(u32),
                       TASK_PING_PRIO, 0);

    ping_task_running = TRUE;

    tls_os_queue_create(&ping_msg_queue, PING_QUEUE_SIZE);

    tls_os_timer_create(&ping_test_stop_timer, ping_test_stop_timeout,
                        NULL, PING_STOP_TIMER_DELAY, FALSE, NULL);

    tls_os_timer_create(&ping_test_abort_timer, ping_test_abort_timeout,
                        NULL, PING_ABORT_TIMER_DELAY, FALSE, NULL);

    return;
}

void ping_test_start(struct ping_param *para)
{
    if (ping_test_running)
        return;

    memcpy(&g_ping_para, para, sizeof(struct ping_param));
    tls_os_queue_send(ping_msg_queue, (void *)PING_TEST_START, 0);

    return;
}

void ping_test_stop(void)
{
    ping_test_abort = TRUE;
    tls_os_timer_start(ping_test_abort_timer);

    return;
}
#endif

