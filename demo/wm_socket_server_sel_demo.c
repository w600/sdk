#include <string.h>
#include "wm_include.h"
#include "wm_sockets.h"

#if DEMO_STD_SOCKET_SER_SEL
#define    DEMO_SOCK_S_SEL_TASK_SIZE      256
tls_os_queue_t *demo_sock_s_sel_q = NULL;
static OS_STK DemoSockSSelTaskStk[DEMO_SOCK_S_SEL_TASK_SIZE]; 

extern ST_Demo_Sys gDemoSys;
static void demo_sock_s_sel_task(void *sdata);

#define MYPORT 1234    // the port users will be connecting to

#define BACKLOG 7     // how many pending connections queue will hold

#define BUF_SIZE 200

int fd_A[BACKLOG] = {-1, -1, -1, -1, -1, -1, -1};    // accepted connection fd
int conn_amount;    // current connection amount

void showclient()
{
    int i;
    printf("client amount: %d\n", conn_amount);
    for (i = 0; i < BACKLOG; i++) {
        printf("[%d]:%d  ", i, fd_A[i]);
    }
    printf("\n\n");
}

int socket_server(void)
{
    int sock_fd, new_fd;  // listen on sock_fd, new connection on new_fd
    struct sockaddr_in server_addr;    // server address information
    struct sockaddr_in client_addr; // connector's address information
    socklen_t sin_size;
    int yes = 1;
    char buf[BUF_SIZE];
    int ret;
    int i;

    fd_set fdsr;
    int maxsock;
    struct timeval tv;

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("socket\n");
        return 1;
    }

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        printf("setsockopt\n");
        return 1;
    }
    
    server_addr.sin_family = AF_INET;         // host byte order
    server_addr.sin_port = htons(MYPORT);     // short, network byte order
    server_addr.sin_addr.s_addr = ((u32)0x00000000UL); // automatically fill with my IP
    memset(server_addr.sin_zero, '\0', sizeof(server_addr.sin_zero));

    if (bind(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        printf("bind\n");
        return 1;
    }

    if (listen(sock_fd, BACKLOG) == -1) {
        printf("listen\n");
        return 1;
    }

    printf("listen port %d\n", MYPORT);

    conn_amount = 0;
    sin_size = sizeof(client_addr);
    maxsock = sock_fd;
    while (1) {
        // initialize file descriptor set
        FD_ZERO(&fdsr);
        FD_SET(sock_fd, &fdsr);

        // timeout setting
        tv.tv_sec = 30;
        tv.tv_usec = 0;

        // add active connection to fd set
        for (i = 0; i < BACKLOG; i++) {
            if (fd_A[i] != -1) {
                FD_SET(fd_A[i], &fdsr);
                if(fd_A[i] > maxsock)
                    maxsock = fd_A[i];
            }
        }
        //printf("maxsock: %d\n", maxsock);
        ret = select(maxsock + 1, &fdsr, NULL, NULL, &tv);
        if (ret < 0) {
            printf("select\n");
            break;
        } else if (ret == 0) {
            printf("timeout\n");
            continue;
        }

        // check every fd in the set
        for (i = 0; i < BACKLOG; i++) {
            if(fd_A[i] == -1 || fd_A[i] == sock_fd)
                continue;
            if (FD_ISSET(fd_A[i], &fdsr)) {
                ret = recv(fd_A[i], buf, BUF_SIZE, 0);
                if (ret <= 0) {        // client close
                    printf("client[%d] close\n", i);
                    closesocket(fd_A[i]);
                    FD_CLR(fd_A[i], &fdsr);
                    conn_amount--;
                    fd_A[i] = -1;
                } else {        // receive data
                    if (ret < BUF_SIZE)
                        memset(&buf[ret], '\0', 1);
                    printf("ret=%d, client[%d] send:%s\n", ret, i, buf);
                }
            }
        }

        // check whether a new connection comes
        if (FD_ISSET(sock_fd, &fdsr)) {
            new_fd = accept(sock_fd, (struct sockaddr *)&client_addr, &sin_size);
            if (new_fd <= 0) {
                printf("accept\n");
                continue;
            }

            // add to fd queue
            if (conn_amount < BACKLOG) {
		 for (i = 0; i < BACKLOG; i++) {
	            if (fd_A[i] == -1) {
	                fd_A[i] = new_fd;
                	  conn_amount++;
			  break;
	            }
	        }
                printf("new connection client[%d] %s:%d\n", conn_amount,
                        inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                if (new_fd > maxsock)
                    maxsock = new_fd;
            }
            else {
                printf("max connections arrive, exit\n");
                send(new_fd, "bye", 4, 0);
                closesocket(new_fd);
            }
        }
        showclient();
    }

    // close other connections
    for (i = 0; i < BACKLOG; i++) {
        if (fd_A[i] != -1) {
            closesocket(fd_A[i]);
        }
    }
    closesocket(sock_fd);

    return 0;
}

static void sock_s_sel_net_status_changed_event(u8 status )
{
	switch(status)
	{
		case NETIF_WIFI_JOIN_FAILED:
			tls_os_queue_send(demo_sock_s_sel_q, (void *)DEMO_MSG_WJOIN_FAILD, 0);
			break;
		case NETIF_WIFI_JOIN_SUCCESS:
			tls_os_queue_send(demo_sock_s_sel_q, (void *)DEMO_MSG_WJOIN_SUCCESS, 0);
			break;
		case NETIF_IP_NET_UP:
			tls_os_queue_send(demo_sock_s_sel_q, (void *)DEMO_MSG_SOCKET_CREATE, 0);
			break;
		default:
			break;
	}
}

int CreateSockSSelDemoTask(char *buf)
{
	tls_os_queue_create(&demo_sock_s_sel_q, DEMO_QUEUE_SIZE);		
	tls_os_task_create(NULL, NULL,
			demo_sock_s_sel_task,
                    (void *)&gDemoSys,
                    (void *)DemoSockSSelTaskStk,          /* 任务栈的起始地址 */
                    DEMO_SOCK_S_SEL_TASK_SIZE * sizeof(u32), /* 任务栈的大小     */
                    DEMO_SOCK_S_SEL_TASK_PRIO,
                    0);
	return WM_SUCCESS;
}


static void demo_sock_s_sel_task(void *sdata)
{
//	ST_Demo_Sys *sys = (ST_Demo_Sys *)sdata;
	void *msg;
	struct tls_ethif * ethif = tls_netif_get_ethif();

	printf("\nsock_s_sel task\n");

	if(ethif->status)	//已经在网
	{
		tls_os_queue_send(demo_sock_s_sel_q, (void *)DEMO_MSG_SOCKET_CREATE, 0);
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
	tls_netif_add_status_event(sock_s_sel_net_status_changed_event);

	for(;;) 
	{
		tls_os_queue_receive(demo_sock_s_sel_q, (void **)&msg, 0, 0);
		//printf("\n msg =%d\n",msg);
		switch((u32)msg)
		{
			case DEMO_MSG_WJOIN_SUCCESS:
				break;
			case DEMO_MSG_SOCKET_CREATE:
				socket_server();
				break;
			case DEMO_MSG_WJOIN_FAILD:
				break;
			default:
				break;
		}
	}

}


#endif //DEMO_STD_SOCKET_SER_SEL

