#include "wm_include.h"
#include "wm_config.h"
#include "iperf.h"

#if TLS_CONFIG_WIFI_PERF_TEST

#define THT_QUEUE_SIZE	32
#define THT_TASK_PRIO	32
#define THT_TASK_STACK_SIZE 512
struct tht_param gThtSys;
tls_os_queue_t *tht_q = NULL;
OS_STK ThtTaskStk[THT_TASK_STACK_SIZE]; 
int testing = 0;
void tht_task(void *sdata)
{
	void *tht = (struct tht_param *)sdata;
	void *msg;
	for(;;) 
	{
		printf("\n tht_task \n");
		//msg = OSQPend(tht_q, 0, &error);
	    tls_os_queue_receive(tht_q,(void **)&msg,0,0);

		printf("\n msg =%d\n",msg);
		switch((u32)msg)
		{
			case TLS_MSG_WIFI_PERF_TEST_START:
				printf("\nTHT_TEST_START\n");
				tls_perf(tht);
				break;
			default:
				break;
		}
	}

}


void CreateThroughputTask(void)
{
    int err;
	if(!testing){
		memset(&gThtSys, 0 ,sizeof(struct tht_param));
		//tht_q = OSQCreate(&tht_queue, THT_QUEUE_SIZE);
       err =  tls_os_queue_create(&tht_q, THT_QUEUE_SIZE);
        //OSTaskCreate(tht_task, (void *)&gThtSys, (void *)&ThtTaskStk[512 - 1], THT_TASK_PRIO);
        tls_os_task_create(NULL, NULL,
                       tht_task,
                       (void *)&gThtSys,
                       (u8 *)ThtTaskStk,
                       THT_TASK_STACK_SIZE * sizeof(u32),
                       THT_TASK_PRIO,
                       0);
		testing = 1;
		printf("CreateThroughputTask\n");
	}
}

#endif 

