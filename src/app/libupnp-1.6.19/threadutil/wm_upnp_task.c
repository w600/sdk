#include "wm_upnp_task.h"
#include "wm_socket.h"
#include "wm_wl_task.h"

#define UPNP_STK_SIZE  1400
#define UPNP_GENA_STK_SIZE  700
#define UPNP_HD_STK_SIZE  500 //http download
#define UPNP_MINISERVER_STK_SIZE  700
OS_STK         upnp_task_stk[UPNP_STK_SIZE+UPNP_GENA_STK_SIZE+UPNP_HD_STK_SIZE+UPNP_MINISERVER_STK_SIZE];


struct task_parameter upnp_hd_task_param = {
	.mbox_size = 128,
	.name = NULL,
	.stk_size = UPNP_HD_STK_SIZE,
	.stk_start = (u8 *)&upnp_task_stk[0],
	.task_id = TLS_UPNP_TASK_PRIO + UPNP_HD_TASK,
	.mbox_id = TLS_MBOX_ID_UPNP_HD,
	.timeo_id = TLS_TIMEO_ID_UPNP_HD,
};
 struct task_parameter upnp_common_task_param = {
	.mbox_size = 32,
	.name = NULL,
	.stk_size = UPNP_STK_SIZE,
	.stk_start = (u8 *)&upnp_task_stk[UPNP_HD_STK_SIZE],
	.task_id = TLS_UPNP_TASK_PRIO + UPNP_COMMON_TASK,
	.mbox_id = TLS_MBOX_ID_UPNP_COMMON,
	.timeo_id = TLS_TIMEO_ID_UPNP_COMMON,
};
 struct task_parameter upnp_gena_task_param = {
	.mbox_size = 32,
	.name = NULL,
	.stk_size = UPNP_GENA_STK_SIZE,
	.stk_start = (u8 *)&upnp_task_stk[UPNP_HD_STK_SIZE+UPNP_STK_SIZE],
	.task_id = TLS_UPNP_TASK_PRIO + UPNP_GENA_TASK,
	.mbox_id = TLS_MBOX_ID_UPNP_GENA,
	.timeo_id = TLS_TIMEO_ID_UPNP_GENA,
};

struct task_parameter upnp_miniserver_task_param = {
	.mbox_size = 32,
	.name = NULL,
	.stk_size = UPNP_MINISERVER_STK_SIZE,
	.stk_start = (u8 *)&upnp_task_stk[UPNP_HD_STK_SIZE+UPNP_STK_SIZE+UPNP_GENA_STK_SIZE],
	.task_id = TLS_UPNP_TASK_PRIO + UPNP_MINI_SERVER_TASK,
	.mbox_id = TLS_MBOX_ID_UPNP_MINISERVER,
	.timeo_id = TLS_TIMEO_ID_UPNP_MINISERVER,
};


void
upnp_init()
{
	tls_wl_task_run(&upnp_hd_task_param);
	tls_wl_task_run(&upnp_common_task_param);
	tls_wl_task_run(&upnp_gena_task_param);
	tls_wl_task_run(&upnp_miniserver_task_param);
}

static struct task_parameter * upnp_get_task_param(enum upnp_task_type task_type)
{
	switch(task_type)
	{
		case UPNP_HD_TASK:
			return &upnp_hd_task_param;
		case UPNP_COMMON_TASK:
			return &upnp_common_task_param;
		case UPNP_MINI_SERVER_TASK:
			return &upnp_miniserver_task_param;
		default:
			return &upnp_gena_task_param;
	}
}

err_t
upnp_callback_with_block(enum upnp_task_type task_type, start_routine function, void *ctx, UCHAR block)
{
	struct task_parameter * task_param = upnp_get_task_param(task_type);
	return tls_wl_task_callback(task_param, function, ctx, block);
}

err_t
upnp_add_timeout(enum upnp_task_type task_type, UINT msecs, sys_timeout_handler h, void *arg)
{
	struct task_parameter * task_param = upnp_get_task_param(task_type);
	return tls_wl_task_add_timeout(task_param, msecs, h, arg);
}

err_t
upnp_untimeout(enum upnp_task_type task_type, sys_timeout_handler h, void *arg)
{
	struct task_parameter * task_param = upnp_get_task_param(task_type);
	return tls_wl_task_untimeout(task_param, h, arg);
}
