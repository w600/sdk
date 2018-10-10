#ifndef __WM_UPNP_TASK_H__
#define __WM_UPNP_TASK_H__

#include "sys_arch.h"
#include "timers.h"
#include "wm_wl_task.h"

enum upnp_msg_type {
  UPNP_MSG_TIMEOUT,
  UPNP_MSG_UNTIMEOUT,
  UPNP_MSG_CALLBACK
};
struct upnp_msg {
  enum upnp_msg_type type;
  sys_sem_t *sem;
  union {
    struct {
      start_routine function;
      void *ctx;
    } cb;
    struct {
      UINT msecs;
      sys_timeout_handler h;
      void *arg;
    } tmo;
  } msg;
};
enum upnp_task_type {
  UPNP_HD_TASK = 0, // http download
  UPNP_COMMON_TASK,
  UPNP_GENA_TASK,
  UPNP_MINI_SERVER_TASK,
  UPNP_ALL_TASK
};

void
upnp_init(void);
err_t
upnp_callback_with_block(enum upnp_task_type task_type, start_routine function, void *ctx, UCHAR block);
err_t
upnp_add_timeout(enum upnp_task_type task_type, UINT msecs, sys_timeout_handler h, void *arg);
err_t
upnp_untimeout(enum upnp_task_type task_type, sys_timeout_handler h, void *arg);

#endif

