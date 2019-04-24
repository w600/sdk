#ifndef USER_MAIN_H
#define USER_MAIN_H
#include "wm_include.h"

#define USER_DEBUG		1
#if USER_DEBUG
#define USER_PRINT printf
#else
#define USER_PRINT(fmt, ...)
#endif

#define BLN_PWM     WM_IO_PB_08
#define BLN_CHANNEL 4
#define BLN_FREQ    20000

#define TIMER_PERIOD    6536
#endif
