#ifndef USER_MAIN_H
#define USER_MAIN_H
#include "wm_include.h"

#define USER_DEBUG		1
#if USER_DEBUG
#define USER_PRINT printf
#else
#define USER_PRINT(fmt, ...)
#endif

#define USER_INFO_MAGIC  0xC98980FF
#define USER_INFO_LEN   100
#define USER_INFO_ADDR1 0x080EF000  //用户区域起始地址，不可小于此地址
#define USER_INFO_ADDR2 (0x080EF000 + sizeof(user_data_s))

typedef struct _user_data_s
{
    u32 magic;
    u8 data[USER_INFO_LEN];
    u32 crc;
}user_data_s;

#endif
