#ifndef _AJ_TARGET_H
#define _AJ_TARGET_H
/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2012-2014, AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
//#include <unistd.h>
#include <string.h>
#ifndef WM_W600
#include <assert.h>
#else
#ifndef assert
#define assert(n)
#endif
#endif
#include "wm_type_def.h"
//#include <endian.h>

/** uintxx_t: it's defined in stdint.h **/
/*
#ifdef uint8_t
#undef uint8_t
#endif
#ifdef int8_t
#undef int8_t
#endif
#ifdef uint16_t
#undef uint16_t
#endif
#ifdef int16_t
#undef int16_t
#endif
#ifdef uint32_t
#undef uint32_t
#endif
#ifdef int32_t
#undef int32_t
#endif
#ifdef uint64_t
#undef uint64_t
#endif
#ifdef int64_t
#undef int64_t
#endif
typedef unsigned char           uint8_t;
typedef signed char             int8_t;
typedef unsigned short          uint16_t; 
typedef signed short            int16_t;
typedef unsigned int            uint32_t;
typedef signed int              int32_t;
typedef unsigned long long      uint64_t;
typedef long long               int64_t;
*/


#define __winnermicro_  

#ifndef max
#define max(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif

#define WORD_ALIGN(x) ((x & 0x3) ? ((x >> 2) + 1) << 2 : x)

#if 1
#define HOST_IS_LITTLE_ENDIAN  TRUE
#define HOST_IS_BIG_ENDIAN     FALSE
#else
#define HOST_IS_LITTLE_ENDIAN  FALSE
#define HOST_IS_BIG_ENDIAN     TRUE
#endif

/**
 * Set or clear the log file for debug output.
 *
 * @param file   A file path or NULL if clearing the log file.
 * @param maxLen Maximum length the log file is allowed to grow. The log file is periodically
 *               truncated to keep the length between maxLen / 2 and maxLen. Zero means no limit.
 */
int AJ_SetLogFile(const char* file, uint32_t maxLen);


#define AJ_Printf(fmat, ...) \
    do { printf(fmat, ## __VA_ARGS__); } while (0)


#ifndef NDEBUG
extern uint8_t dbgCONFIGUREME;
extern uint8_t dbgINIT;
extern uint8_t dbgNET;
extern uint8_t dbgTARGET_CRYPTO;
extern uint8_t dbgTARGET_NVRAM;
extern uint8_t dbgTARGET_SERIAL;
extern uint8_t dbgTARGET_TIMER;
extern uint8_t dbgTARGET_UTIL;

#endif

#define AJ_ASSERT(x) assert(x)

/*
 * AJ_Reboot() is a NOOP on this platform
 */
#define AJ_Reboot()

#define AJ_CreateNewGUID AJ_RandBytes

#define AJ_EXPORT

/*
 * Main method allows argc, argv
 */
#define MAIN_ALLOWS_ARGS

#define AJ_GetDebugTime(x) _AJ_GetDebugTime(x)

#endif
