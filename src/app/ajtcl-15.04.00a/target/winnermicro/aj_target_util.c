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
#define AJ_MODULE TARGET_UTIL

//#include <time.h>
//#include <unistd.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <pthread.h>
//#include <byteswap.h>
#include <stdarg.h>
//#include <arpa/inet.h>
#include <aj_debug.h>
#include "aj_target.h"
#include "aj_util.h"
#include "wm_osal.h"
#include "wm_mem.h"

uint8_t dbgTARGET_UTIL = 0;

void AJ_Sleep(uint32_t time)
{
    int delay = time/10;
    if(delay == 0)
        delay = 1;
    tls_os_time_delay(delay);
}

#ifndef NDEBUG
AJ_Status _AJ_GetDebugTime(AJ_Time* timer)
{
    int ticks = tls_os_get_time();
    timer->seconds = ticks / 100;
    timer->milliseconds = (ticks % 100) * 10;
    return AJ_OK;
}
#endif

uint32_t AJ_GetElapsedTime(AJ_Time* timer, uint8_t cumulative)
{
    uint32_t elapsed;
    AJ_Time now;

    int ticks = tls_os_get_time();
    now.seconds = ticks / 100;
    now.milliseconds = (ticks % 100) * 10;
    elapsed = (1000 * (now.seconds - timer->seconds)) + (now.milliseconds - timer->milliseconds);
    if (!cumulative) {
        timer->seconds = now.seconds;
        timer->milliseconds = now.milliseconds;
    }
    return elapsed;
}
void AJ_InitTimer(AJ_Time* timer)
{
    int ticks = tls_os_get_time();
    timer->seconds = ticks / 100;
    timer->milliseconds = (ticks % 100) * 10;

}

int32_t AJ_GetTimeDifference(AJ_Time* timerA, AJ_Time* timerB)
{
    int32_t diff;

    diff = (1000 * (timerA->seconds - timerB->seconds)) + (timerA->milliseconds - timerB->milliseconds);
    return diff;
}

void AJ_TimeAddOffset(AJ_Time* timerA, uint32_t msec)
{
    uint32_t msecNew;
    if (msec == (uint32_t)-1) {
        timerA->seconds = (uint32_t)-1;
        timerA->milliseconds = (uint16_t)-1;
    } else {
        msecNew = (timerA->milliseconds + msec);
        timerA->seconds = timerA->seconds + (msecNew / 1000);
        timerA->milliseconds = msecNew % 1000;
    }
}


int8_t AJ_CompareTime(AJ_Time timerA, AJ_Time timerB)
{
    if (timerA.seconds == timerB.seconds) {
        if (timerA.milliseconds == timerB.milliseconds) {
            return 0;
        } else if (timerA.milliseconds > timerB.milliseconds) {
            return 1;
        } else {
            return -1;
        }
    } else if (timerA.seconds > timerB.seconds) {
        return 1;
    } else {
        return -1;
    }
}

void* AJ_Malloc(size_t sz)
{
    return tls_mem_alloc(sz);
}
void* AJ_Realloc(void* ptr, size_t size)
{
    return tls_mem_realloc(ptr, size);
}

void AJ_Free(void* mem)
{
    if (mem) {
        tls_mem_free(mem);
    }
}
#if 0
/*
 * get a line of input from the the file pointer (most likely stdin).
 * This will capture the the num-1 characters or till a newline character is
 * entered.
 *
 * @param[out] str a pointer to a character array that will hold the user input
 * @param[in]  num the size of the character array 'str'
 * @param[in]  fp  the file pointer the sting will be read from. (most likely stdin)
 *
 * @return returns the same string as 'str' if there has been a read error a null
 *                 pointer will be returned and 'str' will remain unchanged.
 */
char*AJ_GetLine(char*str, size_t num, void*fp)
{
    char*p = fgets(str, num, fp);

    if (p != NULL) {
        size_t last = strlen(str) - 1;
        if (str[last] == '\n') {
            str[last] = '\0';
        }
    }
    return p;
}

static uint8_t ioThreadRunning = FALSE;
static char cmdline[1024];
static uint8_t consumed = TRUE;
//static pthread_t threadId;

void* RunFunc(void* threadArg)
{
    while (ioThreadRunning) {
        if (consumed) {
            AJ_GetLine(cmdline, sizeof(cmdline), stdin);
            consumed = FALSE;
        }
        AJ_Sleep(1000);
    }
    return 0;
}

uint8_t AJ_StartReadFromStdIn()
{
    int ret = 0;
    if (!ioThreadRunning) {
        ret = pthread_create(&threadId, NULL, RunFunc, NULL);
        if (ret != 0) {
            AJ_ErrPrintf(("Error: fail to spin a thread for reading from stdin\n"));
        }
        ioThreadRunning = TRUE;
        return TRUE;
    }
    return FALSE;
}

char* AJ_GetCmdLine(char* buf, size_t num)
{
    if (!consumed) {
        strncpy(buf, cmdline, num);
        buf[num - 1] = '\0';
        consumed = TRUE;
        return buf;
    }
    return NULL;
}

uint8_t AJ_StopReadFromStdIn()
{
    void* exit_status;
    if (ioThreadRunning) {
        ioThreadRunning = FALSE;
        pthread_join(threadId, &exit_status);
        return TRUE;
    }
    return FALSE;
}
#endif

#ifndef NDEBUG

/*
 * This is not intended, nor required to be particularly efficient.  If you want
 * efficiency, turn of debugging.
 */
int _AJ_DbgEnabled(const char* module)
{
    char buffer[128];
    char* env;

    strcpy(buffer, "ER_DEBUG_ALL");
    env = getenv(buffer);
    if (env && strcmp(env, "1") == 0) {
        return TRUE;
    }

    strcpy(buffer, "ER_DEBUG_");
    strcat(buffer, module);
    env = getenv(buffer);
    if (env && strcmp(env, "1") == 0) {
        return TRUE;
    }

    return FALSE;
}

#endif

uint16_t AJ_ByteSwap16(uint16_t x)
{
    return ((x << 8) & 0x0000FF00) | ((x >> 8) & 0x000000FF);
}

uint32_t AJ_ByteSwap32(uint32_t x)
{
     return ((x >> 24) & 0x000000FF) | ((x >> 8) & 0x0000FF00) |
           ((x << 24) & 0xFF000000) | ((x << 8) & 0x00FF0000);
}

uint64_t AJ_ByteSwap64(uint64_t x)
{
    return ((x >> 56) & 0x00000000000000FF) | ((x >> 40) & 0x000000000000FF00) |
           ((x << 56) & 0xFF00000000000000) | ((x << 40) & 0x00FF000000000000) |
           ((x >> 24) & 0x0000000000FF0000) | ((x >>  8) & 0x00000000FF000000) |
           ((x << 24) & 0x0000FF0000000000) | ((x <<  8) & 0x000000FF00000000);
}

AJ_Status AJ_IntToString(int32_t val, char* buf, size_t buflen)
{
    AJ_Status status = AJ_OK;
    int c = snprintf(buf, buflen, "%d", val);
    if (c <= 0 || c > buflen) {
        status = AJ_ERR_RESOURCES;
    }
    return status;
}

AJ_Status AJ_InetToString(uint32_t addr, char* buf, size_t buflen)
{
    AJ_Status status = AJ_OK;
    int c = snprintf((char*)buf, buflen, "%u.%u.%u.%u", (addr & 0xFF000000) >> 24, (addr & 0x00FF0000) >> 16, (addr & 0x0000FF00) >> 8, (addr & 0x000000FF));
    if (c <= 0 || c > buflen) {
        status = AJ_ERR_RESOURCES;
    }
    return status;
}
#if 0
static FILE* logFile = NULL;
static uint32_t logLim = 0;

int AJ_SetLogFile(const char* file, uint32_t maxLen)
{
    if (logFile) {
        fclose(logFile);
    }
    if (!file) {
        logFile = NULL;
    } else {
        logFile = fopen(file, "w+");
        if (!logFile) {
            return -1;
        }
        logLim = maxLen / 2;
    }
    return 0;
}
#endif
static uint32_t  cpu_sr;
void AJ_EnterCriticalRegion(void)
{
    tls_os_release_critical(cpu_sr);
}

void AJ_LeaveCriticalRegion(void)
{
    tls_os_release_critical(cpu_sr);
}

uint32_t AJ_SeedRNG(void)
{
    return tls_os_get_time();
}
void AJ_RandBytes(uint8_t* random, uint32_t len)
{
    AJ_SeedRNG();
    while (len) {
        *random = (AJ_SeedRNG() + rand()) & 0xFF;
        len -= 1;
        random += 1;
    }
}

uint64_t AJ_DecodeTime(char* der, char* fmt)
{
    return 0;
}

AJ_Status AJ_AcquireIPAddress(uint32_t* ip, uint32_t* mask, uint32_t* gateway, int32_t timeout)
{
	
	return AJ_OK;
}

void AJ_MemZeroSecure(void* s, size_t n)
{
	memset(s, 0, n);
}
