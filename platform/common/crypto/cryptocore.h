#ifndef _CRYPTO_CORE_H_
#define _CRYPTO_CORE_H_

#include <string.h> /* memset, memcpy */
#include "wm_mem.h"
#include <stdlib.h> 		/* malloc, free, etc... */

typedef int32 psPool_t;

#define psMalloc(A, B)		tls_mem_alloc(B)
#define psMallocNoPool		tls_mem_alloc
#define psRealloc				tls_mem_realloc
#define psFree				tls_mem_free
#define psMemset			memset
#define psMemcpy			MEMCPY

#define PSPUBLIC
/******************************************************************************/
/*
	Raw trace and error
*/
#define _psTrace       printf
#define _psTraceInt  _psTrace
#define _psTraceStr  _psTrace
#define psTraceBytes(tag, p, len);  TLS_DBGPRT_DUMP(p, len)
#if 0
#if (GCC_COMPILE==1)
void _psError(char *msg)
#else
static inline void _psError(char* msg)
#endif
{
	_psTrace(msg);
	_psTrace("\n");
}
#endif

#undef psAssert
#define psAssert(C)  if (C) ; else \
{_psTraceStr("psAssert %s", __FILE__);_psTraceInt(":%d ", __LINE__);\
_psError(#C);} 

#undef psError
#define psError(a) \
 _psTraceStr("psError %s", __FILE__);_psTraceInt(":%d ", __LINE__); \
 _psError(a);

#endif

