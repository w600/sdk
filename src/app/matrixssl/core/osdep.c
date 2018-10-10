/*
 *	osdep.c
 *	Release $Name: MATRIXSSL-3-6-1-OPEN $
 *
 *	POSIX layer
 *		Mac OSX 10.5
 *		Linux
 */
/*
 *	Copyright (c) 2013-2014 INSIDE Secure Corporation
 *	Copyright (c) PeerSec Networks, 2002-2011
 *	All Rights Reserved
 *
 *	The latest version of this code is available at http://www.matrixssl.org
 *
 *	This software is open source; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This General Public License does NOT permit incorporating this software 
 *	into proprietary programs.  If you are unable to comply with the GPL, a 
 *	commercial license for this software may be purchased from INSIDE at
 *	http://www.insidesecure.com/eng/Company/Locations
 *	
 *	This program is distributed in WITHOUT ANY WARRANTY; without even the 
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 *	See the GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *	http://www.gnu.org/copyleft/gpl.html
 */
/******************************************************************************/

/******************************************************************************/

/******************************************************************************/

/*
	Universal system POSIX headers and then PScore/coreApi.h 
	OS-specific header includes should be added to PScore/osdep.h
*/
#include <stdlib.h>	/* abort() */
//#include <fcntl.h>	/* open(), O_RDONLY, ect... */
//#include <unistd.h>	/* close() */
#include <errno.h>	/* errno */
//#include <sys/time.h>	/* gettimeofday */

#include "coreApi.h"
#include "wm_osal.h"
#ifdef USE_PKCS11_ENTROPY
#include "cryptoki.h"
#endif

/******************************************************************************/
/*
	TIME FUNCTIONS
*/
#if 1
#if 0
/******************************************************************************/
/*
	Module open and close
*/
int osdepTimeOpen(void)
{
/*
	psTime_t	lt;
	Just a check that gettimeofday is functioning

	if (gettimeofday(&lt, NULL) < 0) {
		return PS_FAILURE;
	}*/
	return PS_SUCCESS;
}

void osdepTimeClose()
{
}
#endif
/*
	PScore Public API implementations
	
	This function always returns seconds/ticks AND OPTIONALLY populates
	whatever psTime_t happens to be on the given platform.
*/
int32 psGetTime(psTime_t *t)
{
//	psTime_t	lt;

	
	
	if (t == NULL) {
		return tls_os_get_time() / HZ;
	} 

	t->tv_sec = tls_os_get_time() / HZ;
	t->tv_usec = (tls_os_get_time() % HZ) * 1000 * 1000 / HZ;
	
	return t->tv_sec;
}

int32 psDiffMsecs(psTime_t then, psTime_t now)
{
	if (now.tv_usec < then.tv_usec) {
		now.tv_sec--;
		now.tv_usec += 1000000; /* borrow 1 second worth of usec */
	}
	return (int32)((now.tv_sec - then.tv_sec) * 1000) + 
		((now.tv_usec - then.tv_usec)/ 1000);
}

int32 psCompareTime(psTime_t a, psTime_t b)
{
/*
	Time comparison.  1 if 'a' is less than or equal.  0 if 'a' is greater
*/
	if (a.tv_sec < b.tv_sec) {
		return 1;
	}
	if (a.tv_sec == b.tv_sec && a.tv_usec <= b.tv_usec) {
		return 1;
	}
	return 0;
}

#else /* USE_HIGHRES_TIME */
/******************************************************************************/
#if 0
/* MAC OS X */

#include <mach/mach_time.h>

static mach_timebase_info_data_t hiresFreq;
	
int osdepTimeOpen(void)
{
	mach_timebase_info(&hiresFreq);
	return PS_SUCCESS;
}

void osdepTimeClose()
{
}

int32 psGetTime(psTime_t *t)
{
	psTime_t	lt;
	
	if (t == NULL) {
		t = &lt;
	}
	*t = mach_absolute_time();
	return (int32)((*t * hiresFreq.numer) / (hiresFreq.denom * 1000000000L));
}

int32 psDiffMsecs(psTime_t then, psTime_t now)
{
	return (int32)(((now - then) * hiresFreq.numer) / (hiresFreq.denom * 1000000));
}

int64_t psDiffUsecs(psTime_t then, psTime_t now)
{
	return (int64_t)(((now - then) * hiresFreq.numer) / (hiresFreq.denom * 1000));
}

int32 psCompareTime(psTime_t a, psTime_t b)
{
	return a <= b ? 1 : 0;
}

/******************************************************************************/
#else /* !APPLE, !tile */
/******************************************************************************/
/* LINUX */
int osdepTimeOpen(void)
{
	return PS_SUCCESS;
}

void osdepTimeClose()
{
}

int32 psGetTime(psTime_t *t)
{
	psTime_t	lt;
	
	if (t == NULL) {
		t = &lt;
	}
	clock_gettime(CLOCK_MONOTONIC, t);
	return t->tv_sec;
}

int32 psDiffMsecs(psTime_t then, psTime_t now)
{
	if (now.tv_nsec < then.tv_nsec) {
		now.tv_sec--;
		now.tv_nsec += 1000000000L; /* borrow 1 second worth of nsec */
	}
	return (int32)((now.tv_sec - then.tv_sec) * 1000) + 
		((now.tv_nsec - then.tv_nsec)/ 1000000);
}

int64_t psDiffUsecs(psTime_t then, psTime_t now)
{
	if (now.tv_nsec < then.tv_nsec) {
		now.tv_sec--;
		now.tv_nsec += 1000000000L; /* borrow 1 second worth of nsec */
	}
	return (int32)((now.tv_sec - then.tv_sec) * 1000) + 
		((now.tv_nsec - then.tv_nsec)/ 1000);
}

int32 psCompareTime(psTime_t a, psTime_t b)
{
	/* Time comparison.  1 if 'a' is less than or equal.  0 if 'a' is greater */
	if (a.tv_sec < b.tv_sec) {
		return 1;
	}
	if (a.tv_sec == b.tv_sec && a.tv_nsec <= b.tv_nsec) {
		return 1;
	}
	return 0;
}
#endif /* !APPLE */

#endif /* USE_HIGHRES_TIME */

/******************************************************************************/

#if 0
/******************************************************************************/
/*
	MUTEX FUNCTIONS
*/
/******************************************************************************/
static pthread_mutexattr_t attr;
/*
	Module open and close
*/
int osdepMutexOpen(void)
{
	int32	rc;

	if ((rc = pthread_mutexattr_init(&attr)) < 0) {
		psErrorInt("pthread_mutexattr_init failed %d\n", rc);
		return PS_PLATFORM_FAIL;
	}
	return PS_SUCCESS; 
}

int osdepMutexClose()
{
	if (pthread_mutexattr_destroy(&attr) != 0) {
		psTraceCore("pthread_mutex_destroy failed\n");
	}
	return PS_SUCCESS; 
}

/*
	PScore Public API implementations
*/
int32 psCreateMutex(psMutex_t *mutex)
{
	int32 err;

	if ((err = pthread_mutex_init(mutex, &attr)) != 0) {
		psTraceIntCore("pthread_mutex_init failed %d\n", err);
		return PS_PLATFORM_FAIL;
	}	
	return PS_SUCCESS;
}

int32 psLockMutex(psMutex_t *mutex)
{
	if (pthread_mutex_lock(mutex) != 0) {
		psTraceCore("pthread_mutex_lock failed\n");
		return PS_PLATFORM_FAIL;
	}
	return PS_SUCCESS;
}

int32 psUnlockMutex(psMutex_t *mutex)
{
	if (pthread_mutex_unlock(mutex) != 0) {
		psTraceCore("pthread_mutex_unlock failed\n");
		return PS_PLATFORM_FAIL;
	}
	return PS_SUCCESS;
}

void psDestroyMutex(psMutex_t *mutex)
{
	pthread_mutex_destroy(mutex);
}
#endif /* USE_MULTITHREADING */
/******************************************************************************/


/******************************************************************************/
/*
	ENTROPY FUNCTIONS
*/
/******************************************************************************/
#if   0
int osdepEntropyOpen(void)
{
	return PS_SUCCESS;
}
void osdepEntropyClose(void)
{
}
int32 psGetEntropy(unsigned char *bytes, uint32 size)
{
	CK_RV rv;
	CK_SESSION_HANDLE hSes;

	if (pkcs11OpenSession(&hSes, 0) != CKR_OK) {
		return PS_PLATFORM_FAIL;
	}

	if ( (rv = C_GenerateRandom(hSes, bytes, size)) ) {
		pkcs11CloseSession(hSes);
		return PS_PLATFORM_FAIL;
	}

	pkcs11CloseSession(hSes); 
	return (int32)size;
}
/******************************************************************************/
#else
#if 0
#define	MAX_RAND_READS		1024

//static int32 urandfd = -1;
//static int32 randfd = -1;
/*
	Module open and close
*/
int osdepEntropyOpen(void)
{
/*
	Open /dev/random access non-blocking.

	if ((urandfd = open("/dev/urandom", O_RDONLY)) < 0) {
		psErrorInt("open of urandom failed %d\n", urandfd);
		return PS_PLATFORM_FAIL;
	}*/
/*
	For platforms that don't have /dev/random, just assign it to urandom

	if ((randfd = open("/dev/random", O_RDONLY | O_NONBLOCK)) < 0) {
		randfd=urandfd;
	}*/
	return PS_SUCCESS;
}

void osdepEntropyClose(void)
{
	/*
	if (randfd != urandfd) {
		close(randfd);
	}
	close(urandfd);*/
}

/*
	PScore Public API implementations
*/
int32 psGetEntropy(unsigned char *bytes, uint32 size)
{
/*
	Read from /dev/random non-blocking first, then from urandom if it would 
	block.  Also, handle file closure case and re-open.

	int32			rc, sanity, retry, readBytes;
	unsigned char 	*where = bytes;

	sanity = retry = rc = readBytes = 0;

	while (size) {
		if ((rc = read(randfd, where, size)) < 0 || sanity > MAX_RAND_READS) {
			if (errno == EINTR) {
				if (sanity > MAX_RAND_READS) {
					psTraceCore("psGetEntropy failed randfd sanity\n");
					return PS_PLATFORM_FAIL;
				}
				sanity++;
				continue;
			} else if (errno == EAGAIN) {
				break;
			} else if (errno == EBADF && retry == 0) {
				close(randfd);
				if ((randfd = open("/dev/random", O_RDONLY | O_NONBLOCK)) < 0) {
					break;
				}
				retry++;
				continue;
			} else {
				break;
			}
		}
		readBytes += rc;
		where += rc;
		size -= rc;
	}

	sanity = retry = 0;	
	while (size) {
		if ((rc = read(urandfd, where, size)) < 0 || sanity > MAX_RAND_READS) {
			if (errno == EINTR) {
				if (sanity > MAX_RAND_READS) {
					psTraceCore("psGetEntropy failed urandfd sanity\n");
					return PS_PLATFORM_FAIL;
				}
				sanity++;
				continue;
			} else if (errno == EBADF && retry == 0) {
				close(urandfd);
				if ((urandfd =
						open("/dev/urandom", O_RDONLY | O_NONBLOCK)) < 0) {
					psTraceCore("psGetEntropy failed urandom open\n");
					return PS_PLATFORM_FAIL;
				}
				retry++;
				continue;
			} else {
				psTraceIntCore("psGetEntropy fail errno %d\n", errno);
				return PS_PLATFORM_FAIL;
			}
		}
		readBytes += rc;
		where += rc;
		size -= rc;
	}*/
	return 0;
}
#endif
#endif
#if 0
/******************************************************************************/


/******************************************************************************/
/*
	RAW TRACE FUNCTIONS
*/
/******************************************************************************/

int osdepTraceOpen(void)
{
	return PS_SUCCESS;
}

void osdepTraceClose(void)
{
}
#endif
void _psTrace(char *msg)
{
	printf("%s", msg);
}

/* message should contain one %s, unless value is NULL */
void _psTraceStr(char *message, char *value)
{
	if (value) {
		printf(message, value);
	} else {
		printf("%s", message);
	}
}

/* message should contain one %d */
void _psTraceInt(char *message, int32 value)
{
	printf(message, value);
}

/* message should contain one %p */
void _psTracePtr(char *message, void *value)
{
	printf(message, value);
}

/******************************************************************************/

#if 0
/******************************************************************************/
/*
	POSIX - abort() on psError when HALT_ON_PS_ERROR enabled
*/
void osdepBreak(void)
{
	abort();
}
#endif /* HALT_ON_PS_ERROR */


#if 0
/******************************************************************************/
/*
	FILE ACCESS FUNCTION
*/
/******************************************************************************/
/*
	Memory info:
	Caller must free 'buf' parameter on success 
	Callers do not need to free buf on function failure
*/
int32 psGetFileBuf(psPool_t *pool, const char *fileName, unsigned char **buf,
				int32 *bufLen)
{
	FILE	*fp;
	struct	stat	fstat;
	size_t	tmp = 0;

	*bufLen = 0;
	*buf = NULL;

	if (fileName == NULL) {
		return PS_ARG_FAIL;
	}
	if ((stat(fileName, &fstat) != 0) || (fp = fopen(fileName, "r")) == NULL) {
		psTraceStrCore("Unable to open %s\n", (char*)fileName);
		return PS_PLATFORM_FAIL;
	}

	*buf = psMalloc(pool, (size_t)(fstat.st_size + 1));
	if (*buf == NULL) {
		return PS_MEM_FAIL;
	}
	memset(*buf, 0x0, (size_t)fstat.st_size + 1);

	while (((tmp = fread(*buf + *bufLen, sizeof(char), 512, fp)) > 0) &&
			(*bufLen < fstat.st_size)) { 
		*bufLen += (int32)tmp;
	}
	fclose(fp);
	return PS_SUCCESS;
}
#endif /* MATRIX_USE_FILE_SYSTEM */


