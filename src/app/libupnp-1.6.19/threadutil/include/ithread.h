#ifndef ITHREAD_H
#define ITHREAD_H

/*******************************************************************************
 *
 * Copyright (c) 2000-2003 Intel Corporation 
 * All rights reserved. 
 * Copyright (c) 2012 France Telecom All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met: 
 *
 * * Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer. 
 * * Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution. 
 * * Neither name of Intel Corporation nor the names of its contributors 
 * may be used to endorse or promote products derived from this software 
 * without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY 
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 ******************************************************************************/

/*!
 * \file
 */

#if !defined(WIN32)
//	#include <sys/param.h>
#endif

#include "UpnpGlobal.h" /* For UPNP_INLINE, EXPORT_SPEC */
#include "UpnpUniStd.h" /* for close() */
#include "wm_osal.h"

#ifdef __cplusplus
extern "C" {
#endif

//#include <pthread.h>

#if defined(BSD) && !defined(__GNU__)
	#define PTHREAD_MUTEX_RECURSIVE_NP 1
#endif


#if defined(PTHREAD_MUTEX_RECURSIVE) || defined(__DragonFly__)
	/* This system has SuS2-compliant mutex attributes.
	 * E.g. on Cygwin, where we don't have the old nonportable (NP) symbols
	 */
	#define ITHREAD_MUTEX_FAST_NP       PTHREAD_MUTEX_NORMAL
	#define ITHREAD_MUTEX_RECURSIVE_NP  PTHREAD_MUTEX_RECURSIVE
	#define ITHREAD_MUTEX_ERRORCHECK_NP PTHREAD_MUTEX_ERRORCHECK
#else /* PTHREAD_MUTEX_RECURSIVE */
	#define ITHREAD_MUTEX_FAST_NP       0
	#define ITHREAD_MUTEX_RECURSIVE_NP  PTHREAD_MUTEX_RECURSIVE_NP
	#define ITHREAD_MUTEX_ERRORCHECK_NP 2
#endif /* PTHREAD_MUTEX_RECURSIVE */


#define ITHREAD_PROCESS_PRIVATE 0
#define ITHREAD_PROCESS_SHARED  1


#define ITHREAD_CANCELED ((void *)(size_t) -1)


#define ITHREAD_STACK_MIN 0
#define ITHREAD_CREATE_DETACHED 1
#define ITHREAD_CREATE_JOINABLE 0

#if 0
struct timespec {
        long       tv_sec;
        long       tv_nsec;
};
#endif
typedef struct
{    
	void * p;                   /* Pointer to actual object */    
	unsigned int x;             /* Extra information - reuse count etc */
} ptw32_handle_t;
/***************************************************************************
 * Name: ithread_t
 *
 *  Description:
 *      Thread handle.
 *      typedef to pthread_t.
 *      Internal Use Only.
 ***************************************************************************/
typedef ptw32_handle_t ithread_t;

typedef struct
{ 
	size_t stackSize;
	int create_mode;
}pthread_attr_t;
/****************************************************************************
 * Name: ithread_attr_t
 *
 *  Description:
 *      Thread attribute.
 *      typedef to pthread_attr_t
 *      Internal Use Only
 ***************************************************************************/
typedef pthread_attr_t ithread_attr_t;	


/****************************************************************************
 * Name: start_routine
 *
 *  Description:
 *      Thread start routine 
 *      Internal Use Only.
 ***************************************************************************/
typedef void *(*start_routine)(void *arg);

  
/****************************************************************************
 * Name: ithread_cond_t
 *
 *  Description:
 *      condition variable.
 *      typedef to pthread_cond_t
 *      Internal Use Only.
 ***************************************************************************/
typedef tls_os_sem_t * ithread_cond_t;


/****************************************************************************
 * Name: ithread_mutexattr_t
 *
 *  Description:
 *      Mutex attribute.
 *      typedef to pthread_mutexattr_t
 *      Internal Use Only
 ***************************************************************************/
//typedef pthread_mutexattr_t ithread_mutexattr_t;	


/****************************************************************************
 * Name: ithread_mutex_t
 *
 *  Description:
 *      Mutex.
 *      typedef to pthread_mutex_t
 *      Internal Use Only.
 ***************************************************************************/
typedef tls_os_sem_t * ithread_mutex_t;


/****************************************************************************
 * Name: ithread_condattr_t
 *
 *  Description:
 *      Condition attribute.
 *      typedef to pthread_condattr_t
 *      NOT USED
 *      Internal Use Only
 ***************************************************************************/
//typedef pthread_condattr_t ithread_condattr_t;	


/****************************************************************************
 * Name: ithread_rwlockattr_t
 *
 *  Description:
 *      Mutex attribute.
 *      typedef to pthread_rwlockattr_t
 *      Internal Use Only
 ***************************************************************************/
#if UPNP_USE_RWLOCK
typedef pthread_rwlockattr_t ithread_rwlockattr_t;	
#endif /* UPNP_USE_RWLOCK */


/****************************************************************************
 * Name: ithread_rwlock_t
 *
 *  Description:
 *      Condition attribute.
 *      typedef to pthread_rwlock_t
 *      Internal Use Only
 ***************************************************************************/
#if UPNP_USE_RWLOCK
	typedef pthread_rwlock_t ithread_rwlock_t;
#else
	/* Read-write locks aren't available: use mutex instead. */
	typedef ithread_mutex_t ithread_rwlock_t;
#endif /* UPNP_USE_RWLOCK */


/****************************************************************************
 * Function: ithread_initialize_library
 *
 *  Description:
 *      Initializes the library. Does nothing in all implementations, except
 *      when statically linked for WIN32.
 *  Parameters:
 *      none.
 *  Returns:
 *      0 on success, Nonzero on failure.
 ***************************************************************************/
static UPNP_INLINE int ithread_initialize_library(void) {
	int ret = 0;

	return ret;
}


/****************************************************************************
 * Function: ithread_cleanup_library
 *
 *  Description:
 *      Clean up library resources. Does nothing in all implementations, except
 *      when statically linked for WIN32.
 *  Parameters:
 *      none.
 *  Returns:
 *      0 on success, Nonzero on failure.
 ***************************************************************************/
static UPNP_INLINE int ithread_cleanup_library(void) {
	int ret = 0;

	return ret;
}


/****************************************************************************
 * Function: ithread_initialize_thread
 *
 *  Description:
 *      Initializes the thread. Does nothing in all implementations, except
 *      when statically linked for WIN32.
 *  Parameters:
 *      none.
 *  Returns:
 *      0 on success, Nonzero on failure.
 ***************************************************************************/
static UPNP_INLINE int ithread_initialize_thread(void) {
	int ret = 0;

#if defined(WIN32) && defined(PTW32_STATIC_LIB)
	ret = !pthread_win32_thread_attach_np();
#endif

	return ret;
}


/****************************************************************************
 * Function: ithread_cleanup_thread
 *
 *  Description:
 *      Clean up thread resources. Does nothing in all implementations, except
 *      when statically linked for WIN32.
 *  Parameters:
 *      none.
 *  Returns:
 *      0 on success, Nonzero on failure.
 ***************************************************************************/
static UPNP_INLINE int ithread_cleanup_thread(void) {
	int ret = 0;

#if defined(WIN32) && defined(PTW32_STATIC_LIB)
	ret = !pthread_win32_thread_detach_np();
#endif

	return ret;
}


/****************************************************************************
 * Function: ithread_mutexattr_init
 *
 *  Description:
 *      Initializes a mutex attribute variable.
 *      Used to set the type of the mutex.
 *  Parameters:
 *      ithread_mutexattr_init * attr (must be valid non NULL pointer to 
 *                                     pthread_mutexattr_t)
 *  Returns:
 *      0 on success, Nonzero on failure.
 *      Always returns 0.
 *      See man page for pthread_mutexattr_init
 ***************************************************************************/
#define ithread_mutexattr_init pthread_mutexattr_init


/****************************************************************************
 * Function: ithread_mutexattr_destroy
 *
 *  Description:
 *      Releases any resources held by the mutex attribute.
 *      Currently there are no resources associated with the attribute
 *  Parameters:
 *      ithread_mutexattr_t * attr (must be valid non NULL pointer to 
 *                                  pthread_mutexattr_t)
 *  Returns:
 *      0 on success, Nonzero on failure.
 *      Always returns 0.
 *      See man page for pthread_mutexattr_destroy
 ***************************************************************************/
#define ithread_mutexattr_destroy pthread_mutexattr_destroy
  
  
/****************************************************************************
 * Function: ithread_mutexattr_setkind_np
 *
 *  Description:
 *      Sets the mutex type in the attribute.
 *      Valid types are: ITHREAD_MUTEX_FAST_NP 
 *                       ITHREAD_MUTEX_RECURSIVE_NP 
 *                       ITHREAD_MUTEX_ERRORCHECK_NP
 *
 *  Parameters:
 *      ithread_mutexattr_t * attr (must be valid non NULL pointer to 
 *                                   ithread_mutexattr_t)
 *      int kind (one of ITHREAD_MUTEX_FAST_NP or ITHREAD_MUTEX_RECURSIVE_NP
 *                or ITHREAD_MUTEX_ERRORCHECK_NP)
 *  Returns:
 *      0 on success. Nonzero on failure.
 *      Returns EINVAL if the kind is not supported.
 *      See man page for pthread_mutexattr_setkind_np
 *****************************************************************************/
#if defined(PTHREAD_MUTEX_RECURSIVE) || defined(__DragonFly__)
	#define ithread_mutexattr_setkind_np pthread_mutexattr_settype
#else
	#define ithread_mutexattr_setkind_np pthread_mutexattr_setkind_np
#endif /* UPNP_USE_RWLOCK */

/****************************************************************************
 * Function: ithread_mutexattr_getkind_np
 *
 *  Description:
 *      Gets the mutex type in the attribute.
 *      Valid types are: ITHREAD_MUTEX_FAST_NP 
 *                       ITHREAD_MUTEX_RECURSIVE_NP 
 *                       ITHREAD_MUTEX_ERRORCHECK_NP
 *
 *  Parameters:
 *      ithread_mutexattr_t * attr (must be valid non NULL pointer to 
 *                                   pthread_mutexattr_t)
 *      int *kind (one of ITHREAD_MUTEX_FAST_NP or ITHREAD_MUTEX_RECURSIVE_NP
 *                or ITHREAD_MUTEX_ERRORCHECK_NP)
 *  Returns:
 *      0 on success. Nonzero on failure.
 *      Always returns 0.
 *      See man page for pthread_mutexattr_getkind_np
 *****************************************************************************/
#if defined(PTHREAD_MUTEX_RECURSIVE) || defined(__DragonFly__)
	#define ithread_mutexattr_getkind_np pthread_mutexattr_gettype
#else
	#define ithread_mutexattr_getkind_np pthread_mutexattr_getkind_np
#endif /* UPNP_USE_RWLOCK */

  
/****************************************************************************
 * Function: ithread_mutex_init
 *
 *  Description:
 *      Initializes mutex.
 *      Must be called before use.
 *      
 *  Parameters:
 *      ithread_mutex_t * mutex (must be valid non NULL pointer to pthread_mutex_t)
 *      const ithread_mutexattr_t * mutex_attr 
 *  Returns:
 *      0 on success, Nonzero on failure.
 *      Always returns 0.
 *      See man page for pthread_mutex_init
 *****************************************************************************/
#define ithread_mutex_init(a, b) tls_os_sem_create(a, 1)


/****************************************************************************
 * Function: ithread_mutex_lock
 *
 *  Description:
 *      Locks mutex.
 *  Parameters:
 *      ithread_mutex_t * mutex (must be valid non NULL pointer to pthread_mutex_t)
 *      mutex must be initialized.
 *      
 *  Returns:
 *      0 on success, Nonzero on failure.
 *      Always returns 0.
 *      See man page for pthread_mutex_lock
 *****************************************************************************/
#define ithread_mutex_lock(a) tls_os_sem_acquire(*a, 0)
  

/****************************************************************************
 * Function: ithread_mutex_unlock
 *
 *  Description:
 *      Unlocks mutex.
 *
 *  Parameters:
 *      ithread_mutex_t * mutex (must be valid non NULL pointer to pthread_mutex_t)
 *      mutex must be initialized.
 *      
 *  Returns:
 *      0 on success, Nonzero on failure.
 *      Always returns 0.
 *      See man page for pthread_mutex_unlock
 *****************************************************************************/
#define ithread_mutex_unlock(a) tls_os_sem_release(*a)


/****************************************************************************
 * Function: ithread_mutex_destroy
 *
 *  Description:
 *      Releases any resources held by the mutex. 
 *		Mutex can no longer be used after this call.
 *		Mutex is only destroyed when there are no longer any threads waiting on it. 
 *		Mutex cannot be destroyed if it is locked.
 *  Parameters:
 *      ithread_mutex_t * mutex (must be valid non NULL pointer to pthread_mutex_t)
 *      mutex must be initialized.
 *  Returns:
 *      0 on success. Nonzero on failure.
 *      Always returns 0.
 *      See man page for pthread_mutex_destroy
 *****************************************************************************/
#define ithread_mutex_destroy(a) tls_os_sem_delete(*a)


/****************************************************************************
 * Function: ithread_rwlockattr_init
 *
 *  Description:
 *      Initializes a rwlock attribute variable to default values.
 *  Parameters:
 *      const ithread_rwlockattr_init *attr (must be valid non NULL pointer to 
 *                                           pthread_rwlockattr_t)
 *  Returns:
 *      0 on success, Nonzero on failure.
 *      Always returns 0.
 *      See man page for pthread_rwlockattr_init
 ***************************************************************************/
#if UPNP_USE_RWLOCK
	#define ithread_rwlockattr_init pthread_rwlockattr_init
#endif /* UPNP_USE_RWLOCK */


/****************************************************************************
 * Function: ithread_rwlockattr_destroy
 *
 *  Description:
 *      Releases any resources held by the rwlock attribute.
 *  Parameters:
 *      ithread_rwlockattr_t *attr (must be valid non NULL pointer to 
 *                                  pthread_rwlockattr_t)
 *  Returns:
 *      0 on success, Nonzero on failure.
 *      Always returns 0.
 *      See man page for pthread_rwlockattr_destroy
 ***************************************************************************/
#if UPNP_USE_RWLOCK
	#define ithread_rwlockattr_destroy pthread_rwlockattr_destroy
#endif /* UPNP_USE_RWLOCK */
  
  
/****************************************************************************
 * Function: ithread_rwlockatttr_setpshared
 *
 *  Description:
 *      Sets the rwlock type in the attribute.
 *      Valid types are: ITHREAD_PROCESS_PRIVATE 
 *                       ITHREAD_PROCESS_SHARED
 *
 *  Parameters:
 *      ithread_rwlockattr_t * attr (must be valid non NULL pointer to 
 *                                   ithread_rwlockattr_t)
 *      int kind (one of ITHREAD_PROCESS_PRIVATE or ITHREAD_PROCESS_SHARED)
 *
 *  Returns:
 *      0 on success. Nonzero on failure.
 *      Returns EINVAL if the kind is not supported.
 *      See man page for pthread_rwlockattr_setkind_np
 *****************************************************************************/
#if UPNP_USE_RWLOCK
	#define ithread_rwlockatttr_setpshared pthread_rwlockatttr_setpshared
#endif /* UPNP_USE_RWLOCK */


/****************************************************************************
 * Function: ithread_rwlockatttr_getpshared
 *
 *  Description:
 *      Gets the rwlock type in the attribute.
 *      Valid types are: ITHREAD_PROCESS_PRIVATE 
 *                       ITHREAD_PROCESS_SHARED 
 *
 *  Parameters:
 *      ithread_rwlockattr_t * attr (must be valid non NULL pointer to 
 *                                   pthread_rwlockattr_t)
 *      int *kind (one of ITHREAD_PROCESS_PRIVATE or ITHREAD_PROCESS_SHARED)
 *
 *  Returns:
 *      0 on success. Nonzero on failure.
 *      Always returns 0.
 *      See man page for pthread_rwlockatttr_getpshared
 *****************************************************************************/
#if UPNP_USE_RWLOCK
	#define ithread_rwlockatttr_getpshared pthread_rwlockatttr_getpshared
#endif /* UPNP_USE_RWLOCK */

  
/****************************************************************************
 * Function: ithread_rwlock_init
 *
 *  Description:
 *      Initializes rwlock.
 *      Must be called before use.
 *      
 *  Parameters:
 *      ithread_rwlock_t *rwlock (must be valid non NULL pointer to pthread_rwlock_t)
 *      const ithread_rwlockattr_t *rwlock_attr 
 *  Returns:
 *      0 on success, Nonzero on failure.
 *      Always returns 0.
 *      See man page for pthread_rwlock_init
 *****************************************************************************/
#if UPNP_USE_RWLOCK
	#define ithread_rwlock_init pthread_rwlock_init
#else
	/* Read-write locks aren't available: use mutex instead. */
	#define ithread_rwlock_init ithread_mutex_init
#endif

/****************************************************************************
 * Function: ithread_rwlock_rdlock
 *
 *  Description:
 *      Locks rwlock for reading.
 *  Parameters:
 *      ithread_rwlock_t *rwlock (must be valid non NULL pointer to pthread_rwlock_t)
 *      rwlock must be initialized.
 *      
 *  Returns:
 *      0 on success, Nonzero on failure.
 *      Always returns 0.
 *      See man page for pthread_rwlock_rdlock
 *****************************************************************************/
#if UPNP_USE_RWLOCK
	#define ithread_rwlock_rdlock pthread_rwlock_rdlock
#else
	/* Read-write locks aren't available: use mutex instead. */
	#define ithread_rwlock_rdlock ithread_mutex_lock
#endif /* UPNP_USE_RWLOCK */

/****************************************************************************
 * Function: ithread_rwlock_wrlock
 *
 *  Description:
 *      Locks rwlock for writting.
 *  Parameters:
 *      ithread_rwlock_t *rwlock (must be valid non NULL pointer to pthread_rwlock_t)
 *      rwlock must be initialized.
 *      
 *  Returns:
 *      0 on success, Nonzero on failure.
 *      Always returns 0.
 *      See man page for pthread_rwlock_wrlock
 *****************************************************************************/
#if UPNP_USE_RWLOCK
	#define ithread_rwlock_wrlock pthread_rwlock_wrlock
#else
	/* Read-write locks aren't available: use mutex instead. */
	#define ithread_rwlock_wrlock ithread_mutex_lock
#endif /* UPNP_USE_RWLOCK */


/****************************************************************************
 * Function: ithread_rwlock_unlock
 *
 *  Description:
 *      Unlocks rwlock.
 *
 *  Parameters:
 *      ithread_rwlock_t *rwlock (must be valid non NULL pointer to pthread_rwlock_t)
 *      rwlock must be initialized.
 *      
 *  Returns:
 *      0 on success, Nonzero on failure.
 *      Always returns 0.
 *      See man page for pthread_rwlock_unlock
 *****************************************************************************/
#if UPNP_USE_RWLOCK
	#define ithread_rwlock_unlock pthread_rwlock_unlock
#else
	/* Read-write locks aren't available: use mutex instead. */
	#define ithread_rwlock_unlock ithread_mutex_unlock
#endif /* UPNP_USE_RWLOCK */


/****************************************************************************
 * Function: ithread_rwlock_destroy
 *
 *  Description:
 *      Releases any resources held by the rwlock. 
 *		rwlock can no longer be used after this call.
 *		rwlock is only destroyed when there are no longer any threads waiting on it. 
 *		rwlock cannot be destroyed if it is locked.
 *  Parameters:
 *      ithread_rwlock_t *rwlock (must be valid non NULL pointer to pthread_rwlock_t)
 *      rwlock must be initialized.
 *  Returns:
 *      0 on success. Nonzero on failure.
 *      Always returns 0.
 *      See man page for pthread_rwlock_destroy
 *****************************************************************************/
#if UPNP_USE_RWLOCK
	#define ithread_rwlock_destroy pthread_rwlock_destroy
#else
	/* Read-write locks aren't available: use mutex instead. */
	#define ithread_rwlock_destroy ithread_mutex_destroy
#endif /* UPNP_USE_RWLOCK */

#if 0
/****************************************************************************
 * Function: ithread_cond_init
 *
 *  Description:
 *      Initializes condition variable.
 *      Must be called before use.
 *  Parameters:
 *      ithread_cond_t *cond (must be valid non NULL pointer to pthread_cond_t)
 *      const ithread_condattr_t *cond_attr (ignored)
 *  Returns:
 *      0 on success, Nonzero on failure.
 *      See man page for pthread_cond_init
 *****************************************************************************/
#define ithread_cond_init(a, b) tls_os_sem_create(a, 0)


/****************************************************************************
 * Function: ithread_cond_signal
 *
 *  Description:
 *      Wakes up exactly one thread waiting on condition.
 *      Associated mutex MUST be locked by thread before entering this call.
 *  Parameters:
 *      ithread_cond_t *cond (must be valid non NULL pointer to 
 *      ithread_cond_t)
 *      cond must be initialized
 *  Returns:
 *      0 on success, Nonzero on failure.
 *      See man page for pthread_cond_signal
 *****************************************************************************/
#define ithread_cond_signal(a) tls_os_sem_release(*a)


/****************************************************************************
 * Function: ithread_cond_broadcast
 *
 *  Description:
 *      Wakes up all threads waiting on condition.
 *      Associated mutex MUST be locked by thread before entering this call.
 *  Parameters:
 *      ithread_cond_t *cond (must be valid non NULL pointer to 
 *      ithread_cond_t)
 *      cond must be initialized
 *  Returns:
 *      0 on success, Nonzero on failure.
 *      See man page for pthread_cond_broadcast
 *****************************************************************************/
static UPNP_INLINE int ithread_cond_broadcast( ithread_cond_t *cond)
{
	u8 err;
	OSSemPendAbort(*cond, OS_PEND_OPT_BROADCAST, &err);
	return 0;
}
  

  /****************************************************************************
   * Function: pthread_cond_timedwait
   *
   *	Description:      
   *		Atomically releases the associated mutex and waits on the
   *	condition.
   *		If the condition is not signaled in the specified time than the
   *	call times out and returns.
   *		Associated mutex MUST be locked by thread before entering this call.
   *		Mutex is reacquired when call returns.
   *  Parameters:
   *      ithread_cond_t *cond (must be valid non NULL pointer to ithread_cond_t)
   *      	cond must be initialized
   *      ithread_mutex_t *mutex (must be valid non NULL pointer to ithread_mutex_t)
   *      	Mutex must be locked.
   *      const struct timespec *abstime (absolute time, measured from Jan 1, 1970)
   *  Returns:
   *      0 on success. ETIMEDOUT on timeout. Nonzero on failure.
   *      See man page for pthread_cond_timedwait
   ***************************************************************************/
 
static UPNP_INLINE int ithread_cond_timedwait(ithread_cond_t * cond_t, ithread_mutex_t * metex_t ,struct timespec * timeout)
{
	u32 msectimeout;
	ithread_mutex_unlock(metex_t);
	 if (timeout == NULL) {
        /* Wait forever */
        msectimeout = 0;
      } else {
        msectimeout =  ((timeout->tv_sec * 1000) + ((timeout->tv_nsec + 500)/1000)) * HZ / 1000;
        if (msectimeout == 0) {
          /* Wait 1ms at least (0 means wait forever) */
          msectimeout = 1;
        }
      }
	tls_os_sem_acquire(*cond_t, msectimeout);
	ithread_mutex_lock(metex_t);
	return 0;
}

/****************************************************************************
 * Function: ithread_cond_wait
 *
 *  Description:
 *      Atomically releases mutex and waits on condition.
 *      Associated mutex MUST be locked by thread before entering this call.
 *      Mutex is reacquired when call returns.
 *  Parameters:
 *      ithread_cond_t *cond (must be valid non NULL pointer to 
 *      ithread_cond_t)
 *      cond must be initialized
 *      ithread_mutex_t *mutex (must be valid non NULL pointer to 
 *      ithread_mutex_t)
 *      Mutex must be locked.
 *  Returns:
 *      0 on success, Nonzero on failure.
 *      See man page for pthread_cond_wait
 *****************************************************************************/
#define ithread_cond_wait(a, b) ithread_cond_timedwait(a, b, NULL)


  /****************************************************************************
   * Function: ithread_cond_destroy
   *
   *  Description:
   *      Releases any resources held by the condition variable. 
   *		Condition variable can no longer be used after this call.	
   *  Parameters:
   *      ithread_cond_t *cond (must be valid non NULL pointer to 
   *      ithread_cond_t)
   *      cond must be initialized.
   *  Returns:
   *      0 on success. Nonzero on failure.
   *      See man page for pthread_cond_destroy
   ***************************************************************************/
#define ithread_cond_destroy(a) tls_os_sem_delete(*a)


  /****************************************************************************
   * Function: ithread_attr_init
   *
   *  Description:
   *      Initialises thread attribute object.
   *  Parameters:
   *      ithread_attr_t *attr (must be valid non NULL pointer to
   *      ithread_attr_t)
   *  Returns:
   *      0 on success. Nonzero on failure.
   *      See man page for pthread_attr_init
   ***************************************************************************/
#define ithread_attr_init(a)

  /****************************************************************************
   * Function: ithread_attr_destroy
   *
   *  Description:
   *      Destroys thread attribute object.
   *  Parameters:
   *      ithread_attr_t *attr (must be valid non NULL pointer to
   *      ithread_attr_t)
   *  Returns:
   *      0 on success. Nonzero on failure.
   *      See man page for pthread_attr_destroy
   ***************************************************************************/
#define ithread_attr_destroy(a)

  /****************************************************************************
   * Function: ithread_attr_setstacksize
   *
   *  Description:
   *      Sets stack size of a thread attribute object.
   *  Parameters:
   *      ithread_attr_t *attr (must be valid non NULL pointer to
   *      ithread_attr_t)
   *      size_t stacksize (value of stacksize must be greater than
   *      ITHREAD_STACK_MIN and lower than system-imposed limits
   *  Returns:
   *      0 on success. Nonzero on failure.
   *      See man page for pthread_attr_setstacksize
   ***************************************************************************/
static UPNP_INLINE int ithread_attr_setstacksize(ithread_attr_t *attr, size_t stacksize)
{
	attr->stackSize = stacksize;
	return 0;
}

  /****************************************************************************
   * Function: ithread_attr_setdetachstate
   *
   *  Description:
   *      Sets detach state of a thread attribute object.
   *  Parameters:
   *      ithread_attr_t *attr (must be valid non NULL pointer to
   *      ithread_attr_t)
   *      int detachstate (value of detachstate must be ITHREAD_CREATE_DETACHED
   *      or ITHREAD_CREATE_JOINABLE)
   *  Returns:
   *      0 on success. Nonzero on failure.
   *      See man page for pthread_attr_setdetachstate
   ***************************************************************************/
static UPNP_INLINE int ithread_attr_setdetachstate(ithread_attr_t *attr, int detachstate)
{
	attr->create_mode = detachstate;
	return 0;
}

#define EAGAIN          11

#define UPNP_STK_SIZE	     700
#define UPNP_TASK_MAX   6
#define UPNP_TASK_START_PRIO  TLS_UPNP_TASK_PRIO

static OS_STK         upnp_task_stk[UPNP_TASK_MAX*UPNP_STK_SIZE];
static UCHAR            upnp_task_priopity_stack[UPNP_TASK_MAX];

  /****************************************************************************
   * Function: ithread_create
   *
   *  Description:
   *		Creates a thread with the given start routine
   *      and argument.
   *  Parameters:
   *      ithread_t * thread (must be valid non NULL pointer to pthread_t)
   *      ithread_attr_t *attr
   *      void * (start_routine) (void *arg) (start routine)
   *      void * arg - argument.
   *  Returns:
   *      0 on success. Nonzero on failure.
   *	    Returns EAGAIN if a new thread can not be created.
   *      Returns EINVAL if there is a problem with the arguments.
   *      See man page fore pthread_create
   ***************************************************************************/
static UPNP_INLINE int ithread_create(ithread_t * thread, ithread_attr_t *attr, void (* start_routine)(void *arg) , void * arg)
{
	UCHAR        ubPrio = UPNP_TASK_START_PRIO;
    int         i; 

    /* Search for a suitable priority */     
        while (ubPrio < (UPNP_TASK_START_PRIO+UPNP_TASK_MAX)) { 
            for (i=0; i<UPNP_TASK_MAX; ++i)
                if (upnp_task_priopity_stack[i] == ubPrio) {
                    ++ubPrio;
                    break;
                }
            if (i == UPNP_TASK_MAX)
                break;
        }
        if (ubPrio < (UPNP_TASK_START_PRIO+UPNP_TASK_MAX))
            for (i=0; i<UPNP_TASK_MAX; ++i)
                if (upnp_task_priopity_stack[i]==0) {
                    upnp_task_priopity_stack[i] = ubPrio;
                    break;
                }
        if (ubPrio >= (UPNP_TASK_START_PRIO+UPNP_TASK_MAX) || i == UPNP_TASK_MAX) {
            printf( "sys_thread_new: there is no free priority");
            return (EAGAIN);
        }
    if (attr->stackSize > UPNP_STK_SIZE || !attr->stackSize)   
        attr->stackSize = UPNP_STK_SIZE;

    thread->x = ubPrio;
    int tsk_prio = ubPrio-UPNP_TASK_START_PRIO;
    OS_STK * task_stk = &upnp_task_stk[tsk_prio*UPNP_STK_SIZE];
    tls_os_task_create(NULL, NULL,
                       start_routine,
                       (void *)arg,
                       (void *)task_stk,
                       attr->stackSize * sizeof(u32),
                       ubPrio,
                       0);
	return 0;
}

  /****************************************************************************
   * Function: ithread_cancel
   *
   *  Description:
   *		Cancels a thread.
   *  Parameters:
   *      ithread_t * thread (must be valid non NULL pointer to ithread_t)
   *  Returns:
   *      0 on success. Nonzero on failure.
   *      See man page for pthread_cancel
   ***************************************************************************/
#define ithread_cancel pthread_cancel
  

  /****************************************************************************
   * Function: ithread_exit
   *
   *  Description:
   *		Returns a return code from a thread.
   *      Implicitly called when the start routine returns.
   *  Parameters:
   *      void  * return_code return code to return
   *      See man page for pthread_exit
   ***************************************************************************/
#define ithread_exit pthread_exit


/****************************************************************************
   * Function: ithread_get_current_thread_id
   *
   *  Description:
   *		Returns the handle of the currently running thread.
   *  Returns:
   *		The handle of the currently running thread.
   *              See man page for pthread_self
   ***************************************************************************/
#define ithread_get_current_thread_id() 0


  /****************************************************************************
   * Function: ithread_self
   *
   *  Description:
   *		Returns the handle of the currently running thread.
   *  Returns:
   *		The handle of the currently running thread.
   *              See man page for pthread_self
   ***************************************************************************/
#define ithread_self() 0


  /****************************************************************************
   * Function: ithread_detach
   *
   *  Description:
   *		Makes a thread's resources reclaimed immediately 
   *            after it finishes
   *            execution.  
   *  Returns:
   *		0 on success, Nonzero on failure.
   *      See man page for pthread_detach
   ***************************************************************************/
#define ithread_detach(a) 0


  /****************************************************************************
   * Function: ithread_join
   *
   *  Description:
   *		Suspends the currently running thread until the 
   * specified thread
   *      has finished. 
   *      Returns the return code of the thread, or ITHREAD_CANCELED 
   *      if the thread has been canceled.
   *  Parameters:
   *      ithread_t *thread (valid non null thread identifier)
   *      void ** return (space for return code) 
   *  Returns:
   *		0 on success, Nonzero on failure.
   *     See man page for pthread_join
   ***************************************************************************/
#define ithread_join pthread_join
#endif
  

/****************************************************************************
 * Function: isleep
 *
 *  Description:
 *		Suspends the currently running thread for the specified number 
 *      of seconds
 *      Always returns 0.
 *  Parameters:
 *      unsigned int seconds - number of seconds to sleep.
 *  Returns:
 *		0 on success, Nonzero on failure.
 *              See man page for sleep (man 3 sleep)
 *****************************************************************************/
#ifdef WIN32
	#define isleep(x) Sleep((x)*1000)
#else
	#define isleep tls_os_time_delay
#endif


/****************************************************************************
 * Function: isleep
 *
 *  Description:
 *		Suspends the currently running thread for the specified number 
 *      of milliseconds
 *      Always returns 0.
 *  Parameters:
 *      unsigned int milliseconds - number of milliseconds to sleep.
 *  Returns:
 *		0 on success, Nonzero on failure.
 *              See man page for sleep (man 3 sleep)
 *****************************************************************************/
#ifdef WIN32
	#define imillisleep Sleep
#else
	#define imillisleep(x)  usleep(1000*x)
#endif


#if !defined(PTHREAD_MUTEX_RECURSIVE) && !defined(__DragonFly__) && !defined(UPNP_USE_MSVCPP)
/* !defined(UPNP_USE_MSVCPP) should probably also have pthreads version check - but it's not clear if that is possible */
/* NK: Added for satisfying the gcc compiler */
//EXPORT_SPEC int pthread_mutexattr_setkind_np(pthread_mutexattr_t *attr, int kind);
#endif


#ifdef __cplusplus
}
#endif


#endif /* ITHREAD_H */

