#ifndef UPNPINET_H
#define UPNPINET_H
#include "wm_type_def.h"
#include "wm_sockets.h"
#include "UpnpUniStd.h" /* for close() */
/*!
 * \addtogroup Sock
 * 
 * @{
 * 
 * \file
 *
 * \brief Provides a platform independent way to include TCP/IP types and functions.
 */


#ifdef WIN32
	#include <stdarg.h>
	#ifndef UPNP_USE_MSVCPP
		/* Removed: not required (and cause compilation issues) */
		#include <winbase.h>
		#include <windef.h>
	#endif
	#include <winsock2.h>
	#include <iphlpapi.h>
	#include <ws2tcpip.h>

	#define UpnpCloseSocket closesocket

	#if(_WIN32_WINNT < 0x0600)
		typedef short sa_family_t;
	#else
		typedef ADDRESS_FAMILY sa_family_t;
	#endif

#else /* WIN32 */
//	#include <sys/param.h>
	#if defined(__sun)
		#include <fcntl.h>
		#include <sys/sockio.h>
	#elif (defined(BSD) && BSD >= 199306) || defined (__FreeBSD_kernel__)
		#include <ifaddrs.h>
		/* Do not move or remove the include below for "sys/socket"!
		 * Will break FreeBSD builds. */
		#include <sys/socket.h>
	#endif
//	#include <arpa/inet.h>  /* for inet_pton() */
//	#include <net/if.h>
//	#include <netinet/in.h>
	#include "inet_pton.h"
	/*! This typedef makes the code slightly more WIN32 tolerant.
	 * On WIN32 systems, SOCKET is unsigned and is not a file
	 * descriptor. */
	typedef int SOCKET;

	/*! INVALID_SOCKET is unsigned on win32. */
	#define INVALID_SOCKET (-1)

	/*! select() returns SOCKET_ERROR on win32. */
	#define SOCKET_ERROR (-1)

	/*! Alias to close() to make code more WIN32 tolerant. */
	#define UpnpCloseSocket closesocket

	typedef short sa_family_t;
#endif /* WIN32 */

/* @} Sock */


#define INET_ADDRSTRLEN 22
#define INET6_ADDRSTRLEN 65

//typedef long long int64;
typedef unsigned char UCHAR;
typedef unsigned short USHORT;
typedef unsigned int UINT;
typedef USHORT ADDRESS_FAMILY;
typedef struct sockaddr_storage {
    //u16 ss_family;      // address family
    UCHAR ss_len;
    UCHAR ss_family;
    char __ss_pad1[6];  // 6 byte pad, this is to make
                                   //   implementation specific pad up to
                                   //   alignment field that follows explicit
                                   //   in the data structure
    int64  __ss_align;            // Field to force desired structure
    char __ss_pad2[112];  // 112 byte pad to achieve desired size;
                                   //   _SS_MAXSIZE value minus size of
                                   //   ss_family, __ss_pad1, and
                                   //   __ss_align fields is 112
} SOCKADDR_STORAGE_LH, *PSOCKADDR_STORAGE_LH;
//
// IPv6 Internet address (RFC 2553)
// This is an 'on-wire' format structure.
//
typedef struct in6_addr {
    union {
        UCHAR       s6_bytes[16];
        USHORT      Word[8];
    } u;
} IN6_ADDR, *PIN6_ADDR;

typedef struct {
    union {
        struct {
            ULONG Zone : 28;
            ULONG Level : 4;
        };
        ULONG Value;
    };
} SCOPE_ID, *PSCOPE_ID;
//
// NB: The LH version of sockaddr_in6 has the struct tag sockaddr_in6 rather
// than sockaddr_in6_lh.  This is to make sure that standard sockets apps
// that conform to RFC 2553 (Basic Socket Interface Extensions for IPv6).
//
typedef struct sockaddr_in6 {
    ADDRESS_FAMILY sin6_family; // AF_INET6.
    USHORT sin6_port;           // Transport level port number.
    ULONG  sin6_flowinfo;       // IPv6 flow information.
    IN6_ADDR sin6_addr;         // IPv6 address.
    union {
        ULONG sin6_scope_id;     // Set of interfaces for a scope.
        SCOPE_ID sin6_scope_struct; 
    };
} SOCKADDR_IN6_LH, *PSOCKADDR_IN6_LH;

static inline BOOLEAN
IN6_IS_ADDR_LINKLOCAL(const IN6_ADDR *a)
{
    return (BOOLEAN)((a->u.s6_bytes[0] == 0xfe) && 
                     ((a->u.s6_bytes[1] & 0xc0) == 0x80));
}

#endif /* UPNPINET_H */
