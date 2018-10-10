 
#include "lwip/arch.h"
#include "HTTPClientWrapper.h"
#include "random.h"
#include "wm_osal.h"
#include "wm_sockets.h"
#include "lwip/sockets.h"
#include "wm_debug.h"
#if TLS_CONFIG_HTTP_CLIENT_SECURE
#if TLS_CONFIG_USE_POLARSSL
#include "polarssl/camellia.h"
#include "polarssl/certs.h"
#include "polarssl/x509.h"
#include "polarssl/error.h"
#else
#include "matrixsslApi.h"
#endif
#include "HTTPClient.h"
#endif
#if TLS_CONFIG_HTTP_CLIENT

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Section      : Stdc: HTTPWrapperIsAscii
// Last updated : 15/05/2005
// Author Name	: Eitan Michaelson
// Notes	    : Same as stdc: isascii
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int HTTPWrapperIsAscii(int c)
{
    return (!(c & ~0177));
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Section      : Stdc: HTTPWrapperToUpper
// Last updated : 15/05/2005
// Author Name	: Eitan Michaelson
// Notes	    : Convert character to uppercase.
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int HTTPWrapperToUpper(int c)
{
    // -32
    if(HTTPWrapperIsAscii(c) > 0)
    {
        if(c >= 97 && c <= 122)
        {
            return (c - 32);
        }
    }

    return c;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Section      : Stdc: HTTPWrapperToLower
// Last updated : 13/06/2006
// Author Name	 : Eitan Michaelson
// Notes	       : Convert character to lowercase.
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int HTTPWrapperToLower(int c)
{
    // +32
    if(HTTPWrapperIsAscii(c) > 0)
    {
        if(c >= 65 && c <= 90)
        {
            return (c + 32);
        }
    }

    return c;
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Section      : Stdc: isalpha
// Last updated : 15/05/2005
// Author Name	: Eitan Michaelson
// Notes	    : returns nonzero if c is a particular representation of an alphabetic character
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int HTTPWrapperIsAlpha(int c)
{

    if(HTTPWrapperIsAscii(c) > 0)
    {
        if( (c >= 97 && c <= 122) || (c >= 65 && c <= 90)) 
        {
            return c;
        }
    }
    return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Section      : Stdc: isalnum
// Last updated : 15/05/2005
// Author Name	: Eitan Michaelson
// Notes	    : returns nonzero if c is a particular representation of an alphanumeric character
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int HTTPWrapperIsAlNum(int c)
{
    if(HTTPWrapperIsAscii(c) > 0)
    {

        if(HTTPWrapperIsAlpha(c) > 0)
        {
            return c;
        }

        if( c >= 48 && c <= 57)  
        {
            return c;
        } 

    }
    return 0;
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Section      : HTTPWrapper_itoa
// Last updated : 15/05/2005
// Author Name	: Eitan Michaelson
// Notes	    : same as stdc itoa() // hmm.. allmost the same
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

char* HTTPWrapperItoa(char *s,int a)
{

    unsigned int b;
    if(a > 2147483647)
    {
        return 0; // overflow
    }

    if (a < 0) b = -a, *s++ = '-';
    else b = a;
    for(;a;a=a/10) s++;
    for(*s='\0';b;b=b/10) *--s=b%10+'0';
    return s;

}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Section      : HTTPWrapper_ShutDown
// Last updated : 15/05/2005
// Author Name	: Eitan Michaelson
// Notes	    : Handles parameter changes in the socket shutdown() function in AMT
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


int HTTPWrapperShutDown (int s,int how) 
{
    return shutdown(s,how);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Section      : HTTPWrapper_GetSocketError
// Last updated : 15/05/2005
// Author Name	: Eitan Michaelson
// Notes	    : WSAGetLastError Wrapper (Win32 Specific)
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int HTTPWrapperGetSocketError (int s)
{
#if TLS_CONFIG_LWIP_VER2_0_3
	return errno;
#else
	struct lwip_sock * sock;
	sock = get_socket(s);
	if(sock == NULL)
		return SOCKET_ERROR;
	TLS_DBGPRT_INFO("sock->err=%d\n", sock->err);
	return sock->err;
#endif
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Section      : HTTPWrapper_GetRandomeNumber
// Last updated : 15/05/2005
// Author Name	: Eitan Michaelson
// Notes	    : GetRandom number for Win32 & AMT
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void HTTPWrapperInitRandomeNumber()
{
    srand((unsigned int)tls_os_get_time());
}

int HTTPWrapperGetRandomeNumber()
{
    int num;
    num = (int)(((double) rand()/ ((double)RAND_MAX+1)) * 16);
    return num;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Section      : HTTPWrapper_GetRTC
// Last updated : 15/05/2005
// Author Name	: Eitan Michaelson
// Notes	    : Get uptime under Win32 & AMT
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

long HTTPWrapperGetUpTime()
{

    long lTime = 0;

    lTime = tls_os_get_time();
    return lTime;

}

#endif //TLS_CONFIG_HTTP_CLIENT

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Section      : HTTPWrapper_GetHostByName
// Last updated : 15/05/2005
// Author Name	: Eitan Michaelson
// Notes	    : gethostbyname for Win32 (supports the AMT edition of the function)
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

unsigned long HTTPWrapperGetHostByName(char *name,unsigned long *address)
{
    HTTP_HOSTNET     *HostEntry;
    int     iPos = 0, iLen = 0,iNumPos = 0,iDots =0;
    long    iIPElement;
    char    c = 0;
    char    Num[4];
    int     iHostType = 0; // 0 : numeric IP

    // Check if the name is an IP or host 
    iLen = strlen(name);
    for(iPos = 0; iPos <= iLen;iPos++)
    {
        c = name[iPos];
        if((c >= 48 && c <= 57)  || (c == '.') )
        {   
            // c is numeric or dot
            if(c != '.')
            {
                // c is numeric
                if(iNumPos > 3)
                {
                    iHostType++;
                    break;
                }
                Num[iNumPos] = c;
                Num[iNumPos + 1] = 0;
                iNumPos ++;
            }
            else
            {
                iNumPos = 0;
                iDots++;
                iIPElement = atol(Num);
                if(iIPElement > 256 || iDots > 3)
                {
                    return 0; // error invalid IP
                }
            }
        }
        else
        {
            break; // this is an alpha numeric address type
        }
    }

    if(c == 0 && iHostType == 0 && iDots == 3)
    {
        iIPElement = atol(Num);
        if(iIPElement > 256)
        {
            return 0; // error invalid IP
        }
    }
    else
    {
        iHostType++;
    }   

    if(iHostType > 0)
    {

        HostEntry = gethostbyname(name); 
        if(HostEntry)
        {
            *(address) = *((u_long*)HostEntry->h_addr_list[0]);

            //*(address) = (unsigned long)HostEntry->h_addr_list[0];
            return 1; // Error 
        }
        else
        {
            return 0; // OK
        }
    }

    else // numeric address - no need for DNS resolve
    {
        *(address) = inet_addr(name);
        return 1;

    }
}


#if TLS_CONFIG_HTTP_CLIENT_SECURE
#define ALLOW_ANON_CONNECTIONS	1
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int HTTPWrapperSSLNegotiate(HTTP_SESSION_HANDLE pSession,int s,const struct sockaddr *name,int namelen,char *hostname)
{
    return 0;
}

#if TLS_CONFIG_USE_POLARSSL

#if 0
#define PSLL_PRT    printf
#else
#define PSLL_PRT(x, ...)
#endif

/************************ memory manage ************************/


void *platform_malloc(uint32_t size)
{
	return tls_mem_alloc(size);
}


void platform_free(void *ptr)
{
	tls_mem_free(ptr);
}



/************************ mutex manage ************************/

void *platform_mutex_init(void)
{
	tls_os_sem_t *mutex = NULL;

	tls_os_sem_create(&mutex,1);

	return mutex;
}


void platform_mutex_lock(void *mutex)
{
	tls_os_sem_acquire(mutex,0);
}


void platform_mutex_unlock(void *mutex)
{
	tls_os_sem_release(mutex);
}


void platform_mutex_destroy(void *mutex)
{
    if (!mutex)
        return;
	tls_os_sem_delete(mutex);
}

static int ctr_drbg_random( void *p_rng, unsigned char *output, size_t output_len )
{
    return random_get_bytes( output, output_len );
}

static void my_debug( void *ctx, int level, const char *str )
{
    PSLL_PRT("%s", str);
}

static int net_is_blocking( void )
{
    switch( errno )
    {
#if defined EAGAIN
        case EAGAIN:
#endif
#if defined EWOULDBLOCK && EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
            return( 1 );
    }
    return( 0 );
}

static int net_recv( void *ctx, unsigned char *buf, size_t len )
{
    int ret;
    int skt = (int)(long) ctx;
#if 0
    fd_set read_set;
    struct timeval tv;

    FD_ZERO(&read_set);
    FD_SET(skt, &read_set);
    tv.tv_sec  = 5;
    tv.tv_usec = 0;

    ret = select(skt + 1, &read_set, NULL, NULL, &tv);
    if (ret > 0)
    {
        if (FD_ISSET(skt, &read_set))
        {
#endif
            ret = recv( skt, buf, len, 0);

            if( ret < 0 )
            {
                if( net_is_blocking() != 0 )
                    return( POLARSSL_ERR_NET_WANT_READ );

                if( errno == EPIPE || errno == ECONNRESET )
                    return( POLARSSL_ERR_NET_CONN_RESET );

                if( errno == EINTR )
                    return( POLARSSL_ERR_NET_WANT_READ );

                return( POLARSSL_ERR_NET_RECV_FAILED );
            }

#if 0
            FD_CLR(skt, &read_set);
        }
        else
        {
            PSLL_PRT("\r\n\r\nssl select no\r\n\r\n");
        }
    }
    else if (0 == ret)
    {
        PSLL_PRT("\r\n\r\nssl recv timeout\r\n\r\n");
    }
    else
    {
        PSLL_PRT("\r\n\r\nssl select error\r\n\r\n");
    }
#endif

    return ret;
}

/*
 * Write at most 'len' characters
 */
static int net_send( void *ctx, const unsigned char *buf, size_t len )
{
    int ret = send( (long) ctx, buf, len, 0);

    if( ret < 0 )
    {
        if( net_is_blocking() != 0 )
            return( POLARSSL_ERR_NET_WANT_WRITE );

        if( errno == EPIPE || errno == ECONNRESET )
            return( POLARSSL_ERR_NET_CONN_RESET );

        if( errno == EINTR )
            return( POLARSSL_ERR_NET_WANT_WRITE );

        return( POLARSSL_ERR_NET_SEND_FAILED );
    }

    return( ret );
}

void *platform_ssl_connect(void *tcp_fd,
        const char *server_cert,
        int server_cert_len)
{
    int ret;
    ssl_context *ssl;
    ssl_session *ssn;
    x509_cert *cacert = NULL;

    ssl = platform_malloc(sizeof(ssl_context));
    if (!ssl)
        return NULL;

    ssn = platform_malloc(sizeof(ssl_session));
    if (!ssn)
    {
        platform_free(ssl);
        return NULL;
    }

    if (server_cert)
    {
        cacert = platform_malloc(sizeof(x509_cert));
        if (!cacert)
        {
            platform_free(ssl);
            platform_free(ssn);
            return NULL;
        }

        memset(cacert, 0, sizeof(x509_cert));
        ret = x509parse_crt(cacert, (unsigned char *) server_cert, server_cert_len);
        if( ret != 0 )
        {
            PSLL_PRT( " failed\n  !  x509parse_crt returned %d\n\n", ret );
            platform_free(ssl);
            platform_free(ssn);
            if(cacert)
    			platform_free(cacert);
            return NULL;
        }
    }

    memset(ssl, 0, sizeof(ssl_context));
    if( ( ret = ssl_init( ssl ) ) != 0 )
    {
        PSLL_PRT( " failed\n  ! ssl_init returned %d\n\n", ret );
        if(cacert)
    		x509_free( cacert );
        platform_free(ssl);
        platform_free(ssn);
        if(cacert)
    		platform_free(cacert);
        return NULL;
    }

    ssl_set_endpoint( ssl, SSL_IS_CLIENT );
    if (server_cert)
        ssl_set_authmode( ssl, SSL_VERIFY_REQUIRED );
    else
        ssl_set_authmode( ssl, SSL_VERIFY_NONE );

    ssl_set_rng( ssl, ctr_drbg_random, NULL );
    ssl_set_dbg( ssl, my_debug, NULL);
    ssl_set_bio( ssl, net_recv, tcp_fd, net_send, tcp_fd );

    ssl_set_ciphersuites( ssl, ssl_default_ciphersuites );

    memset(ssn, 0, sizeof(ssl_session));
    ssl_set_session( ssl, 1, 600, ssn );

    if (server_cert)
        ssl_set_ca_chain( ssl, cacert, NULL, NULL);

     while( ( ret = ssl_handshake( ssl ) ) != 0 )
    {
        if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            PSLL_PRT( " failed\n  ! ssl_handshake returned %d\n\n", ret );
            goto fail;
        }
		PSLL_PRT("INFO: ssl_handshake returned %d\n\n", ret);
    }

    if (server_cert)
    {
        if( ( ret = ssl_get_verify_result( ssl ) ) != 0 )
        {
            PSLL_PRT( "Verifying peer X.509 certificate failed\n" );

            if( ( ret & BADCERT_EXPIRED ) != 0 )
                PSLL_PRT( "  ! server certificate has expired\n" );

            if( ( ret & BADCERT_REVOKED ) != 0 )
                PSLL_PRT( "  ! server certificate has been revoked\n" );

            if( ( ret & BADCERT_CN_MISMATCH ) != 0 )
                PSLL_PRT( "  ! CN mismatch \n");

            if( ( ret & BADCERT_NOT_TRUSTED ) != 0 )
                PSLL_PRT( "  ! self-signed or not signed by a trusted CA\n" );

            PSLL_PRT( "\n" );

            ssl_close_notify( ssl );
            goto fail;
        }
        else
        {
            PSLL_PRT( "Verifying X.509 certificate pass.\n" );
        }
    }

    //ssl->read_lock = platform_mutex_init();
    ssl->write_lock = platform_mutex_init();

    //printf("ssl read/write lock 0x%p/0x%p\n", ssl->read_lock, ssl->write_lock);
    PSLL_PRT("ssl rdwr lock 0x%p\n", ssl->write_lock);

    return ssl;

fail:
	if(cacert)
    	x509_free( cacert );
    ssl_free( ssl );
    platform_free(ssl);
    platform_free(ssn);
    if(cacert)
    	platform_free(cacert);
    return NULL;
}


int platform_ssl_close(void *ssl)
{
    ssl_context *sslt = (ssl_context *)ssl;

    platform_mutex_lock(sslt->write_lock);

    ssl_close_notify( sslt );

    x509_free( sslt->ca_chain );

    platform_free(sslt->ca_chain);

    platform_free(sslt->session);

    platform_mutex_unlock(sslt->write_lock);
    platform_mutex_destroy(sslt->write_lock);
    //platform_mutex_destroy(sslt->read_lock);

    ssl_free(sslt);

    platform_free(sslt);

    return 0;
}

int platform_ssl_send(void *ssl, const char *buf, int len)
{
    int ret;
    ssl_context *sslt = (ssl_context *)ssl;

    platform_mutex_lock(sslt->write_lock);

    while( ( ret = ssl_write( sslt, (u8 *)buf, len ) ) <= 0 )
    {
        if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            PSLL_PRT( " failed\n  ! ssl_write returned %d, errno %d\n", ret , errno);
            break;
        }
    }

    platform_mutex_unlock(sslt->write_lock);

    return ret;
}

int platform_ssl_recv(void *ssl, char *buf, int len)
{
    int ret;
    ssl_context *sslt = (ssl_context *)ssl;

    platform_mutex_lock(sslt->write_lock);
    //platform_mutex_lock(sslt->read_lock);

    do
    {
        ret = ssl_read( sslt, (u8 *)buf, len );

        if( ret == POLARSSL_ERR_NET_WANT_READ || ret == POLARSSL_ERR_NET_WANT_WRITE )
            continue;

        //if( ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY )
        //    break;

        if( ret < 0 )
        {
            PSLL_PRT( "failed\n  ! ssl_read returned %d, errno %d\n", ret , errno);
            break;
        }
        else if( ret == 0 )
        {
            PSLL_PRT("\n\nEOF, errno %d\n\n", errno);
            break;
        }
        else
        {
            //PSLL_PRT( " %d bytes read\n\n%s", ret, (char *) buf );
            break;
        }
    } while(1);

    platform_mutex_unlock(sslt->write_lock);
    //platform_mutex_unlock(sslt->read_lock);
	//PSLL_PRT(" <== platform_ssl_recv ret %d\n", ret);
    return ret;
}

int HTTPWrapperSSLConnect(tls_ssl_t **ssl_p,int fd,const struct sockaddr *name,int namelen,char *hostname)
{
	int			rc;
	tls_ssl_t *ssl = NULL;

	if(name)
	{
		char *host_ip = inet_ntoa(((struct sockaddr_in*)name)->sin_addr);
		
		rc = connect(fd,	// Socket
						name,							// Server address	 
						sizeof(struct sockaddr));
		if(rc)
		{
			TLS_DBGPRT_ERR("host_ip=%s\n", host_ip);
			TLS_DBGPRT_ERR("Connection Failed: %d.  Exiting\n", rc);
			return rc;
		}
	}
	ssl = platform_ssl_connect((void *)fd, NULL, 0);

	if(ssl == NULL)
		return -1;
	*ssl_p = ssl;
	return 0;
}
int HTTPWrapperSSLSend(tls_ssl_t *ssl, int s,char *sndbuf, int len,int flags)
{
	return platform_ssl_send(ssl, sndbuf, len);
}

int HTTPWrapperSSLRecv(tls_ssl_t *ssl,int s,char *buf, int len,int flags)
{
	int ret = platform_ssl_recv(ssl, buf, len);
	if(ssl->in_msglen > 0)
		return SOCKET_SSL_MORE_DATA;
	return ret;
}
int HTTPWrapperSSLRecvPending(tls_ssl_t *ssl)
{
	return ssl_get_bytes_avail(ssl);
}
int HTTPWrapperSSLClose(tls_ssl_t *ssl, int s)
{
	if(ssl == NULL)
		return 0;
	return platform_ssl_close(ssl);
}


#else //TLS_CONFIG_USE_POLARSSL
/******************************************************************************/
/*
	Example callback to show possiblie outcomes of certificate validation.
	If this callback is not registered in matrixSslNewClientSession
	the connection will be accepted or closed based on the alert value.
 */
static int32 certCb(tls_ssl_t *ssl, psX509Cert_t *cert, int32 alert)
{
#ifndef USE_ONLY_PSK_CIPHER_SUITE
	psX509Cert_t	*next;
		
	/* Did we even find a CA that issued the certificate? */
	if (alert == SSL_ALERT_UNKNOWN_CA) {
			/* Example to allow anonymous connections based on a define */
		if (ALLOW_ANON_CONNECTIONS) {
			if (1) {
				TLS_DBGPRT_INFO("Allowing anonymous connection for: %s.\n", 
						cert->subject.commonName);
			}
			return SSL_ALLOW_ANON_CONNECTION;
		}
	}

	/* Test if the server certificate didn't match the name passed to
		expectedName in matrixSslNewClientSession */
	if (alert == SSL_ALERT_CERTIFICATE_UNKNOWN) {
		TLS_DBGPRT_ERR("ERROR: %s not found in cert subject names\n",
			ssl->expectedName);
	}
	
	if (alert == SSL_ALERT_CERTIFICATE_EXPIRED) {
#ifdef POSIX
		TLS_DBGPRT_ERR("ERROR: A cert did not fall within the notBefore/notAfter window\n");
#else
		TLS_DBGPRT_WARNING("WARNING: Certificate date window validation not implemented\n");
		alert = 0;
#endif
	}
	
	if (alert == SSL_ALERT_ILLEGAL_PARAMETER) {
		TLS_DBGPRT_ERR("ERROR: Found correct CA but X.509 extension details are wrong\n");
	}
	
	/* Key usage related problems */
	next = cert;
	while (next) {
		if (next->authStatus == PS_CERT_AUTH_FAIL_EXTENSION) {
			if (cert->authFailFlags & PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG) {
				TLS_DBGPRT_ERR("CA keyUsage extension doesn't allow cert signing\n");
			}
			if (cert->authFailFlags & PS_CERT_AUTH_FAIL_EKU_FLAG) {
				TLS_DBGPRT_ERR("Cert extendedKeyUsage extension doesn't allow TLS\n");
			}
		}
		next = next->next;
	}
	
	if (alert == SSL_ALERT_BAD_CERTIFICATE) {
		/* Should never let a connection happen if this is set.  There was
			either a problem in the presented chain or in the final CA test */
		TLS_DBGPRT_ERR("ERROR: Problem in certificate validation.  Exiting.\n");	
		alert = 0;
	}

	
	if (alert == 0) TLS_DBGPRT_INFO("SUCCESS: Validated cert for: %s.\n",
		cert->subject.commonName);
	
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */
	return alert; 
}


/******************************************************************************/
/*
	Close a socket and free associated SSL context and buffers
	An attempt is made to send a closure alert
 */
static void closeConn(tls_ssl_t *ssl, int fd)
{
	unsigned char	*buf;
	int32			len;
#if 1
	/* Set the socket to non-blocking to flush remaining data */
	//len = 1;		/* 1 for non-block, 0 for block */
	//ioctlsocket(fd, FIONBIO, &len);
	
	/* Quick attempt to send a closure alert, don't worry about failure */
	if (matrixSslEncodeClosureAlert(ssl) >= 0) {
		if ((len = matrixSslGetOutdata(ssl, &buf)) > 0) {
			if ((len = send(fd, buf, len, MSG_DONTWAIT)) > 0) {
				matrixSslSentData(ssl, len);
			}
		}
	}
#endif
	matrixSslDeleteSession(ssl);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// Section      : TSL Wrapper
// Last updated : 15/05/2005
// Author Name	: Eitan Michaelson
// Notes	    : HTTPWrapper_Sec_Connect
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int HTTPWrapperSSLConnect(tls_ssl_t **ssl_p,int fd,const struct sockaddr *name,int namelen,char *hostname)
{
	int32			rc;
	sslKeys_t		*keys;
	sslSessionId_t	*sid;
	tlsExtension_t	*extension = NULL;
	int32			transferred, len, sessionFlag, SNIextLen;
	tls_ssl_t			*ssl;
	unsigned char	*buf, *SNIext;
	uint32 g_cipher[16] = {4, 5, 0x002F, 0x0035};
	int g_ciphers = 4;
	fd_set rdSet;
	fd_set wtSet;
//	int ret = 0;
	struct timeval timeout;
	char *host_ip = NULL;


	timeout.tv_sec = 10;
	timeout.tv_usec = 0;
	
	TLS_DBGPRT_INFO("HTTPWrapperSSLConnect start.\n");	
	if ((rc = matrixSslOpen()) < 0) 
	{
		TLS_DBGPRT_ERR("MatrixSSL library init failure.  Exiting\n");	
		return rc;
	}
	if (matrixSslNewKeys(&keys) < 0) 
	{
		TLS_DBGPRT_ERR("MatrixSSL library key init failure.  Exiting\n");
		return -1;
	}

	if (matrixSslNewSessionId(&sid) < 0) 
	{
		TLS_DBGPRT_ERR("MatrixSSL library SessionId init failure.  Exiting\n");
		matrixSslDeleteKeys(keys);
		return -1;
	}
	if(name)
	{
		host_ip = inet_ntoa(((struct sockaddr_in*)name)->sin_addr);
		rc = connect(fd,	// Socket
	                name,			                // Server address    
	                sizeof(struct sockaddr));
		if(rc)
			rc = SocketGetErr(fd);
		//TLS_DBGPRT_INFO("SocketGetErr rc %d\n", rc);
	    if(rc == 0 || rc == HTTP_EWOULDBLOCK || rc == HTTP_EINPROGRESS)
	    { }
		else
		{
			TLS_DBGPRT_ERR("host_ip=%s\n", host_ip);
			TLS_DBGPRT_ERR("Connection Failed: %d.  Exiting\n", rc);
			matrixSslDeleteSessionId(sid);
			matrixSslDeleteKeys(keys);
			return rc;
		}
		TLS_DBGPRT_INFO("HTTPWrapperSSLConnect keys=%p, sid=%p\n", keys, sid);
	}
#ifdef SSL_FLAGS_SSLV3
	/* Corresponds to version 3.g_version */
	switch (1) {
	case 0:
        sessionFlag = SSL_FLAGS_SSLV3;
		break;
	case 1:
        sessionFlag = SSL_FLAGS_TLS_1_0;
		break;
	case 2:
        sessionFlag = SSL_FLAGS_TLS_1_1;
		break;
	case 3:
        sessionFlag = SSL_FLAGS_TLS_1_2;
		break;
	default:
        sessionFlag = SSL_FLAGS_TLS_1_0;
		break;
    }
#else
	/* MatrixSSL <= 3.4.2 don't support setting version on request */
	sessionFlag = 0;
#endif
	if(host_ip)
	{
		matrixSslNewHelloExtension(&extension);
		matrixSslCreateSNIext(NULL, (unsigned char*)host_ip, (uint32)strlen(host_ip),
			&SNIext, &SNIextLen);
		matrixSslLoadHelloExtension(extension, SNIext, SNIextLen, 0);
		psFree(SNIext);
	}
	rc = matrixSslNewClientSession(&ssl, keys, sid, g_cipher, g_ciphers,
		certCb, host_ip, extension, NULL, sessionFlag);
	matrixSslDeleteHelloExtension(extension);
	if (rc != MATRIXSSL_REQUEST_SEND) {
		TLS_DBGPRT_ERR("New Client Session Failed: %d.  Exiting\n", rc);
		matrixSslDeleteSessionId(sid);
		matrixSslDeleteKeys(keys);
		return SOCKET_ERROR;
	}
	*ssl_p = ssl;
WRITE_MORE:
	while ((len = matrixSslGetOutdata(ssl, &buf)) > 0) {
		FD_ZERO(&wtSet);
		FD_SET(fd, &wtSet);
		select(fd+1, NULL, &wtSet, NULL, &timeout);
		if(FD_ISSET(fd, &wtSet)){
			transferred = send(fd, buf, len, 0);
			if (transferred <= 0) {
				goto L_CLOSE_ERR;
			} else {
				/* Indicate that we've written > 0 bytes of data */
				if ((rc = matrixSslSentData(ssl, transferred)) < 0) {
					goto L_CLOSE_ERR;
				}
				if (rc == MATRIXSSL_REQUEST_CLOSE) {
					return SOCKET_ERROR;
				} 
				if (rc == MATRIXSSL_HANDSHAKE_COMPLETE) {
					/* If we sent the Finished SSL message, initiate the HTTP req */
					/* (This occurs on a resumption handshake) 
					if (httpWriteRequest(ssl) < 0) {
						goto L_CLOSE_ERR;
					}
					goto WRITE_MORE;*/
				}
				/* SSL_REQUEST_SEND is handled by loop logic */
			}
		}
	}

READ_MORE:
	if ((len = matrixSslGetReadbuf(ssl, &buf)) <= 0) {
		goto L_CLOSE_ERR;
	}
	FD_ZERO(&rdSet);
	FD_SET(fd, &rdSet);
	select(fd+1, &rdSet, NULL, NULL, &timeout);
	if(FD_ISSET(fd, &rdSet)){
		if ((transferred = recv(fd, buf, len, 0)) < 0) {
			goto L_CLOSE_ERR;
		}
		/*	If EOF, remote socket closed. But we haven't received the HTTP response 
			so we consider it an error in the case of an HTTP client */
		if (transferred == 0) {
			goto L_CLOSE_ERR;
		}
		if ((rc = matrixSslReceivedData(ssl, (int32)transferred, &buf,
										(uint32*)&len)) < 0) {
			goto L_CLOSE_ERR;
		}
	}
	else{
		goto L_CLOSE_ERR;
	}
	
PROCESS_MORE:
	switch (rc) {
		case MATRIXSSL_HANDSHAKE_COMPLETE:
			break;
		case MATRIXSSL_APP_DATA:
		case MATRIXSSL_APP_DATA_COMPRESSED:
			rc = matrixSslProcessedData(ssl, &buf, (uint32*)&len);
			if (rc == 0) {
				/* We processed a partial HTTP message */
				goto READ_MORE;
			}
			goto PROCESS_MORE;
		case MATRIXSSL_REQUEST_SEND:
			goto WRITE_MORE;
		case MATRIXSSL_REQUEST_RECV:
			goto READ_MORE;
		case MATRIXSSL_RECEIVED_ALERT:
			/* The first byte of the buffer is the level */
			/* The second byte is the description */
			if (*buf == SSL_ALERT_LEVEL_FATAL) {
				TLS_DBGPRT_ERR("Fatal alert: %d, closing connection.\n", 
							*(buf + 1));
				goto L_CLOSE_ERR;
			}
			/* Closure alert is normal (and best) way to close */
			if (*(buf + 1) == SSL_ALERT_CLOSE_NOTIFY) {
				return SOCKET_ERROR;
			}
			TLS_DBGPRT_INFO("Warning alert: %d\n", *(buf + 1));
			if ((rc = matrixSslProcessedData(ssl, &buf, (uint32*)&len)) == 0) {
				/* No more data in buffer. Might as well read for more. */
				goto READ_MORE;
			}
			goto PROCESS_MORE;
		default:
			/* If rc <= 0 we fall here */
			goto L_CLOSE_ERR;
	}

	return 0;
L_CLOSE_ERR:
	return SOCKET_ERROR;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int HTTPWrapperSSLSend(tls_ssl_t *ssl, int s,char *sndbuf, int len,int flags)
{
	unsigned char   *buf;
	uint32          requested = len;
	int32			rc,available, transferred;
	if ((available = matrixSslGetWritebuf(ssl, &buf, requested)) < 0) {
		TLS_DBGPRT_ERR("matrixSslGetWritebuf available = %d.\n", available);	
		return SOCKET_ERROR;
	}
	requested = min(requested, available);
	MEMCPY(buf, sndbuf, requested);
	
	TLS_DBGPRT_INFO("SEND: [%s]\n", (char*)sndbuf);
	if ((rc = matrixSslEncodeWritebuf(ssl, requested)) < 0) {
		TLS_DBGPRT_ERR("matrixSslEncodeWritebuf rc = %d.\n", rc);	
		return SOCKET_ERROR;
	}
	
//WRITE_MORE:
	while ((len = matrixSslGetOutdata(ssl, &buf)) > 0) {
		transferred = send(s, buf, len, flags);
		if (transferred <= 0) {
			TLS_DBGPRT_ERR("send transferred = %d.\n", transferred);	
			goto L_CLOSE_ERR;
		} else {
			/* Indicate that we've written > 0 bytes of data */
			if ((rc = matrixSslSentData(ssl, transferred)) < 0) {
				TLS_DBGPRT_ERR("matrixSslSentData rc = %d.\n", rc);	
				goto L_CLOSE_ERR;
			}
			if (rc == MATRIXSSL_REQUEST_CLOSE) {
				TLS_DBGPRT_ERR("MATRIXSSL_REQUEST_CLOSE rc = %d.\n", rc);	
				goto L_CLOSE_ERR;
			} 
			/* SSL_REQUEST_SEND is handled by loop logic */
		}
	}
	return requested;
L_CLOSE_ERR:
	return SOCKET_ERROR;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int HTTPWrapperSSLRecv(tls_ssl_t *ssl,int s,char *buf, int len,int flags)
{
	int32			rc,offset, transferred;
	unsigned char *ptbuf;
	int ptlen;
	int buf_offset = 0;
	offset = 0;
	if(ssl->lastDataLen > ssl->lastDataOffset)
	{
		offset = ssl->lastDataLen - ssl->lastDataOffset;
		goto L_CLOSE_OK;
	}
	else if( ssl->inlen > 0)
	{
		rc =  matrixSslProcessedData(ssl, &ptbuf, (uint32*)&ptlen);
		goto PROCESS_MORE;
	}
	READ_MORE:
		ptlen  = len;
			/* Get the ssl buffer and how much data it can accept */
			/* Note 0 is a return failure, unlike with matrixSslGetOutdata */
			if ((ptlen = matrixSslGetReadbuf(ssl, &ptbuf)) <= 0) {
				TLS_DBGPRT_ERR("matrixSslGetReadbuf err.\n");	
				return SOCKET_ERROR;
			}
			//ptlen = min(ptlen, 1460);
			if ((transferred = recv(s, ptbuf, ptlen, flags)) < 0) {
				TLS_DBGPRT_ERR("recv err.\n");	
				return SOCKET_ERROR;
			}
			/* If EOF, remote socket closed. This is semi-normal closure.
			   Officially, we should close on closure alert. */
			if (transferred == 0) {
				TLS_DBGPRT_ERR("recv zero.\n");	
				return SOCKET_ERROR;
			}
/*
			Notify SSL state machine that we've received more data into the
			ssl buffer retreived with matrixSslGetReadbuf.
 */
			if ((rc = matrixSslReceivedData(ssl, (int32)transferred, &ptbuf, 
											(uint32*)&ptlen)) < 0) {
				TLS_DBGPRT_ERR("matrixSslReceivedData err = %d.\n", rc);	
				return SOCKET_ERROR;
			}
			TLS_DBGPRT_INFO("matrixSslReceivedData rc = %d.\n", rc);	
			if(ptlen > 0){
				TLS_DBGPRT_INFO("matrixSslReceivedData %.*s.\n", ptlen, ptbuf);	
				ssl->lastData = ptbuf;
				ssl->lastDataLen = ptlen;
				ssl->lastDataOffset = 0;
				offset = ptlen;
				goto L_CLOSE_OK;
			}
PROCESS_MORE:
			/* Process any incoming plaintext application data */
			switch (rc) {
				case MATRIXSSL_SUCCESS:
					break;
				case MATRIXSSL_APP_DATA:
				case MATRIXSSL_APP_DATA_COMPRESSED:
					/* We processed a partial HTTP message */
					if(ptlen > 0){
						TLS_DBGPRT_INFO("MATRIXSSL_APP_DATA %.*s.\n", ptlen, ptbuf);	
						ssl->lastData = ptbuf;
						ssl->lastDataLen = ptlen;
						ssl->lastDataOffset = 0;
						offset = ptlen;
						goto L_CLOSE_OK;
					}
				case MATRIXSSL_REQUEST_SEND:
					while ((ptlen = matrixSslGetOutdata(ssl, &ptbuf)) > 0) {
						transferred = send(s, buf, len, 0);
						if (transferred <= 0) {
							TLS_DBGPRT_ERR("send transferred = %d.\n", transferred);	
							goto L_CLOSE_ERR;
						} else {
							/* Indicate that we've written > 0 bytes of data */
							if ((rc = matrixSslSentData(ssl, transferred)) < 0) {
								TLS_DBGPRT_ERR("matrixSslSentData rc = %d.\n", rc);	
								goto L_CLOSE_ERR;
							}
							if (rc == MATRIXSSL_REQUEST_CLOSE) {
								TLS_DBGPRT_ERR("MATRIXSSL_REQUEST_CLOSE rc = %d.\n", rc);	
								goto L_CLOSE_ERR;
							} 
							/* SSL_REQUEST_SEND is handled by loop logic */
						}
					}
					goto READ_MORE;
				case MATRIXSSL_REQUEST_RECV:
					goto READ_MORE;
				case MATRIXSSL_RECEIVED_ALERT:
					/* The first byte of the buffer is the level */
					/* The second byte is the description */
					if (*ptbuf == SSL_ALERT_LEVEL_FATAL) {
						TLS_DBGPRT_ERR("Fatal alert: %d, closing connection.\n", 
									*(ptbuf + 1));
						return SOCKET_ERROR;
					}
					/* Closure alert is normal (and best) way to close */
					if (*(ptbuf + 1) == SSL_ALERT_CLOSE_NOTIFY) {
						TLS_DBGPRT_ERR("Fatal alert: %d, closing connection.\n", 
									*(ptbuf + 1));
						return SOCKET_ERROR;
					}
					TLS_DBGPRT_INFO("Warning alert: %d\n", *(ptbuf + 1));
					if ((rc = matrixSslProcessedData(ssl, &ptbuf, (uint32*)&ptlen)) == 0) {
						break;
					}
					goto PROCESS_MORE;
				default:
					/* If rc < 0 we fall here */
					TLS_DBGPRT_ERR("process default code err %d.\n", rc);	
					return SOCKET_ERROR;
			}
L_CLOSE_OK:
			if(offset > 0)
			{
				offset = min(offset, len-buf_offset);
				MEMCPY(buf+buf_offset, ssl->lastData + ssl->lastDataOffset, offset);
				buf_offset += offset;
				//printf("buf=%p, ssl->lastDataOffset=%d, offset=%d\n", buf, ssl->lastDataOffset, offset);
				ssl->lastDataOffset += offset;
				offset = 0;
				if(ssl->lastDataLen > ssl->lastDataOffset)
				{
					buf_offset = SOCKET_SSL_MORE_DATA;
				}
				else if( ssl->inlen > 0)
				{
					rc =  matrixSslProcessedData(ssl, &ptbuf, (uint32*)&ptlen);
					goto PROCESS_MORE;
				}
			}
    return buf_offset;
L_CLOSE_ERR:
	return SOCKET_ERROR;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int HTTPWrapperSSLRecvPending(tls_ssl_t *ssl)
{
    return ssl->lastDataLen - ssl->lastDataOffset;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int HTTPWrapperSSLClose(tls_ssl_t *ssl, int s)
{
	if(ssl)
	{
		sslKeys_t		*keys = ssl->keys;
		sslSessionId_t	*sid = ssl->sid;
		TLS_DBGPRT_INFO("HTTPWrapperSSLClose keys=%p, sid=%p\n", keys, sid);
		closeConn(ssl, s);
		matrixSslDeleteSessionId(sid);
		matrixSslDeleteKeys(keys);
	}
	matrixSslClose();
    return 0;

}
#endif //TLS_CONFIG_USE_POLARSSL
#endif //TLS_CONFIG_HTTP_CLIENT_SECURE
