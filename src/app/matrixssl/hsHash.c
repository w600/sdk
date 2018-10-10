/*
 *	hsHash.c
 *	Release $Name: MATRIXSSL-3-6-1-OPEN $
 *
 *	"Native" handshake hash
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

#include "matrixsslApi.h"
#if TLS_CONFIG_HARD_CRYPTO
#include "wm_crypto_hard.h"
#endif

#define FINISHED_LABEL_SIZE	15
#define LABEL_CLIENT		"client finished"
#define LABEL_SERVER		"server finished"
/******************************************************************************/
/*
	Initialize the SHA1 and MD5 hash contexts for the handshake messages
*/
int32 sslInitHSHash(ssl_t *ssl)
{

	psSha1Init(&ssl->sec.msgHashSha1);
	psMd5Init(&ssl->sec.msgHashMd5);
#ifdef USE_TLS_1_2
	psSha256Init(&ssl->sec.msgHashSha256);
#ifdef USE_SHA384
	psSha384Init(&ssl->sec.msgHashSha384);
#endif	
#endif	
	return 0;
}

/******************************************************************************/
/*
	Add the given data to the running hash of the handshake messages
*/
int32 sslUpdateHSHash(ssl_t *ssl, unsigned char *in, uint32 len)
{

#ifdef USE_TLS_1_2
	/* Keep a running total of each for greatest RFC support when it comes
		to the CertificateVerify message.  Although, trying to be smart
		about MD5 and SHA-2 based on protocol version */
	if ((ssl->majVer == 0 && ssl->minVer == 0) ||
			ssl->minVer == TLS_1_2_MIN_VER) {
		psSha256Update(&ssl->sec.msgHashSha256, in, len);
#ifdef USE_SHA384
		psSha384Update(&ssl->sec.msgHashSha384, in, len);
#endif		
	}
	
	if (ssl->reqMinVer == 0 || ssl->minVer != TLS_1_2_MIN_VER) {
		psMd5Update(&ssl->sec.msgHashMd5, in, len);
	}
	psSha1Update(&ssl->sec.msgHashSha1, in, len);
#else	
	psMd5Update(&ssl->sec.msgHashMd5, in, len);
	psSha1Update(&ssl->sec.msgHashSha1, in, len);
#endif

	return 0;
}

#ifdef USE_TLS_1_2
/*	Functions necessary to deal with needing to keep track of both SHA-1
	and SHA-256 handshake hash states.  FINISHED message will always be
	SHA-256 but client might be sending SHA-1 CertificateVerify message */
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
int32 sslSha1RetrieveHSHash(ssl_t *ssl, unsigned char *out)
{
	memcpy(out, ssl->sec.sha1Snapshot, SHA1_HASH_SIZE);
	return SHA1_HASH_SIZE;
}
#ifdef USE_SHA384
int32 sslSha384RetrieveHSHash(ssl_t *ssl, unsigned char *out)
{
	memcpy(out, ssl->sec.sha384Snapshot, SHA384_HASH_SIZE);
	return SHA384_HASH_SIZE;
}
#endif
#endif

#if defined(USE_CLIENT_SIDE_SSL) && defined(USE_CLIENT_AUTH)
/*	It is possible the certificate verify message wants a non-SHA256 hash */
void sslSha1SnapshotHSHash(ssl_t *ssl, unsigned char *out)
{
	psSha1Final(&ssl->sec.msgHashSha1, out);
}
#ifdef USE_SHA384
void sslSha384SnapshotHSHash(ssl_t *ssl, unsigned char *out)
{
	psDigestContext_t sha384;
   
    /* SHA384 must copy the context because it could be needed again for
        final handshake hash.  SHA1 doesn't need this because it will
        not ever be used again after this client auth one-off */
    sha384 = ssl->sec.msgHashSha384;
    psSha384Final(&sha384, out);
}
#endif /* USE_SHA384 */
#endif /* USE_CLIENT_SIDE_SSL */
#endif /* USE_TLS_1_2 */

#ifdef USE_TLS
/******************************************************************************/
/*
	TLS handshake hash computation
*/
static int32 tlsGenerateFinishedHash(ssl_t *ssl, psDigestContext_t *md5,
				psDigestContext_t *sha1, psDigestContext_t *sha256,
				psDigestContext_t *sha384, unsigned char *masterSecret,
				unsigned char *out, int32 sender)
{
	unsigned char	tmp[FINISHED_LABEL_SIZE + SHA384_HASH_SIZE];
	int32			tlsTmpSize;

	if (sender >= 0) {
		memcpy(tmp, (sender & SSL_FLAGS_SERVER) ? LABEL_SERVER : LABEL_CLIENT, 
			FINISHED_LABEL_SIZE);
		tlsTmpSize = FINISHED_LABEL_SIZE + SHA1_HASH_SIZE + MD5_HASH_SIZE;
#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			if (ssl->cipher->flags & CRYPTO_FLAGS_SHA3) {
#ifdef USE_SHA384			
				psSha384Final(sha384, tmp + FINISHED_LABEL_SIZE);
				return prf2(masterSecret, SSL_HS_MASTER_SIZE, tmp,
					FINISHED_LABEL_SIZE + SHA384_HASH_SIZE, out,
					TLS_HS_FINISHED_SIZE, CRYPTO_FLAGS_SHA3);
#endif					
			} else {
				psSha256Final(sha256, tmp + FINISHED_LABEL_SIZE);
				return prf2(masterSecret, SSL_HS_MASTER_SIZE, tmp,
					FINISHED_LABEL_SIZE + SHA256_HASH_SIZE, out,
					TLS_HS_FINISHED_SIZE, CRYPTO_FLAGS_SHA2);
			}
		} else {
			psMd5Final(md5, tmp + FINISHED_LABEL_SIZE);
			psSha1Final(sha1, tmp + FINISHED_LABEL_SIZE + MD5_HASH_SIZE);
			return prf(masterSecret, SSL_HS_MASTER_SIZE, tmp, tlsTmpSize, 
				out, TLS_HS_FINISHED_SIZE);
		}
#else		
		psMd5Final(md5, tmp + FINISHED_LABEL_SIZE);
		psSha1Final(sha1, tmp + FINISHED_LABEL_SIZE + MD5_HASH_SIZE);
		return prf(masterSecret, SSL_HS_MASTER_SIZE, tmp, tlsTmpSize, 
			out, TLS_HS_FINISHED_SIZE);
#endif			
	} else {
		/* Overloading this function to handle the client auth needs of
			handshake hashing. */
#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			psSha256Final(sha256, out);			
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
#ifdef USE_SHA384
			psSha384Final(sha384, ssl->sec.sha384Snapshot);
#endif		
			psSha1Final(sha1, ssl->sec.sha1Snapshot);
#endif
			return SHA256_HASH_SIZE;
		} else {
			psMd5Final(md5, out);
			psSha1Final(sha1, out + MD5_HASH_SIZE);
			return MD5_HASH_SIZE + SHA1_HASH_SIZE;
		}
#else			
/*
		The handshake snapshot for client authentication is simply the
		appended MD5 and SHA1 hashes
*/
		psMd5Final(md5, out);
		psSha1Final(sha1, out + MD5_HASH_SIZE);
		return MD5_HASH_SIZE + SHA1_HASH_SIZE;
#endif		
	}
	return PS_FAILURE; /* Should not reach this */
}
#endif /* USE_TLS */

/******************************************************************************/
/*
	Snapshot is called by the receiver of the finished message to produce
	a hash of the preceeding handshake messages for comparison to incoming
	message.
*/
int32 sslSnapshotHSHash(ssl_t *ssl, unsigned char *out, int32 senderFlag)
{
#ifdef USE_TLS
	psDigestContext_t	sha256, sha384;
#endif
	psDigestContext_t	md5, sha1;
	int32				len = PS_FAILURE;
	

/*
	Use a backup of the message hash-to-date because we don't want
	to destroy the state of the handshaking until truly complete
*/
#ifdef  USE_TLS_1_2
	if (ssl->flags & SSL_FLAGS_TLS_1_2) {
		sha256 = ssl->sec.msgHashSha256;
#ifdef USE_SHA384
		sha384 = ssl->sec.msgHashSha384;
#endif		
	}
#endif	
	md5 = ssl->sec.msgHashMd5;
	sha1 = ssl->sec.msgHashSha1;

#ifdef USE_TLS
	if (ssl->flags & SSL_FLAGS_TLS) {
		len = tlsGenerateFinishedHash(ssl, &md5, &sha1, &sha256, &sha384,
			ssl->sec.masterSecret, out, senderFlag);
	} else {
#endif /* USE_TLS */
#ifndef DISABLE_SSLV3
		len = sslGenerateFinishedHash(&md5, &sha1, ssl->sec.masterSecret,
			out, senderFlag);
#endif /* DISABLE_SSLV3 */			
#ifdef USE_TLS
	}
#endif /* USE_TLS */

	return len;
}

