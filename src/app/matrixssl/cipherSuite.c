/*
 *	cipherSuite.c
 *	Release $Name: MATRIXSSL-3-6-1-OPEN $
 *
 *	Wrappers for the various cipher suites.
 *	Enable specific suites at compile time in matrixsslConfig.h
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

#include "matrixsslApi.h"
#include "aes.h"
#if TLS_CONFIG_HARD_CRYPTO
#include "wm_crypto_hard.h"
#endif
/******************************************************************************/
/*	Symmetric cipher initializtion wrappers for cipher suites */
/******************************************************************************/
/*
	SSL_NULL_WITH_NULL_NULL cipher functions
	Used in handshaking before SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC message
*/
static int32 csNullInit(sslSec_t *sec, int32 type, uint32 keysize)
{
	return 0;
}

/******************************************************************************/
#ifdef USE_ARC4_CIPHER_SUITE
/******************************************************************************/
static int32 csArc4Init(sslSec_t *sec, int32 type, uint32 keysize)
{
	if (type == INIT_ENCRYPT_CIPHER) {
		memset(&(sec->encryptCtx), 0, sizeof(psRc4Key_t));
		psArc4Init(&(sec->encryptCtx), sec->writeKey, keysize);
	} else {
		memset(&(sec->decryptCtx), 0, sizeof(psRc4Key_t));
		psArc4Init(&(sec->decryptCtx), sec->readKey, keysize);
	}
	return PS_SUCCESS;
}
int32 csArc4Encrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len)
{
	ssl_t	*lssl = ssl;
	psCipherContext_t *ctx = (psCipherContext_t*)&lssl->sec.encryptCtx;
	return psArc4(ctx, pt, ct, len);	
}
int32 csArc4Decrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len)
{
	ssl_t	*lssl = ssl;
	psCipherContext_t *ctx = (psCipherContext_t*)&lssl->sec.decryptCtx;
	return psArc4(ctx, ct, pt, len);	
}

#endif /* USE_ARC4_CIPHER_SUITE */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_3DES_CIPHER_SUITE
/******************************************************************************/
static int32 csDes3Init(sslSec_t *sec, int32 type, uint32 keysize)
{
	int32	err;
	
	psAssert(keysize == DES3_KEY_LEN);
	
	if (type == INIT_ENCRYPT_CIPHER) {
		memset(&(sec->encryptCtx), 0, sizeof(des3_CBC));	
		if ((err = psDes3Init(&(sec->encryptCtx), sec->writeIV, sec->writeKey, 
							  DES3_KEY_LEN)) < 0) {
			return err;
		}
	} else {
		memset(&(sec->decryptCtx), 0, sizeof(des3_CBC));
		if ((err = psDes3Init(&(sec->decryptCtx), sec->readIV, sec->readKey, 
							  DES3_KEY_LEN)) < 0) {
			return err;
		}
	}
	return PS_SUCCESS;
}

int32 csDes3Encrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len)
{
	ssl_t	*lssl = ssl;
	psCipherContext_t *ctx = (psCipherContext_t*)&lssl->sec.encryptCtx;
	return psDes3Encrypt(ctx, pt, ct, len);	
}

int32 csDes3Decrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len)
{
	ssl_t	*lssl = ssl;
	psCipherContext_t *ctx = (psCipherContext_t*)&lssl->sec.decryptCtx;
	return psDes3Decrypt(ctx, ct, pt, len);	
}

#endif /* USE_3DES_CIPHER_SUITE */
/******************************************************************************/


#ifdef USE_AES_CIPHER_SUITE
#ifdef USE_AES_GCM
int32 csAesGcmInit(sslSec_t *sec, int32 type, uint32 keysize)
{
	int32	err;
	
	if (type == INIT_ENCRYPT_CIPHER) {
		memset(&(sec->encryptCtx), 0, sizeof(psAesCipher_t));	
		if ((err = psAesInitGCM(&(sec->encryptCtx), sec->writeKey,
				keysize)) < 0) {
			return err;
		}
	} else {
		memset(&(sec->decryptCtx), 0, sizeof(psAesCipher_t));
		if ((err = psAesInitGCM(&(sec->decryptCtx), sec->readKey,
				keysize)) < 0) {
			return err;
		}
	}
	return 0;
}

int32 csAesGcmEncrypt(void *ssl, unsigned char *pt,
			unsigned char *ct, uint32 len)
{
	ssl_t				*lssl = ssl;
	psCipherContext_t	*ctx;
	unsigned char		nonce[12];
	unsigned char		aad[13];
	int32				i, ptLen, seqNotDone;
	
	if (len == 0) {
		return PS_SUCCESS;
	}

	if (len < 16 + 1) {
		return PS_LIMIT_FAIL;
	}
	ptLen = len - TLS_GCM_TAG_LEN;
	
	ctx = (psCipherContext_t*)&lssl->sec.encryptCtx;
	
	memcpy(nonce, lssl->sec.writeIV, 4);
	
	seqNotDone = 1;
	
	if (seqNotDone) {
		memcpy(nonce + 4, lssl->sec.seq, TLS_GCM_NONCE_LEN);
		memcpy(aad, lssl->sec.seq, 8);
	}
	aad[8] = lssl->outRecType;
	aad[9] = lssl->majVer;
	aad[10] = lssl->minVer;
	aad[11] = ptLen >> 8 & 0xFF;
	aad[12] = ptLen & 0xFF;

	psAesReadyGCM(ctx, nonce, aad, 13);
	psAesEncryptGCM(ctx, pt, ct, ptLen);
	psAesGetGCMTag(ctx, 16, ct + ptLen);
	
	/* Normally HMAC would increment the sequence */
	for (i = 7; i >= 0; i--) {
		lssl->sec.seq[i]++;
		if (lssl->sec.seq[i] != 0) {
			break; 
		}
	}
	return len;
}

int32 csAesGcmDecrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len)
{
	ssl_t				*lssl = ssl;
	psCipherContext_t	*ctx;
	int32				i, ctLen, bytes, seqNotDone;	
	unsigned char		nonce[12];
	unsigned char		aad[13];
	
	ctx = (psCipherContext_t*)&lssl->sec.decryptCtx;
	
	seqNotDone = 1;
	memcpy(nonce, lssl->sec.readIV, 4);
	
	
	if (seqNotDone) {
		memcpy(nonce + 4, ct, TLS_GCM_NONCE_LEN);
		memcpy(aad, lssl->sec.remSeq, 8);
		ct += TLS_GCM_NONCE_LEN;
		len -= TLS_GCM_NONCE_LEN;
	}
	ctLen = len - TLS_GCM_TAG_LEN; 
	aad[8] = lssl->rec.type;
	aad[9] = lssl->majVer;
	aad[10] = lssl->minVer;
	aad[11] = ctLen >> 8 & 0xFF;
	aad[12] = ctLen & 0xFF;
	
	psAesReadyGCM(ctx, nonce, aad, 13);

	if ((bytes = psAesDecryptGCM(ctx, ct, len, pt, len - TLS_GCM_TAG_LEN)) < 0){
		return -1;
	}
	for (i = 7; i >= 0; i--) {
		lssl->sec.remSeq[i]++;
		if (lssl->sec.remSeq[i] != 0) {
			break; 
		}
	}
	return bytes;
}
#endif /* USE_AES_GCM */


/******************************************************************************/
int32 csAesInit(sslSec_t *sec, int32 type, uint32 keysize)
{
	int32	err;
	
	if (type == INIT_ENCRYPT_CIPHER) {	
		memset(&(sec->encryptCtx), 0, sizeof(psAesCipher_t));	
		if ((err = psAesInit((psAesCipherContext_t *)&sec->encryptCtx, sec->writeIV, sec->writeKey,
							 keysize)) < 0) {
			return err;
		}
	} else { /* Init for decrypt */	
		memset(&(sec->decryptCtx), 0, sizeof(psAesCipher_t));	
		if ((err = psAesInit((psAesCipherContext_t *)&sec->decryptCtx, sec->readIV, sec->readKey,
							 keysize)) < 0) {
			return err;
		}
	}
	return PS_SUCCESS;
}

int32 csAesEncrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len)
{
	ssl_t	*lssl = ssl;
	return psAesEncrypt((psAesCipherContext_t *)&lssl->sec.encryptCtx, pt, ct, len);	
}

int32 csAesDecrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len)
{
	ssl_t	*lssl = ssl;
	return psAesDecrypt((psAesCipherContext_t *)&lssl->sec.decryptCtx, ct, pt, len);	
}
#endif /* USE_AES_CIPHER_SUITE */
/******************************************************************************/

#ifdef USE_IDEA_CIPHER_SUITE
int32 csIdeaInit(sslSec_t *sec, int32 type, uint32 keysize)
{
	int32	err;
	
	if (type == INIT_ENCRYPT_CIPHER) {	
		memset(&(sec->encryptCtx), 0, sizeof(psCipherContext_t));	
		if ((err = psIdeaInit(&(sec->encryptCtx), sec->writeIV, sec->writeKey,
							 keysize)) < 0) {
			return err;
		}
	} else { /* Init for decrypt */	
		memset(&(sec->decryptCtx), 0, sizeof(psCipherContext_t));	
		if ((err = psIdeaInit(&(sec->decryptCtx), sec->readIV, sec->readKey,
							 keysize)) < 0) {
			return err;
		}
	}
	return PS_SUCCESS;
}

int32 csIdeaEncrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len)
{
	ssl_t	*lssl = ssl;
	psCipherContext_t *ctx = (psCipherContext_t*)&lssl->sec.encryptCtx;
	return psIdeaEncrypt(ctx, pt, ct, len);
}

int32 csIdeaDecrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len)
{
	ssl_t	*lssl = ssl;
	psCipherContext_t *ctx = (psCipherContext_t*)&lssl->sec.decryptCtx;
	return psIdeaDecrypt(ctx, ct, pt, len);
}
#endif /* USE_IDEA_CIPHER_SUITE */

/******************************************************************************/
#ifdef USE_SEED_CIPHER_SUITE
/******************************************************************************/
static int32 csSeedInit(sslSec_t *sec, int32 type, uint32 keysize)
{
	int32	err;
	
	psAssert(keysize == SSL_SEED_KEY_LEN);
	
	if (type == INIT_ENCRYPT_CIPHER) {
		memset(&(sec->encryptCtx), 0, sizeof(seed_CBC));
		if ((err = psSeedInit(&(sec->encryptCtx), sec->writeIV, sec->writeKey, 
							  SSL_SEED_KEY_LEN)) < 0) {
			return err;
		}		
	} else {
		memset(&(sec->decryptCtx), 0, sizeof(seed_CBC));
		if ((err = psSeedInit(&(sec->decryptCtx), sec->readIV, sec->readKey, 
							  SSL_SEED_KEY_LEN)) < 0) {
			return err;
		}		
	}
	return 0;
}
int32 csSeedEncrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len)
{
	ssl_t	*lssl = ssl;
	psCipherContext_t *ctx = (psCipherContext_t*)&lssl->sec.encryptCtx;
	return psSeedEncrypt(ctx, pt, ct, len);	
}

int32 csSeedDecrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len)
{
	ssl_t	*lssl = ssl;
	psCipherContext_t *ctx = (psCipherContext_t*)&lssl->sec.decryptCtx;
	return psSeedDecrypt(ctx, ct, pt, len);	
}

#endif /* USE_SEED_CIPHER_SUITE */
/******************************************************************************/


/******************************************************************************/
/*	Null cipher crypto */
/******************************************************************************/
static int32 csNullEncrypt(void *ctx, unsigned char *in,
						 unsigned char *out, uint32 len)
{
	if (out != in) {
		memcpy(out, in, len);
	}
	return len;
}

static int32 csNullDecrypt(void *ctx, unsigned char *in,
						 unsigned char *out, uint32 len)
{
	if (out != in) {
		memmove(out, in, len);
	}
	return len;
}

/******************************************************************************/
/*	HMAC wrappers for cipher suites */
/******************************************************************************/
static int32 csNullGenerateMac(void *ssl, unsigned char type,
						unsigned char *data, uint32 len, unsigned char *mac)
{
	return 0;
}

static int32 csNullVerifyMac(void *ssl, unsigned char type,
						unsigned char *data, uint32 len, unsigned char *mac)
{
	return 0;
}

#ifdef USE_SHA_MAC
/******************************************************************************/
static int32 csShaGenerateMac(void *sslv, unsigned char type,
					unsigned char *data, uint32 len, unsigned char *macOut)
{
	ssl_t	*ssl = (ssl_t*)sslv;
	unsigned char	mac[MAX_HASH_SIZE];

#ifdef USE_TLS
	if (ssl->flags & SSL_FLAGS_TLS) {
#ifdef USE_SHA256	
		if (ssl->nativeEnMacSize == SHA256_HASH_SIZE ||
				ssl->nativeEnMacSize == SHA384_HASH_SIZE) {
			tlsHMACSha2(ssl, HMAC_CREATE, type, data, len, mac,
				ssl->nativeEnMacSize);
		} else {
#endif		
			tlsHMACSha1(ssl, HMAC_CREATE, type, data, len, mac);
#ifdef USE_SHA256			
		}
#endif
	} else {
#endif /* USE_TLS */
#ifndef DISABLE_SSLV3
		ssl3HMACSha1(ssl, HMAC_CREATE, ssl->sec.writeMAC, ssl->sec.seq, type, data,
				len, mac);
#else
		return PS_ARG_FAIL;
#endif /* DISABLE_SSLV3 */
#ifdef USE_TLS
	}
#endif /* USE_TLS */

	memcpy(macOut, mac, ssl->enMacSize);
	return ssl->enMacSize;
}

static int32 csShaVerifyMac(void *sslv, unsigned char type,
					unsigned char *data, uint32 len, unsigned char *mac)
{
	unsigned char	buf[MAX_HASH_SIZE];
	ssl_t	*ssl = (ssl_t*)sslv;
	
#ifdef USE_TLS
	if (ssl->flags & SSL_FLAGS_TLS) {
#ifdef USE_SHA256
		if (ssl->nativeDeMacSize == SHA256_HASH_SIZE ||
				ssl->nativeDeMacSize == SHA384_HASH_SIZE) {
			tlsHMACSha2(ssl, HMAC_VERIFY, type, data, len, buf,
				ssl->nativeDeMacSize);
		} else {
#endif		
			tlsHMACSha1(ssl, HMAC_VERIFY, type, data, len, buf);
#ifdef USE_SHA256			
		}
#endif		
	} else {
#endif /* USE_TLS */
#ifndef DISABLE_SSLV3
		ssl3HMACSha1(ssl, HMAC_VERIFY, ssl->sec.readMAC, ssl->sec.remSeq, type, data, len, buf);
#endif /* DISABLE_SSLV3 */		
#ifdef USE_TLS
	}
#endif /* USE_TLS */
#ifdef USE_APP_DATA_PARTIAL_PARSING
	if(ssl->rec.type == SSL_RECORD_TYPE_APPLICATION_DATA && ssl->deBlockSize <= 1 && (data != NULL || len != 0))
		return PS_SUCCESS;
#endif
	if (memcmp(buf, mac, ssl->deMacSize) == 0) {
		return PS_SUCCESS;
	}
	return PS_FAILURE;
}
#endif /* USE_SHA_MAC */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_MD5_MAC
/******************************************************************************/
static int32 csMd5GenerateMac(void *sslv, unsigned char type,
					unsigned char *data, uint32 len, unsigned char *macOut)
{
	unsigned char	mac[MD5_HASH_SIZE];
	ssl_t	*ssl = (ssl_t*)sslv;
#ifdef USE_TLS
	if (ssl->flags & SSL_FLAGS_TLS) {
		tlsHMACMd5(ssl, HMAC_CREATE, type, data, len, mac);
	} else {
#endif /* USE_TLS */
#ifndef DISABLE_SSLV3
		ssl3HMACMd5(ssl, HMAC_CREATE, ssl->sec.writeMAC, ssl->sec.seq, type, data,
						   len, mac);
#else
		return PS_ARG_FAIL;
#endif /* DISABLE_SSLV3 */						   
#ifdef USE_TLS
	}
#endif /* USE_TLS */
	memcpy(macOut, mac, ssl->enMacSize);
	return ssl->enMacSize;
}

static int32 csMd5VerifyMac(void *sslv, unsigned char type, unsigned char *data,
					uint32 len, unsigned char *mac)
{
	unsigned char	buf[MD5_HASH_SIZE];
	ssl_t	*ssl = (ssl_t*)sslv;
	
#ifdef USE_TLS
	if (ssl->flags & SSL_FLAGS_TLS) {
		tlsHMACMd5(ssl, HMAC_VERIFY, type, data, len, buf);
	} else {
#endif /* USE_TLS */
#ifndef DISABLE_SSLV3
		ssl3HMACMd5(ssl, HMAC_VERIFY, ssl->sec.readMAC, ssl->sec.remSeq, type, data, len, buf);
#endif /* DISABLE_SSLV3 */		
#ifdef USE_TLS
	}
#endif /* USE_TLS */
#ifdef USE_APP_DATA_PARTIAL_PARSING
	if(ssl->rec.type == SSL_RECORD_TYPE_APPLICATION_DATA && ssl->deBlockSize <= 1 && (data != NULL || len != 0))
		return PS_SUCCESS;
#endif
	if (memcmp(buf, mac, ssl->deMacSize) == 0) {
		return PS_SUCCESS;
	}
	return PS_FAILURE;
}
#endif /* USE_MD5_MAC */
/******************************************************************************/

/******************************************************************************/
/*	Public Key operations wrappers for cipher suites */
/******************************************************************************/
/******************************************************************************/
#ifdef USE_RSA
/******************************************************************************/

int32 csRsaEncryptPub(psPool_t *pool, psPubKey_t *key, 
			unsigned char *in, uint32 inlen, unsigned char *out, uint32 outlen,
			void *data)
{
	psAssert(key->type == PS_RSA);
	return psRsaEncryptPub(pool, (psRsaKey_t*)key->key, in, inlen, out, outlen,
			data);
}
#ifdef USE_SERVER_SIDE_SSL
int32 csRsaDecryptPub(psPool_t *pool, psPubKey_t *key, 
			unsigned char *in, uint32 inlen, unsigned char *out, uint32 outlen,
			void *data)
{
	psAssert(key->type == PS_RSA);
	return psRsaDecryptPub(pool, (psRsaKey_t*)key->key, in, inlen, out, outlen,
			data);
}

int32 csRsaEncryptPriv(psPool_t *pool, psPubKey_t *key, 
			unsigned char *in, uint32 inlen, unsigned char *out, uint32 outlen,
			void *data)
{
	psAssert(key->type == PS_RSA);
	return psRsaEncryptPriv(pool, (psRsaKey_t*)key->key, in, inlen, out,
		outlen, data);
}

int32 csRsaDecryptPriv(psPool_t *pool, psPubKey_t *key, 
			unsigned char *in, uint32 inlen, unsigned char *out, uint32 outlen,
			void *data)
{
	psAssert(key->type == PS_RSA);
	return psRsaDecryptPriv(pool, (psRsaKey_t*)key->key, in, inlen, out, outlen,
			data);
}
#endif
#endif /* USE_RSA */



/******************************************************************************/


static sslCipherSpec_t	supportedCiphers[] = {
/*
	New ciphers should be added here, similar to the ones below

	Ciphers are listed in order of greater security at top... this generally
	means the slower ones are on top as well.
*/
#ifdef USE_TLS_1_2
#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		CS_ECDHE_ECDSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3,
		0,			/* macSize */
		32,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt, 
		csAesGcmDecrypt,  
		NULL, 
		NULL},
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		CS_ECDHE_ECDSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA2,
		0,			/* macSize */
		16,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt, 
		csAesGcmDecrypt,  
		NULL, 
		NULL},
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		CS_ECDHE_ECDSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA3,
		48,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 */

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		CS_ECDHE_ECDSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	{TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		CS_ECDHE_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3,
		0,			/* macSize */
		32,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt, 
		csAesGcmDecrypt,  
		NULL, 
		NULL},
#endif /* USE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		CS_ECDHE_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA2,
		0,			/* macSize */
		16,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt, 
		csAesGcmDecrypt,  
		NULL, 
		NULL},
#endif /* USE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		CS_ECDHE_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA3,
		48,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		CS_ECDHE_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 */

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
	{TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
		CS_ECDH_ECDSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3,
		0,			/* macSize */
		32,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt, 
		csAesGcmDecrypt,  
		NULL, 
		NULL},
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 */

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
	{TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
		CS_ECDH_ECDSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA2,
		0,			/* macSize */
		16,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt, 
		csAesGcmDecrypt,  
		NULL, 
		NULL},
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 */

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
	{TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
		CS_ECDH_ECDSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA3,
		48,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 */

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
	{TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
		CS_ECDH_ECDSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 */

#ifdef USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
	{TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
		CS_DHE_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */

#ifdef USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
	{TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
		CS_DHE_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */

#ifdef USE_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
	{TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
		CS_ECDH_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3,
		0,			/* macSize */
		32,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt, 
		csAesGcmDecrypt,  
		NULL, 
		NULL},
#endif /* USE_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 */

#ifdef USE_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
	{TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
		CS_ECDH_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA2,
		0,			/* macSize */
		16,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt, 
		csAesGcmDecrypt,  
		NULL, 
		NULL},
#endif /* USE_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 */

#ifdef USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
	{TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
		CS_ECDH_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA3,
		48,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 */

#ifdef USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
	{TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
		CS_ECDH_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 */

#endif /* USE_TLS_1_2 */


#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		CS_ECDHE_ECDSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */	

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		CS_ECDHE_ECDSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */	

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		CS_ECDHE_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		CS_ECDHE_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */


#ifdef USE_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
	{TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		CS_ECDHE_RSA,
		CRYPTO_FLAGS_3DES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		24,			/* keySize */
		8,			/* ivSize */
		8,			/* blocksize */
		csDes3Init,
		csDes3Encrypt, 
		csDes3Decrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA */


#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
	{TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
		CS_ECDH_ECDSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */	

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
	{TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
		CS_ECDH_ECDSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA */

#ifdef USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
	{TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
		CS_DHE_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	{TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
		CS_DHE_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA */

#ifdef USE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA
	{SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
		CS_DHE_RSA,
		CRYPTO_FLAGS_3DES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		24,			/* keySize */
		8,			/* ivSize */
		8,			/* blocksize */
		csDes3Init,
		csDes3Encrypt, 
		csDes3Decrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA */

#ifdef USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
	{TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
		CS_ECDH_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
	{TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
		CS_ECDH_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA */

#ifdef USE_TLS_1_2
#ifdef USE_TLS_RSA_WITH_AES_256_CBC_SHA256
	{TLS_RSA_WITH_AES_256_CBC_SHA256,
		CS_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif

#ifdef USE_TLS_RSA_WITH_AES_128_CBC_SHA256
	{TLS_RSA_WITH_AES_128_CBC_SHA256,
		CS_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif

#ifdef USE_TLS_RSA_WITH_AES_256_GCM_SHA384
	{TLS_RSA_WITH_AES_256_GCM_SHA384,
		CS_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA3,
		0,			/* macSize */
		32,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt, 
		csAesGcmDecrypt,  
		NULL, 
		NULL},
#endif

#ifdef USE_TLS_RSA_WITH_AES_128_GCM_SHA256
	{TLS_RSA_WITH_AES_128_GCM_SHA256,
		CS_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_GCM | CRYPTO_FLAGS_SHA2,
		0,			/* macSize */
		16,			/* keySize */
		4,			/* ivSize */
		0,			/* blocksize */
		csAesGcmInit,
		csAesGcmEncrypt, 
		csAesGcmDecrypt,  
		NULL, 
		NULL},
#endif
#endif /* USE_TLS_1_2 */

#ifdef USE_TLS_RSA_WITH_AES_256_CBC_SHA
	{TLS_RSA_WITH_AES_256_CBC_SHA,
		CS_RSA,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_RSA_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_RSA_WITH_AES_128_CBC_SHA
	{TLS_RSA_WITH_AES_128_CBC_SHA,
		CS_RSA,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_RSA_WITH_AES_128_CBC_SHA */

#ifdef USE_TLS_RSA_WITH_SEED_CBC_SHA
	{TLS_RSA_WITH_SEED_CBC_SHA,
		CS_RSA,
		CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csSeedInit,
		csSeedEncrypt, 
		csSeedDecrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_SSL_RSA_WITH_SEED_CBC_SHA */

#ifdef USE_TLS_DHE_PSK_WITH_AES_256_CBC_SHA
	{TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
		CS_DHE_PSK,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_DHE_PSK_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_DHE_PSK_WITH_AES_128_CBC_SHA
	{TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
		CS_DHE_PSK,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_DHE_PSK_WITH_AES_128_CBC_SHA */

#ifdef USE_TLS_PSK_WITH_AES_256_CBC_SHA
	{TLS_PSK_WITH_AES_256_CBC_SHA,
		CS_PSK,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_PSK_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_PSK_WITH_AES_128_CBC_SHA
	{TLS_PSK_WITH_AES_128_CBC_SHA,
		CS_PSK,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_PSK_WITH_AES_128_CBC_SHA */

#ifdef USE_TLS_PSK_WITH_AES_128_CBC_SHA256
	{TLS_PSK_WITH_AES_128_CBC_SHA256,
		CS_PSK,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA2,
		32,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_PSK_WITH_AES_128_CBC_SHA256 */

#ifdef USE_TLS_PSK_WITH_AES_256_CBC_SHA384
	{TLS_PSK_WITH_AES_256_CBC_SHA384,
		CS_PSK,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA3,
		48,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_PSK_WITH_AES_256_CBC_SHA384 */

#ifdef USE_SSL_RSA_WITH_3DES_EDE_CBC_SHA
	{SSL_RSA_WITH_3DES_EDE_CBC_SHA,
		CS_RSA,
		CRYPTO_FLAGS_3DES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		24,			/* keySize */
		8,			/* ivSize */
		8,			/* blocksize */
		csDes3Init,
		csDes3Encrypt, 
		csDes3Decrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_SSL_RSA_WITH_3DES_EDE_CBC_SHA */

#ifdef USE_SSL_RSA_WITH_RC4_128_SHA
	{SSL_RSA_WITH_RC4_128_SHA,
		CS_RSA,
		CRYPTO_FLAGS_ARC4INITE | CRYPTO_FLAGS_ARC4INITD | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		0,			/* ivSize */
		1,			/* blocksize */
		csArc4Init,
		csArc4Encrypt, 
		csArc4Decrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_SSL_RSA_WITH_RC4_128_SHA */

#ifdef USE_SSL_RSA_WITH_RC4_128_MD5
	{SSL_RSA_WITH_RC4_128_MD5,
		CS_RSA,
		CRYPTO_FLAGS_ARC4INITE | CRYPTO_FLAGS_ARC4INITD | CRYPTO_FLAGS_MD5,
		16,			/* macSize */
		16,			/* keySize */
		0,			/* ivSize */
		1,			/* blocksize */
		csArc4Init,
		csArc4Encrypt, 
		csArc4Decrypt,  
		csMd5GenerateMac, 
		csMd5VerifyMac},
#endif /* USE_SSL_RSA_WITH_RC4_128_MD5 */

#ifdef USE_TLS_RSA_WITH_IDEA_CBC_SHA
	{TLS_RSA_WITH_IDEA_CBC_SHA,
		CS_RSA,
		CRYPTO_FLAGS_SEED | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		8,			/* ivSize */
		8,			/* blocksize */
		csIdeaInit,
		csIdeaEncrypt,
		csIdeaDecrypt,
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_SSL_RSA_WITH_IDEA_CBC_SHA */

#ifdef USE_TLS_DH_anon_WITH_AES_256_CBC_SHA
	{TLS_DH_anon_WITH_AES_256_CBC_SHA,
		CS_DH_ANON,
		CRYPTO_FLAGS_AES256 | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		32,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_DH_anon_WITH_AES_256_CBC_SHA */

#ifdef USE_TLS_DH_anon_WITH_AES_128_CBC_SHA
	{TLS_DH_anon_WITH_AES_128_CBC_SHA,
		CS_DH_ANON,
		CRYPTO_FLAGS_AES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		16,			/* keySize */
		16,			/* ivSize */
		16,			/* blocksize */
		csAesInit,
		csAesEncrypt, 
		csAesDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_TLS_DH_anon_WITH_AES_128_CBC_SHA */

#ifdef USE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA
	{SSL_DH_anon_WITH_3DES_EDE_CBC_SHA,
		CS_DH_ANON,
		CRYPTO_FLAGS_3DES | CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		24,			/* keySize */
		8,			/* ivSize */
		8,			/* blocksize */
		csDes3Init,
		csDes3Encrypt, 
		csDes3Decrypt,  
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA */

#ifdef USE_SSL_DH_anon_WITH_RC4_128_MD5
	{SSL_DH_anon_WITH_RC4_128_MD5,
		CS_DH_ANON,
		CRYPTO_FLAGS_ARC4INITE | CRYPTO_FLAGS_ARC4INITD | CRYPTO_FLAGS_MD5,
		16,			/* macSize */
		16,			/* keySize */
		0,			/* ivSize */
		1,			/* blocksize */
		csArc4Init,
		csArc4Encrypt, 
		csArc4Decrypt, 
		csMd5GenerateMac, 
		csMd5VerifyMac},
#endif /* USE_SSL_DH_anon_WITH_RC4_128_MD5 */

/*
	These two USE_SSL_RSA_WITH_NULL ciphers are not recommended for use
	in production applications.
*/
#ifdef USE_SSL_RSA_WITH_NULL_SHA
	{SSL_RSA_WITH_NULL_SHA,
		CS_RSA,
		CRYPTO_FLAGS_SHA1,
		20,			/* macSize */
		0,			/* keySize */
		0,			/* ivSize */
		0,			/* blocksize */
		csNullInit,
		csNullEncrypt, 
		csNullDecrypt, 
		csShaGenerateMac, 
		csShaVerifyMac},
#endif /* USE_SSL_RSA_WITH_NULL_SHA */

#ifdef USE_SSL_RSA_WITH_NULL_MD5
	{SSL_RSA_WITH_NULL_MD5,
		CS_RSA,
		CRYPTO_FLAGS_MD5,
		16,			/* macSize */
		0,			/* keySize */
		0,			/* ivSize */
		0,			/* blocksize */
		csNullInit,
		csNullEncrypt, 
		csNullDecrypt,  
		csMd5GenerateMac, 
		csMd5VerifyMac},
#endif /* USE_SSL_RSA_WITH_NULL_MD5 */

/*
	The NULL Cipher suite must exist and be the last in this list
*/
	{SSL_NULL_WITH_NULL_NULL,
		CS_NULL,
		0,
		0,
		0,
		0,
		0,
		csNullInit,
		csNullEncrypt, 
		csNullDecrypt, 
		csNullGenerateMac, 
		csNullVerifyMac}
};

#ifdef USE_SERVER_SIDE_SSL
/******************************************************************************/
/*
	Disable and re-enable ciphers suites on a global or per-session level.
	This is only a server-side feature because the client is always able to
	nominate the specific cipher it wishes to use.  Servers may want to disable
	specific ciphers for a given session (or globally without having to
	rebuild the library).
	
	This function must be called immediately after matrixSslNewServerSession
	
	If ssl is NULL, the setting will be global.  If a cipher is globally
	disabled, the per-session setting will be ignored.
	
	flags:
		PS_TRUE to reenable (always enabled by default if compiled in)
		PS_FALSE to disable cipher suite
*/
int32 matrixSslSetCipherSuiteEnabledStatus(ssl_t *ssl, uint16 cipherId,
			uint32 flags)
{
	uint16	i, j;
	
	if (ssl && !(ssl->flags & SSL_FLAGS_SERVER)) {
		return PS_UNSUPPORTED_FAIL;
	}
	if (flags != PS_TRUE && flags != PS_FALSE) {
		return PS_ARG_FAIL;
	}
	for (i = 0; supportedCiphers[i].ident != SSL_NULL_WITH_NULL_NULL; i++) {
		if (supportedCiphers[i].ident == cipherId) {
			if (ssl == NULL) {
/*
				Global status of cipher suite.  Disabled status takes
				precident over session setting
*/
				if (flags == PS_TRUE) {
					supportedCiphers[i].flags &= ~CRYPTO_FLAGS_DISABLED;
				} else {
					supportedCiphers[i].flags |= CRYPTO_FLAGS_DISABLED;
				}
				return PS_SUCCESS;
			} else {
/*
				Status of this suite for a specific session
*/
				for (j = 0; j < SSL_MAX_DISABLED_CIPHERS; j++) {
					if (flags == PS_FALSE) {
						/* Find first empty spot to add disabled cipher */
						if (ssl->disabledCiphers[j] == 0x0 ||
								ssl->disabledCiphers[j] == cipherId) {
							ssl->disabledCiphers[j] = cipherId;
							return PS_SUCCESS;
						}
					} else {
						if (ssl->disabledCiphers[j] == cipherId) {
							ssl->disabledCiphers[j] = 0x0;
							return PS_SUCCESS;
						}
					}
				}
				if (flags == PS_FALSE) {
					return PS_LIMIT_FAIL; /* No empty spot in disabledCiphers */
				} else {
					/* Tried to re-enabled a cipher that wasn't disabled */
					return PS_SUCCESS; 
				}
			}
		}
	}
	return PS_FAILURE; /* Cipher not found */
}
#endif /* USE_SERVER_SIDE_SSL */

#ifdef VALIDATE_KEY_MATERIAL
#define KEY_ALG_ANY		1
#define KEY_ALG_FIRST	2
/*
	anyOrFirst is basically a determination of whether we are looking through
	a collection of CA files for an algorithm (ANY) or a cert chain where
	we really only care about the child most cert because that is the one
	that ultimately determines the authentication algorithm (FIRST)
*/
static int32 haveCorrectKeyAlg(psX509Cert_t *cert, int32 keyAlg, int anyOrFirst)
{		
	while (cert) {
		if (cert->pubKeyAlgorithm == keyAlg) {
			return PS_SUCCESS;
		}
		if (anyOrFirst == KEY_ALG_FIRST) {
			return PS_FAILURE;
		}
		cert = cert->next;
	}
	return PS_FAILURE;
}

#ifdef USE_SERVER_SIDE_SSL
/*
	This is the signature algorithm that the client will be using to encrypt
	the key material based on what the cipher suite says it should be.
	Only looking at child most cert
*/
static int32 haveCorrectSigAlg(psX509Cert_t *cert, int32 sigType)
{		
	if (sigType == RSA_TYPE_SIG) {
		if (cert->sigAlgorithm == OID_SHA1_RSA_SIG ||
				cert->sigAlgorithm == OID_SHA256_RSA_SIG ||
				cert->sigAlgorithm == OID_SHA384_RSA_SIG ||
				cert->sigAlgorithm == OID_SHA512_RSA_SIG ||
				cert->sigAlgorithm == OID_MD5_RSA_SIG ||
				cert->sigAlgorithm == OID_MD2_RSA_SIG) {
			return PS_SUCCESS;
		}
	} else if (sigType == DSA_TYPE_SIG) {
		if (cert->sigAlgorithm == OID_SHA1_ECDSA_SIG ||
				cert->sigAlgorithm == OID_SHA224_ECDSA_SIG ||
				cert->sigAlgorithm == OID_SHA256_ECDSA_SIG ||
				cert->sigAlgorithm == OID_SHA384_ECDSA_SIG ||
				cert->sigAlgorithm == OID_SHA512_ECDSA_SIG) {
			return PS_SUCCESS;
		}
	}

	return PS_FAILURE;
}
#endif
					
/******************************************************************************/
/*
	Don't report a matching cipher suite if the user hasn't loaded the 
	proper public key material to support it.  We do not check the client
	auth side of the algorithms because that authentication mechanism is
	negotiated within the handshake itself
	
	The annoying #ifdef USE_SERVER_SIDE and CLIENT_SIDE are because the
	structure members only exist one one side or the other and so are used
	for compiling.  You can't actually get into the wrong area of the
	SSL_FLAGS_SERVER test so no #else cases should be needed
 */
static int32 haveKeyMaterial(ssl_t *ssl, int32 cipherType)
{
#ifdef USE_SERVER_SIDE_SSL
	/* If the user has a ServerNameIndication callback registered we're
		going to leave the key material management up to them.  The issue
		here is that we are checking key material for cipher suite support
		before parsing the SNI so the key may change and if the server app
		is advanced enough to have a callback registered then we have to
		trust they know what keys are needed for a specific server request */
	if (ssl->sni_cb) {
		return PS_SUCCESS;
	}
#endif

#ifndef USE_ONLY_PSK_CIPHER_SUITE

	/*	To start, capture all the cipherTypes where servers must have an
		identity and clients have a CA so we don't repeat them everywhere */
	if (cipherType == CS_RSA || cipherType == CS_DHE_RSA ||
			cipherType == CS_ECDHE_RSA || cipherType == CS_ECDH_RSA ||
			cipherType == CS_ECDHE_ECDSA || cipherType == CS_ECDH_ECDSA) {
		if (ssl->flags & SSL_FLAGS_SERVER) {
#ifdef USE_SERVER_SIDE_SSL	
			if (ssl->keys == NULL || ssl->keys->cert == NULL ||
					ssl->keys->privKey == NULL) {
				return PS_FAILURE;
			}
#endif
#ifdef USE_CLIENT_SIDE_SSL
		} else {	
			if (ssl->keys == NULL || ssl->keys->CAcerts == NULL) {
				return PS_FAILURE;
			}
#endif				
		}
	}
	
	/*	Standard RSA ciphers types - auth and exchange */
	if (cipherType == CS_RSA) {
		if (ssl->flags & SSL_FLAGS_SERVER) {
#ifdef USE_SERVER_SIDE_SSL			
			if (haveCorrectKeyAlg(ssl->keys->cert, OID_RSA_KEY_ALG,
					KEY_ALG_FIRST) < 0) {
				return PS_FAILURE;
			}
			if (haveCorrectSigAlg(ssl->keys->cert, RSA_TYPE_SIG) < 0) {
				return PS_FAILURE;
			}
#endif
#ifdef USE_CLIENT_SIDE_SSL			
		} else { /* Client */
		
			if (haveCorrectKeyAlg(ssl->keys->CAcerts, OID_RSA_KEY_ALG,
					KEY_ALG_ANY) < 0) {
				return PS_FAILURE;
			}
#endif			
		}
	}
	
#ifdef USE_DHE_CIPHER_SUITE 
/*
	DHE_RSA ciphers types
*/
	if (cipherType == CS_DHE_RSA) {
		if (ssl->flags & SSL_FLAGS_SERVER) {
#ifdef REQUIRE_DH_PARAMS
			if (ssl->keys->dhParams == NULL) {
				return PS_FAILURE;
			}
#endif			
#ifdef USE_SERVER_SIDE_SSL	
			if (haveCorrectKeyAlg(ssl->keys->cert, OID_RSA_KEY_ALG,
					KEY_ALG_FIRST) < 0) {
				return PS_FAILURE;
			}
#endif	
#ifdef USE_CLIENT_SIDE_SSL				
		} else {
			if (haveCorrectKeyAlg(ssl->keys->CAcerts, OID_RSA_KEY_ALG,
					KEY_ALG_ANY) < 0) {
				return PS_FAILURE;
			}
#endif					
		}	
	}

#ifdef REQUIRE_DH_PARAMS
/*
	Anon DH ciphers don't need much
*/
	if (cipherType == CS_DH_ANON) {
		if (ssl->flags & SSL_FLAGS_SERVER) {
			if (ssl->keys == NULL || ssl->keys->dhParams == NULL) {
				return PS_FAILURE;
			}
		} 
	}
#endif		
	
#ifdef USE_PSK_CIPHER_SUITE
	if (cipherType == CS_DHE_PSK) {
#ifdef REQUIRE_DH_PARAMS	
		if (ssl->flags & SSL_FLAGS_SERVER) {
			if (ssl->keys == NULL || ssl->keys->dhParams == NULL) {
				return PS_FAILURE;
			}
		}
#endif		
		if (ssl->keys == NULL || ssl->keys->pskKeys == NULL) {
			return PS_FAILURE;
		}
	}
#endif	/* USE_PSK_CIPHER_SUITE */
#endif /* USE_DHE_CIPHER_SUITE */	

#ifdef USE_ECC_CIPHER_SUITE /* key exchange */
/*
	ECDHE_RSA ciphers use RSA keys
*/
	if (cipherType == CS_ECDHE_RSA) {
		if (ssl->flags & SSL_FLAGS_SERVER) {
#ifdef USE_SERVER_SIDE_SSL			
			if (haveCorrectKeyAlg(ssl->keys->cert, OID_RSA_KEY_ALG,
					KEY_ALG_FIRST) < 0) {
				return PS_FAILURE;
			}
			if (haveCorrectSigAlg(ssl->keys->cert, RSA_TYPE_SIG) < 0) {
				return PS_FAILURE;
			}
#endif			
#ifdef USE_CLIENT_SIDE_SSL
		} else {
			if (haveCorrectKeyAlg(ssl->keys->CAcerts, OID_RSA_KEY_ALG,
					KEY_ALG_ANY) < 0) {
				return PS_FAILURE;
			}
#endif
		}
	}

/*
	ECDH_RSA ciphers use ECDSA key exhange and RSA auth.
*/
	if (cipherType == CS_ECDH_RSA) {
		if (ssl->flags & SSL_FLAGS_SERVER) {
#ifdef USE_SERVER_SIDE_SSL		
			if (haveCorrectKeyAlg(ssl->keys->cert, OID_ECDSA_KEY_ALG,
					KEY_ALG_FIRST) < 0) {
				return PS_FAILURE;
			}
			if (haveCorrectSigAlg(ssl->keys->cert, RSA_TYPE_SIG) < 0) {
				return PS_FAILURE;
			}
#endif			
#ifdef USE_CLIENT_SIDE_SSL
		} else {
			if (haveCorrectKeyAlg(ssl->keys->CAcerts, OID_RSA_KEY_ALG,
					KEY_ALG_ANY) < 0) {
				return PS_FAILURE;
			}
#endif
		}
	}


/*
	ECDHE_ECDSA and ECDH_ECDSA ciphers must have ECDSA keys
*/
	if (cipherType == CS_ECDHE_ECDSA || cipherType == CS_ECDH_ECDSA) {
		if (ssl->flags & SSL_FLAGS_SERVER) {
#ifdef USE_SERVER_SIDE_SSL		
			if (haveCorrectKeyAlg(ssl->keys->cert, OID_ECDSA_KEY_ALG,
					KEY_ALG_FIRST) < 0) {
				return PS_FAILURE;
			}
			if (haveCorrectSigAlg(ssl->keys->cert, DSA_TYPE_SIG) < 0) {
				return PS_FAILURE;
			}
#endif		
#ifdef USE_CLIENT_SIDE_SSL
		} else {
			if (haveCorrectKeyAlg(ssl->keys->CAcerts, OID_ECDSA_KEY_ALG,
					KEY_ALG_ANY) < 0) {
				return PS_FAILURE;
			}
#endif
		}	
	}
#endif /* USE_ECC_CIPHER_SUITE */
#endif /* USE_ONLY_PSK_CIPHER_SUITE	*/

#ifdef USE_PSK_CIPHER_SUITE
	if (cipherType == CS_PSK) {
		if (ssl->keys == NULL || ssl->keys->pskKeys == NULL) {
			return PS_FAILURE;
		}
	}
#endif	/* USE_PSK_CIPHER_SUITE */
	 
	return PS_SUCCESS;
}
#endif /* VALIDATE_KEY_MATERIAL */

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#ifdef USE_ECC_CIPHER_SUITE
/*	
	See if any of the EC suites are supported.  Needed by client very early on
	to know whether or not to add the EC client hello extensions
*/
int32 eccSuitesSupported(ssl_t *ssl, uint16 cipherSpecLen,
		uint32 cipherSpecs[])
{
	int32	i = 0;
	
	if (cipherSpecLen == 0) {
		if (sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA) || 
				sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA) ||
				sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA) ||
				sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA) ||
				sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA) ||
#ifdef USE_TLS_1_2
				sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)||
				sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384)||
				sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256) ||
				sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384) ||
				sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256) ||
				sslGetCipherSpec(ssl, TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)||
				sslGetCipherSpec(ssl, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)||
				sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) ||
				sslGetCipherSpec(ssl, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) ||
				sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256) ||
				sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384) ||
				sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256) ||
				sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384) ||
#endif			
				sslGetCipherSpec(ssl, TLS_ECDH_RSA_WITH_AES_128_CBC_SHA)) {
			return 1;
		}
	} else {
		while (i < cipherSpecLen) {
			if (cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA ||
					cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA ||
					cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA ||
					cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA ||
					cipherSpecs[i] == TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA ||
					cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA ||
					cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA ||
					cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_256_CBC_SHA ||
#ifdef USE_TLS_1_2
					cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 ||
					cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 ||
					cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 ||
					cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 ||
					cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 ||
					cipherSpecs[i] == TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 ||
					cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
					cipherSpecs[i] == TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ||
					cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ||
					cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 ||
					cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
					cipherSpecs[i] == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
					cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 ||
					cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 ||
					cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 ||
					cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 ||
#endif			
					cipherSpecs[i] == TLS_ECDH_RSA_WITH_AES_128_CBC_SHA) {
				return 1;
			}
			i++;
		}
	}
	return 0;
}
#endif /* USE_ECC_CIPHER_SUITE */

#ifdef USE_CLIENT_SIDE_SSL
/* Test if agreed upon cipher suite authentication is being adhered to */
int32 csCheckCertAgainstCipherSuite(int32 sigAlg, int32 cipherType)
{
	if (sigAlg == OID_MD5_RSA_SIG || sigAlg == OID_SHA1_RSA_SIG ||
			sigAlg == OID_SHA256_RSA_SIG || sigAlg == OID_SHA384_RSA_SIG ||
			sigAlg == OID_SHA512_RSA_SIG) {
		if (cipherType == CS_DHE_RSA || cipherType == CS_RSA ||
				cipherType == CS_ECDHE_RSA || cipherType == CS_ECDH_RSA) {
			return 1;
		}
	}
	if (sigAlg == OID_SHA1_ECDSA_SIG || sigAlg == OID_SHA224_ECDSA_SIG ||
			sigAlg == OID_SHA256_ECDSA_SIG || sigAlg == OID_SHA384_ECDSA_SIG ||
			sigAlg == OID_SHA512_ECDSA_SIG) {
		if (cipherType == CS_ECDHE_ECDSA || cipherType == CS_ECDH_ECDSA) {
			return 1;
		}

	}
	return 0; /* no match */
}
#endif /* USE_CLIENT_SIDE_SSL */
#endif /* USE_ONLY_PSK_CIPHER_SUITE */

/******************************************************************************/
/*
	Lookup the given cipher spec ID and return a pointer to the structure
	if found.  This is used when negotiating security, to find out what suites
	we support.
*/
sslCipherSpec_t *sslGetCipherSpec(ssl_t *ssl, uint32 id)
{
	int16	i;
#ifdef USE_SERVER_SIDE_SSL
	int16	j;
#endif /* USE_SERVER_SIDE_SSL */

	i = 0;
	do {
		if (supportedCiphers[i].ident == id) {
#ifdef USE_SERVER_SIDE_SSL		
			/* Globally disabled? */
			if (supportedCiphers[i].flags & CRYPTO_FLAGS_DISABLED) {
				psTraceIntInfo("Matched cipher suite %d but disabled by user\n",
					id);
				return NULL;
			}
			/* Disabled for session? */
			if (id != 0) { /* Disable NULL_WITH_NULL_NULL not possible */
				for (j = 0; j < SSL_MAX_DISABLED_CIPHERS; j++) {
					if (ssl->disabledCiphers[j] == id) {
						psTraceIntInfo("Matched cipher suite %d but disabled by user\n",
							id);
						return NULL;
					}
				}
			}
#endif /* USE_SERVER_SIDE_SSL */
#ifdef USE_TLS_1_2
			/* Unusable because protocol doesn't allow? */
			if (ssl->minVer != TLS_1_2_MIN_VER) {
				if (supportedCiphers[i].flags & CRYPTO_FLAGS_SHA3 ||
						supportedCiphers[i].flags & CRYPTO_FLAGS_SHA2) {
					psTraceIntInfo("Matched cipher suite %d but only allowed in TLS 1.2\n",
							id);
					return NULL;
				}
			}
			
			if (ssl->minVer == TLS_1_2_MIN_VER) {
				if (supportedCiphers[i].flags & CRYPTO_FLAGS_MD5) {
					psTraceIntInfo("Not allowing MD5 suite %d in TLS 1.2\n",
						id);
					return NULL;
				}
			}
#endif /* TLS_1_2 */
			/*	Unusable due to key material not available? */
#ifdef VALIDATE_KEY_MATERIAL
			if (haveKeyMaterial(ssl, supportedCiphers[i].type) == PS_SUCCESS) {
				return &supportedCiphers[i];
			}
			psTraceIntInfo("Matched cipher suite %d but no supporting keys\n",
				id);
#else
			return &supportedCiphers[i];
#endif /* VALIDATE_KEY_MATERIAL */
		}
	} while (supportedCiphers[i++].ident != SSL_NULL_WITH_NULL_NULL) ;

	return NULL;
}


/******************************************************************************/
/*
	Write out a list of the supported cipher suites to the caller's buffer
	First 2 bytes are the number of cipher suite bytes, the remaining bytes are
	the cipher suites, as two byte, network byte order values.
*/
int32 sslGetCipherSpecList(ssl_t *ssl, unsigned char *c, int32 len,
		int32 addScsv)
{
	unsigned char	*end, *p;
	unsigned short	i;
	int32			ignored;

	if (len < 4) {
		return -1;
	}
	end = c + len;
	p = c; c += 2;
	
	ignored = 0;
	for (i = 0; supportedCiphers[i].ident != SSL_NULL_WITH_NULL_NULL; i++) {
		if (end - c < 2) {
			return -1;
		}
#ifdef USE_TLS_1_2
		/* The SHA-2 based cipher suites are TLS 1.2 only so don't send
			those if the user has requested a lower protocol in
			NewClientSession */
		if (ssl->minVer != TLS_1_2_MIN_VER) {
			if (supportedCiphers[i].flags & CRYPTO_FLAGS_SHA3 ||
					supportedCiphers[i].flags & CRYPTO_FLAGS_SHA2) {
				ignored += 2;
				continue;
			}
		}
#endif	/* TLS_1_2 */
#ifdef VALIDATE_KEY_MATERIAL
		if (haveKeyMaterial(ssl, supportedCiphers[i].type) != PS_SUCCESS) {
			ignored += 2;
			continue;
		}
#endif 		
		*c = (unsigned char)((supportedCiphers[i].ident & 0xFF00) >> 8); c++;
		*c = (unsigned char)(supportedCiphers[i].ident & 0xFF); c++;
	}
	i *= 2;
	i -= (unsigned short)ignored;
#ifdef ENABLE_SECURE_REHANDSHAKES
	if (addScsv == 1) {
		*c = ((TLS_EMPTY_RENEGOTIATION_INFO_SCSV & 0xFF00) >> 8); c++;
		*c = TLS_EMPTY_RENEGOTIATION_INFO_SCSV  & 0xFF; c++;
		i += 2;
	}
#endif	
	*p = (unsigned char)(i >> 8); p++;
	*p = (unsigned char)(i & 0xFF);
	return i + 2;
}

/******************************************************************************/
/*
	Return the length of the cipher spec list, including initial length bytes,
	(minus any suites that we don't have the key material to support)
*/
int32 sslGetCipherSpecListLen(ssl_t *ssl)
{
	int32	i, ignored;

	ignored = 0;
	for (i = 0; supportedCiphers[i].ident != SSL_NULL_WITH_NULL_NULL; i++) {
#ifdef USE_TLS_1_2
		/* The SHA-2 based cipher suites are TLS 1.2 only so don't send
			those if the user has requested a lower protocol in
			NewClientSession */
		if (ssl->minVer != TLS_1_2_MIN_VER) {
			if (supportedCiphers[i].flags & CRYPTO_FLAGS_SHA3 ||
					supportedCiphers[i].flags & CRYPTO_FLAGS_SHA2) {
				ignored += 2;
				continue;
			}
		}
#endif	/* USE_TLS_1_2 */
#ifdef VALIDATE_KEY_MATERIAL
		if (haveKeyMaterial(ssl, supportedCiphers[i].type) != PS_SUCCESS) {
			ignored += 2;
		}
#endif 	
	}
	return (i * 2) + 2 - ignored;
}

/******************************************************************************/
/*
	Flag the session based on the agreed upon cipher suite
	NOTE: sslResetContext will have cleared these flags for re-handshakes
*/
void matrixSslSetKexFlags(ssl_t *ssl)
{

#ifdef USE_DHE_CIPHER_SUITE
/*
	Flag the specific DH ciphers so the correct key exchange
	mechanisms can be used.  And because DH changes the handshake
	messages as well.
*/
	if (ssl->cipher->type == CS_DHE_RSA) {
		ssl->flags |= SSL_FLAGS_DHE_KEY_EXCH;
		ssl->flags |= SSL_FLAGS_DHE_WITH_RSA;
	}

#ifdef USE_PSK_CIPHER_SUITE
/*
	Set the PSK flags and DH kex.
	NOTE:  Although this isn't technically a DH_anon cipher, the handshake
	message order for DHE_PSK are identical and we can nicely piggy back
	on the handshake logic that already exists.
*/
	if (ssl->cipher->type == CS_DHE_PSK) {
		ssl->flags |= SSL_FLAGS_DHE_KEY_EXCH;
		ssl->flags |= SSL_FLAGS_ANON_CIPHER;
		ssl->flags |= SSL_FLAGS_PSK_CIPHER;
#ifdef USE_CLIENT_AUTH
		if (ssl->flags & SSL_FLAGS_SERVER) {
			if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
				psTraceInfo("No client auth TLS mode for DHE_PSK ciphers");
				psTraceInfo(". Disabling CLIENT_AUTH.\n");
				ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
			}
		}
#endif /* USE_CLIENT_AUTH */		
	}
#endif /* USE_PSK_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE
	if (ssl->cipher->type == CS_ECDHE_RSA) {
		ssl->flags |= SSL_FLAGS_ECC_CIPHER;
		ssl->flags |= SSL_FLAGS_DHE_KEY_EXCH;
		ssl->flags |= SSL_FLAGS_DHE_WITH_RSA;
	}
	if (ssl->cipher->type == CS_ECDHE_ECDSA) {
		ssl->flags |= SSL_FLAGS_ECC_CIPHER;
		ssl->flags |= SSL_FLAGS_DHE_KEY_EXCH;
		ssl->flags |= SSL_FLAGS_DHE_WITH_DSA;
	}
#endif /* USE_ECC_CIPHER_SUITE */

#ifdef USE_ANON_DH_CIPHER_SUITE
	if (ssl->cipher->type == CS_DH_ANON) {
		ssl->flags |= SSL_FLAGS_DHE_KEY_EXCH;
		ssl->flags |= SSL_FLAGS_ANON_CIPHER;
		ssl->sec.anon = 1;
	}
#endif /* USE_ANON_DH_CIPHER_SUITE */
#endif /* USE_DHE_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE
	if (ssl->cipher->type == CS_ECDH_ECDSA) {
		ssl->flags |= SSL_FLAGS_ECC_CIPHER;
	}
	if (ssl->cipher->type == CS_ECDH_RSA) {
		ssl->flags |= SSL_FLAGS_ECC_CIPHER;
	}
#endif /* USE_ECC_CIPHER_SUITE */

#ifdef USE_PSK_CIPHER_SUITE
	if (ssl->cipher->type == CS_PSK) {
		ssl->flags |= SSL_FLAGS_PSK_CIPHER;
#ifdef USE_CLIENT_AUTH
		if (ssl->flags & SSL_FLAGS_SERVER) {
			if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
				psTraceInfo("No client auth TLS mode for basic PSK ciphers");
				psTraceInfo(". Disabling CLIENT_AUTH.\n");
				ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
			}
		}
#endif /* USE_CLIENT_AUTH */
	} 
#endif /* USE_PSK_CIPHER_SUITE	*/

	return;
}
/******************************************************************************/

