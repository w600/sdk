/*
 *	hmac.c
 *	Release $Name: MATRIXSSL-3-6-1-OPEN $
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

#include "../cryptoApi.h"
#include "../cryptocore.h"
#if TLS_CONFIG_HARD_CRYPTO
#include "wm_crypto_hard.h"
#endif
/******************************************************************************/
#ifdef USE_HMAC


/******************************************************************************/

#if !defined(USE_MD5) && !defined(USE_SHA1)
	#error "Must enable USE_MD5 and/or USE_SHA1 if enabling USE_HMAC"
#endif

/******************************************************************************/
#ifdef USE_MD5
/******************************************************************************/
/*
	HMAC-MD5
	http://www.faqs.org/rfcs/rfc2104.html

	the HMAC_MD5 transform looks like:

		MD5(K XOR opad, MD5(K XOR ipad, text))
       
		where K is an n byte key
		ipad is the byte 0x36 repeated 64 times

		opad is the byte 0x5c repeated 64 times
		and text is the data being protected

	If the keyLen is > 64 bytes, we hash the key and use it instead
*/
int32 psHmacMd5(unsigned char *key, uint32 keyLen, 
				const unsigned char *buf, uint32 len, unsigned char *hash,
				unsigned char *hmacKey, uint32 *hmacKeyLen)
{
	psHmacContext_t		ctx;
	psDigestContext_t	md;
/*
	Support for keys larger than 64 bytes.  In this case, we take the
	hash of the key itself and use that instead.  Inform the caller by
	updating the hmacKey and hmacKeyLen outputs
*/
	if (keyLen > 64) {
		psMd5Init(&md);
		psMd5Update(&md, key, keyLen);
		psMd5Final(&md, hash);
		*hmacKeyLen = MD5_HASH_SIZE;
		memcpy(hmacKey, hash, *hmacKeyLen);
	} else {
		hmacKey = key;
		*hmacKeyLen = keyLen;
	}

	psHmacMd5Init(&ctx, hmacKey, *hmacKeyLen);
	psHmacMd5Update(&ctx, buf, len);
	return psHmacMd5Final(&ctx, hash);
}

void psHmacMd5Init(psHmacContext_t *ctx, unsigned char *key, uint32 keyLen)
{
	int32				i;

	psAssert(keyLen <= 64);

	for (i = 0; (uint32)i < keyLen; i++) {
		ctx->pad[i] = key[i] ^ 0x36;
	}
	for (i = keyLen; i < 64; i++) {
		ctx->pad[i] = 0x36;
	}
	psMd5Init(&ctx->u.md5);
	psMd5Update(&ctx->u.md5, ctx->pad, 64);
	for (i = 0; (uint32)i < keyLen; i++) {
		ctx->pad[i] = key[i] ^ 0x5c;
	}
	for (i = keyLen; i < 64; i++) {
		ctx->pad[i] = 0x5c;
	}
}

void psHmacMd5Update(psHmacContext_t *ctx, const unsigned char *buf, uint32 len)
{
	psAssert(ctx != NULL && buf != NULL);

	psMd5Update(&ctx->u.md5, buf, len);
}

int32 psHmacMd5Final(psHmacContext_t *ctx, unsigned char *hash)
{
	psAssert(ctx != NULL);
	if (hash == NULL) {
		psTraceCrypto("NULL hash storage passed to psHmacMd5Final\n");
		return PS_ARG_FAIL;
	}
	psMd5Final(&ctx->u.md5, hash);

	psMd5Init(&ctx->u.md5);
	psMd5Update(&ctx->u.md5, ctx->pad, 64);
	psMd5Update(&ctx->u.md5, hash, MD5_HASH_SIZE);
	psMd5Final(&ctx->u.md5, hash);

	memset(ctx->pad, 0x0, 64);
	return MD5_HASH_SIZE;
}

#endif /* USE_MD5 */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_SHA1
/******************************************************************************/
/*
	HMAC-SHA1
	http://www.faqs.org/rfcs/rfc2104.html
*/

int32 psHmacSha1(unsigned char *key, uint32 keyLen, const unsigned char *buf,
				uint32 len, unsigned char *hash, unsigned char *hmacKey,
				uint32 *hmacKeyLen)
{
	psHmacContext_t		ctx;
	psDigestContext_t	sha;
/*
	Support for keys larger than 64 bytes.  In this case, we take the
	hash of the key itself and use that instead.  Inform the caller by
	updating the hmacKey and hmacKeyLen outputs
*/
	if (keyLen > 64) {
		psSha1Init(&sha);
		psSha1Update(&sha, key, keyLen);
		psSha1Final(&sha, hash);
		*hmacKeyLen = SHA1_HASH_SIZE;
		memcpy(hmacKey, hash, *hmacKeyLen);
	} else {
		hmacKey = key;
		*hmacKeyLen = keyLen;
	}

	psHmacSha1Init(&ctx, hmacKey, *hmacKeyLen);
	psHmacSha1Update(&ctx, buf, len);
	return psHmacSha1Final(&ctx, hash);
}

void psHmacSha1Init(psHmacContext_t *ctx, unsigned char *key, uint32 keyLen)
{
	int32	i;

	psAssert(keyLen <= 64);

	for (i = 0; (uint32)i < keyLen; i++) {
		ctx->pad[i] = key[i] ^ 0x36;
	}
	for (i = keyLen; (uint32)i < 64; i++) {
		ctx->pad[i] = 0x36;
	}
	psSha1Init(&ctx->u.sha1);
	psSha1Update(&ctx->u.sha1, ctx->pad, 64);
	for (i = 0; (uint32)i < keyLen; i++) {
		ctx->pad[i] = key[i] ^ 0x5c;
	}
	for (i = keyLen; i < 64; i++) {
		ctx->pad[i] = 0x5c;
	}
}

void psHmacSha1Update(psHmacContext_t *ctx, const unsigned char *buf,
						uint32 len)
{
	psAssert(ctx != NULL && buf != NULL);

	psSha1Update(&ctx->u.sha1, buf, len);
}

int32 psHmacSha1Final(psHmacContext_t *ctx, unsigned char *hash)
{
	psAssert(ctx != NULL);
	if (hash == NULL) {
		psTraceCrypto("NULL hash storage passed to psHmacSha1Final\n");
		return PS_ARG_FAIL;
	}
	psSha1Final(&ctx->u.sha1, hash);

	psSha1Init(&ctx->u.sha1);
	psSha1Update(&ctx->u.sha1, ctx->pad, 64);
	psSha1Update(&ctx->u.sha1, hash, SHA1_HASH_SIZE);
	psSha1Final(&ctx->u.sha1, hash);

	memset(ctx->pad, 0x0, 64);
	return SHA1_HASH_SIZE;
}

#endif /* USE_SHA1 */
/******************************************************************************/
#ifdef USE_SHA256
/******************************************************************************/
/*
	HMAC-SHA256
*/

int32 psHmacSha2(unsigned char *key, uint32 keyLen, const unsigned char *buf,
				uint32 len, unsigned char *hash, unsigned char *hmacKey,
				uint32 *hmacKeyLen, uint32 hashSize)
{
	psHmacContext_t		ctx;
	psDigestContext_t	sha;
	int32				padLen = 64;

#ifdef USE_SHA384
	if (hashSize == SHA384_HASH_SIZE) {
		padLen = 128;
	}
#endif
/*
	Support for keys larger than hash block size.  In this case, we take the
	hash of the key itself and use that instead.  Inform the caller by
	updating the hmacKey and hmacKeyLen outputs
*/
	if (keyLen > (uint32)padLen) {
		if (hashSize == SHA384_HASH_SIZE) {
#ifdef USE_SHA384		
			psSha384Init(&sha);
			psSha384Update(&sha, key, keyLen);
			psSha384Final(&sha, hash);
#else
			return PS_UNSUPPORTED_FAIL;
#endif			
		} else {
			psSha256Init(&sha);
			psSha256Update(&sha, key, keyLen);
			psSha256Final(&sha, hash);
		}
		*hmacKeyLen = hashSize;
		memcpy(hmacKey, hash, *hmacKeyLen);
	} else {
		hmacKey = key;
		*hmacKeyLen = keyLen;
	}
	
	psHmacSha2Init(&ctx, hmacKey, *hmacKeyLen, hashSize);
	psHmacSha2Update(&ctx, buf, len, hashSize);
	return psHmacSha2Final(&ctx, hash, hashSize);
}

void psHmacSha2Init(psHmacContext_t *ctx, unsigned char *key, uint32 keyLen,
				uint32 hashSize)
{
	int32	i, padLen = 64;

#ifdef USE_SHA384
	if (hashSize == SHA384_HASH_SIZE) {
		padLen = 128;
	}
#endif

	psAssert(keyLen <= (uint32)padLen);

	for (i = 0; (uint32)i < keyLen; i++) {
		ctx->pad[i] = key[i] ^ 0x36;
	}
	for (i = keyLen; i < padLen; i++) {
		ctx->pad[i] = 0x36;
	}
	if (hashSize == SHA384_HASH_SIZE) {
#ifdef USE_SHA384	
		psSha384Init(&ctx->u.sha512);
		psSha384Update(&ctx->u.sha512, ctx->pad, padLen);
#endif		
	} else {
		psSha256Init(&ctx->u.sha256);
		psSha256Update(&ctx->u.sha256, ctx->pad, padLen);
	}
	for (i = 0; (uint32)i < keyLen; i++) {
		ctx->pad[i] = key[i] ^ 0x5c;
	}
	for (i = keyLen; i < padLen; i++) {
		ctx->pad[i] = 0x5c;
	}
}

void psHmacSha2Update(psHmacContext_t *ctx, const unsigned char *buf,
						uint32 len, uint32 hashSize)
{
	psAssert(ctx != NULL && buf != NULL);
	
	if (hashSize == SHA384_HASH_SIZE) {
#ifdef USE_SHA384	
		psSha384Update(&ctx->u.sha512, buf, len);
#endif		
	} else {
		psSha256Update(&ctx->u.sha256, buf, len);
	}
}

int32 psHmacSha2Final(psHmacContext_t *ctx, unsigned char *hash,
						uint32 hashSize)
{
	psAssert(ctx != NULL);
	if (hash == NULL) {
		psTraceCrypto("NULL hash storage passed to psHmacSha256Final\n");
		return PS_ARG_FAIL;
	}
	if (hashSize == SHA384_HASH_SIZE) {
#ifdef USE_SHA384	
		psSha384Final(&ctx->u.sha512, hash);

		psSha384Init(&ctx->u.sha512);
		psSha384Update(&ctx->u.sha512, ctx->pad, 128);
		psSha384Update(&ctx->u.sha512, hash, SHA384_HASH_SIZE);
		psSha384Final(&ctx->u.sha512, hash);
#else
		return PS_UNSUPPORTED_FAIL;
#endif			
	} else {
		psSha256Final(&ctx->u.sha256, hash);

		psSha256Init(&ctx->u.sha256);
		psSha256Update(&ctx->u.sha256, ctx->pad, 64);
		psSha256Update(&ctx->u.sha256, hash, SHA256_HASH_SIZE);
		psSha256Final(&ctx->u.sha256, hash);
	}

	memset(ctx->pad, 0x0, 64);
	return hashSize;
}

#endif /* USE_SHA256 */


#endif /* USE_HMAC */
/******************************************************************************/

