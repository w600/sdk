/*
 *	cryptoApi.h
 *	Release $Name: MATRIXSSL-3-6-1-OPEN $
 *
 *	Prototypes for the Matrix crypto public APIs
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

#ifndef _h_PS_CRYPTOAPI
#define _h_PS_CRYPTOAPI

#include "core/osdep.h"
//#include "core/coreApi.h" /* Must be first included */
#include "cryptoConfig.h" /* Must be second included */
#include "cryptolib.h"
#include "wm_crypto_hard.h"
/******************************************************************************/
/*	Public return codes */
/******************************************************************************/
/*	Failure codses MUST be < 0  */
/*	NOTE: The range for crypto error codes must be between -30 and -49  */
#define	PS_PARSE_FAIL			-31

/*
	PS NOTE:  Any future additions to certificate authentication failures
	must be carried through to MatrixSSL code
*/	
#define PS_CERT_AUTH_PASS			PS_TRUE
#define	PS_CERT_AUTH_FAIL_BC		-32 /* BasicConstraint failure */
#define	PS_CERT_AUTH_FAIL_DN		-33 /* DistinguishedName failure */
#define	PS_CERT_AUTH_FAIL_SIG		-34 /* Signature validation failure */
#define PS_CERT_AUTH_FAIL_REVOKED	-35 /* Revoked via CRL */
#define	PS_CERT_AUTH_FAIL			-36 /* Generic cert auth fail */
#define PS_CERT_AUTH_FAIL_EXTENSION -37 /* extension permission problem */
#define PS_CERT_AUTH_FAIL_PATH_LEN	-38 /* pathLen exceeded */
#define PS_CERT_AUTH_FAIL_AUTHKEY	-39 /* subjectKeyid != issuer authKeyid */

#define PS_SIGNATURE_MISMATCH	-40 /* Alorithms all work but sig not a match */

/* Set as authStatusFlags to certificate callback when authStatus
	is PS_CERT_AUTH_FAIL_EXTENSION */
#define PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG	0x01
#define PS_CERT_AUTH_FAIL_EKU_FLAG			0x02
#define PS_CERT_AUTH_FAIL_SUBJECT_FLAG		0x04
#define PS_CERT_AUTH_FAIL_DATE_FLAG			0x08

/******************************************************************************/
#if 0
#if defined PSTM_X86 || defined PSTM_X86_64 || defined PSTM_ARM || \
    defined PSTM_MIPS
 #define PSTM_ASM_CONFIG_STR "Y"
#else
 #define PSTM_ASM_CONFIG_STR "N"
#endif
#ifdef PSTM_64BIT
 #define PSTM_64_CONFIG_STR "Y"
#else
 #define PSTM_64_CONFIG_STR "N"
#endif
#ifdef USE_AESNI_CRYPTO
 #define AESNI_CONFIG_STR "Y"
#else
 #define AESNI_CONFIG_STR "N"
#endif
 #define HW_PKA_CONFIG_STR "N"
#ifdef USE_PKCS11
 #define PKCS11_CONFIG_STR "Y"
#else
 #define PKCS11_CONFIG_STR "N"
#endif
 #define FIPS_CONFIG_STR "N"

#define PSCRYPTO_CONFIG \
    "Y" \
    PSTM_ASM_CONFIG_STR \
    PSTM_64_CONFIG_STR \
    AESNI_CONFIG_STR \
	HW_PKA_CONFIG_STR \
    PKCS11_CONFIG_STR \
    FIPS_CONFIG_STR

/******************************************************************************/
/* Public APIs */
/******************************************************************************/

PSPUBLIC int32 psCryptoOpen(char *config);
PSPUBLIC void psCryptoClose(void);
#endif

#ifdef USE_AES

#ifdef USE_AES_GCM
PSPUBLIC int32 psAesInitGCM(psCipherContext_t *ctx, unsigned char *key,
				int32 keylen);
PSPUBLIC int32 psAesReadyGCM(psCipherContext_t *ctx, unsigned char *IV,
					unsigned char *aad,	int32 aadLen);				
PSPUBLIC int32 psAesEncryptGCM(psCipherContext_t *ctx, unsigned char *pt,
			unsigned char *ct, int32 len);
PSPUBLIC int32 psAesGetGCMTag(psCipherContext_t *ctx, int32 TagBytes,
			unsigned char *tag);
PSPUBLIC int32 psAesDecryptGCM(psCipherContext_t *ctx, unsigned char *ct,
			int32 ctLen, unsigned char *pt, int32 ptLen);
PSPUBLIC int32 psAesDecryptGCMtagless(psCipherContext_t *ctx, unsigned char *ct,
			unsigned char *pt, int32 len);
 
#endif /* USE_AES_GCM */	



#endif /* USE_AES */
/******************************************************************************/

#ifdef USE_SEED
/******************************************************************************/
PSPUBLIC int32 psSeedInit(psCipherContext_t *ctx, unsigned char *IV,
						unsigned char *key, uint32 keylen);
PSPUBLIC int32 psSeedDecrypt(psCipherContext_t *ctx, unsigned char *ct,
						unsigned char *pt, uint32 len);
PSPUBLIC int32 psSeedEncrypt(psCipherContext_t *ctx, unsigned char *pt,
						unsigned char *ct, uint32 len);

PSPUBLIC int32 psSeedInitKey(const unsigned char *key, uint32 keylen,
						psSeedKey_t *skey);
PSPUBLIC void psSeedEncryptBlock(const unsigned char *pt, unsigned char *ct,
						psSeedKey_t *skey);
PSPUBLIC void psSeedDecryptBlock(const unsigned char *ct, unsigned char *pt,
						psSeedKey_t *skey);
#endif /* USE_SEED */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_3DES
/******************************************************************************/
/*
	CBC Mode DES3 
*/
#if !TLS_CONFIG_HARD_CRYPTO
PSPUBLIC int32 psDes3Init(psCipherContext_t *ctx, unsigned char *IV,
						unsigned char *key, uint32 keylen);
PSPUBLIC int32 psDes3Decrypt(psCipherContext_t *ctx, unsigned char *ct,
						unsigned char *pt, uint32 len);
PSPUBLIC int32 psDes3Encrypt(psCipherContext_t *ctx, unsigned char *pt,
						unsigned char *ct, uint32 len);
#else
#define psDes3Init(ctx, IV, key, keylen)    tls_crypto_3des_init(ctx, IV, key, keylen, CRYPTO_MODE_CBC)
#define psDes3Decrypt(ctx, ct, pt, len)  tls_crypto_3des_encrypt_decrypt(ctx, ct, pt, len, CRYPTO_WAY_DECRYPT)   
#define psDes3Encrypt(ctx, pt, ct, len)  tls_crypto_3des_encrypt_decrypt(ctx, pt, ct, len, CRYPTO_WAY_ENCRYPT)
#endif
/*
	Block Mode DES3 
*/
PSPUBLIC int32 psDes3InitKey(const unsigned char *key, uint32 keylen,
						psDes3Key_t *skey);
PSPUBLIC void psDes3EncryptBlock(const unsigned char *pt, unsigned char *ct,
						psDes3Key_t *skey);
PSPUBLIC void psDes3DecryptBlock(const unsigned char *ct, unsigned char *pt,
						psDes3Key_t *skey);
#endif /* USE_3DES */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_DES
PSPUBLIC int32 psDesInitKey(const unsigned char *key, int32 keylen,
						psDes3Key_t *skey);
PSPUBLIC void psDesEncryptBlock(const unsigned char *pt, unsigned char *ct,
						psDes3Key_t *skey);
PSPUBLIC void psDesDecryptBlock(const unsigned char *ct, unsigned char *pt,
						psDes3Key_t *skey);
#endif /* USE_DES */
/******************************************************************************/

#ifdef USE_IDEA
/******************************************************************************/
/*
	CBC Mode IDEA
*/
PSPUBLIC int32 psIdeaInit(psCipherContext_t *ctx, unsigned char *IV,
						unsigned char *key, uint32 keylen);
PSPUBLIC int32 psIdeaDecrypt(psCipherContext_t *ctx, unsigned char *ct,
						unsigned char *pt, uint32 len);
PSPUBLIC int32 psIdeaEncrypt(psCipherContext_t *ctx, unsigned char *pt,
						unsigned char *ct, uint32 len);
#endif

/******************************************************************************/
#ifdef USE_ARC4
#if 1//!TLS_CONFIG_HARD_CRYPTO
#if 0
PSPUBLIC void psArc4Init(psCipherContext_t *ctx, unsigned char *key,
						uint32 keylen);
PSPUBLIC int32 psArc4(psCipherContext_t *ctx, unsigned char *in,
						unsigned char *out, uint32 len);
#else
#include "rc4.h"
#define psArc4Init Arc4Init
#define psArc4(ctx, in, out, len) Arc4_skip(ctx, in, out, 0, len)
#endif
#else
#define psArc4Init tls_crypto_rc4_init
#define psArc4(ctx, in, out, len) tls_crypto_rc4(ctx, in, out, len)
#endif
#endif /* USE_ARC4 */
/******************************************************************************/

#ifdef USE_RC2
/******************************************************************************/
PSPUBLIC int32 psRc2Init(psCipherContext_t *ctx, unsigned char *IV,
						unsigned char *key, uint32 keylen);
PSPUBLIC int32 psRc2Decrypt(psCipherContext_t *ctx, unsigned char *ct,
						unsigned char *pt, uint32 len);
PSPUBLIC int32 psRc2Encrypt(psCipherContext_t *ctx, unsigned char *pt,
						unsigned char *ct, uint32 len);
PSPUBLIC int32 psRc2InitKey(unsigned char *key, uint32 keylen, uint32 rds,
						psRc2Key_t *skey);
PSPUBLIC int32 psRc2EncryptBlock(unsigned char *pt, unsigned char *ct,
						psRc2Key_t *skey);
PSPUBLIC int32 psRc2DecryptBlock(unsigned char *ct, unsigned char *pt,
						psRc2Key_t *skey);					
#endif /* USE_RC2 */
/******************************************************************************/
/******************************************************************************/
#ifdef USE_SHA1
#if !TLS_CONFIG_HARD_CRYPTO
#include "sha1.h"
/******************************************************************************/
#if 0
PSPUBLIC void psSha1Init(psDigestContext_t * md);
PSPUBLIC void psSha1Update(psDigestContext_t * md, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psSha1Final(psDigestContext_t * md, unsigned char *hash);
#else
#define psSha1Init(context) SHA1Init((struct SHA1Context *)context)
#define psSha1Update(context, data, len) SHA1Update((struct SHA1Context *)context, data, len)
#define psSha1Final(A, B) SHA1Final(B, (struct SHA1Context *)A)
#endif
#else
#define psSha1Init(md) tls_crypto_sha1_init(md)
#define psSha1Update(md, data, len) tls_crypto_sha1_update(md, data, len)
#define psSha1Final(md, hash) tls_crypto_sha1_final(md, hash)
#endif
#ifdef USE_HMAC
PSPUBLIC int32 psHmacSha1(unsigned char *key, uint32 keyLen,
				const unsigned char *buf, uint32 len,
				unsigned char *hash, unsigned char *hmacKey,
				uint32 *hmacKeyLen);
PSPUBLIC void psHmacSha1Init(psHmacContext_t *ctx, unsigned char *key,
				uint32 keyLen);
PSPUBLIC void psHmacSha1Update(psHmacContext_t *ctx, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psHmacSha1Final(psHmacContext_t *ctx, unsigned char *hash); 
#endif /* USE_HMAC */
#endif /* USE_SHA1 */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_SHA256
#ifdef USE_HMAC
PSPUBLIC int32 psHmacSha2(unsigned char *key, uint32 keyLen,
				const unsigned char *buf, uint32 len,
				unsigned char *hash, unsigned char *hmacKey,
				uint32 *hmacKeyLen, uint32 hashSize);
PSPUBLIC void psHmacSha2Init(psHmacContext_t *ctx, unsigned char *key,
				uint32 keyLen, uint32 hashSize);
PSPUBLIC void psHmacSha2Update(psHmacContext_t *ctx, const unsigned char *buf,
				uint32 len, uint32 hashSize);
PSPUBLIC int32 psHmacSha2Final(psHmacContext_t *ctx, unsigned char *hash,
				uint32 hashSize); 
#endif /* USE_HMAC */
#endif /* USE_SHA256 */
/******************************************************************************/
#ifdef USE_SHA256
#include "sha256.h"
#if 0
PSPUBLIC void psSha256Init(psDigestContext_t * md);
PSPUBLIC void psSha256Update(psDigestContext_t * md, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psSha256Final(psDigestContext_t * md, unsigned char *hash);
#else 
#define psSha256Init(md) wpa_sha256_init((struct sha256_state *)md)
#define psSha256Update(md, in, len)  sha256_process((struct sha256_state *)md, in, len)
#define psSha256Final(md, out)  sha256_done((struct sha256_state *)md, out)
#endif
#endif /* USE_SHA256 */

#ifdef USE_SHA224
PSPUBLIC void psSha224Init(psDigestContext_t * md);
PSPUBLIC void psSha224Update(psDigestContext_t * md, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psSha224Final(psDigestContext_t * md, unsigned char *hash);
#endif /* USE_SHA224 */

#ifdef USE_SHA384
PSPUBLIC void psSha384Init(psDigestContext_t * md);
PSPUBLIC void psSha384Update(psDigestContext_t * md, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psSha384Final(psDigestContext_t * md, unsigned char *hash);
#endif /* USE_SHA384 */

#ifdef USE_SHA512
PSPUBLIC void psSha512Init(psDigestContext_t * md);
PSPUBLIC void psSha512Update(psDigestContext_t * md, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psSha512Final(psDigestContext_t * md, unsigned char *hash);
#endif /* USE_SHA512 */

/******************************************************************************/

#ifdef USE_ECC
PSPUBLIC int32 psEcdsaParsePrivKey(psPool_t *pool, unsigned char *keyBuf,
				int32 keyBufLen, psPubKey_t **keyPtr, psEccSet_t *curve);
PSPUBLIC int32 psEcdsaParsePrivFile(psPool_t *pool, char *fileName,
				char *password,	psPubKey_t **outkey);
PSPUBLIC int32 psEccX963ImportKey(psPool_t *pool, const unsigned char *inbuf,
				uint32 inlen, psEccKey_t *key);
PSPUBLIC int32 psEccX963ExportKey(psPool_t *pool, psEccKey_t *key,
				unsigned char *outbuf, uint32 *outlen);
PSPUBLIC int32 psEccMakeKeyEx(psPool_t *pool, psEccKey_t **keyPtr,
				psEccSet_t *dp, void *eccData);
PSPUBLIC void psEccFreeKey(psEccKey_t **key);
PSPUBLIC int32 psEccGenSharedSecret(psPool_t *pool, psEccKey_t *private_key,
				psEccKey_t *public_key, unsigned char *outbuf,
				uint32 *outlen, void *eccData);
PSPUBLIC int32 psEcDsaValidateSignature(psPool_t *pool, psEccKey_t *myPubKey,
				unsigned char *signature, int32 sigLen,	unsigned char *hash,
				int32 hashLen, int32 *stat, void *eccData);
PSPUBLIC int32 psEccSignHash(psPool_t *pool, unsigned char *inbuf,
				int32 inlen, unsigned char *c, int32 outlen,
				psEccKey_t *privKey, int32 *bytesWritten, int32 includeSize,
				void *eccData);
#endif /* USE_ECC */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_MD5
#if !TLS_CONFIG_HARD_CRYPTO
#include "md5.h"
/******************************************************************************/
#if 0
PSPUBLIC void psMd5Init(psDigestContext_t * md);
PSPUBLIC void psMd5Update(psDigestContext_t * md, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psMd5Final(psDigestContext_t * md, unsigned char *hash);
#else
#define psMd5Init(ctx) MD5Init((struct MD5Context *)ctx)
#define psMd5Update(ctx, buf, len) MD5Update((struct MD5Context *)ctx, buf, len)
#define psMd5Final(A, B) MD5Final(B, (struct MD5Context *)A)
#endif
#else
#define psMd5Init(ctx) tls_crypto_md5_init(ctx)
#define psMd5Update(ctx, buf, len) tls_crypto_md5_update(ctx, buf, len)
#define psMd5Final(ctx, hash) tls_crypto_md5_final(ctx, hash)
#endif
#ifdef USE_HMAC
PSPUBLIC int32 psHmacMd5(unsigned char *key, uint32 keyLen,
				const unsigned char *buf, uint32 len,
				unsigned char *hash, unsigned char *hmacKey,
				uint32 *hmacKeyLen);
PSPUBLIC void psHmacMd5Init(psHmacContext_t *ctx, unsigned char *key,
				uint32 keyLen);
PSPUBLIC void psHmacMd5Update(psHmacContext_t *ctx, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psHmacMd5Final(psHmacContext_t *ctx, unsigned char *hash); 
#endif /* USE_HMAC */
#endif /* USE_MD5 */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_MD4
/******************************************************************************/
PSPUBLIC void psMd4Init(psDigestContext_t * md);
PSPUBLIC void psMd4Update(psDigestContext_t * md, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psMd4Final(psDigestContext_t * md, unsigned char *hash);
#endif /* USE_MD4 */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_MD2
/******************************************************************************/
PSPUBLIC void psMd2Init(psDigestContext_t * md);
PSPUBLIC int32 psMd2Update(psDigestContext_t * md, const unsigned char *buf,
				uint32 len);
PSPUBLIC int32 psMd2Final(psDigestContext_t * md, unsigned char *hash);
#endif /* USE_MD2 */
/******************************************************************************/

/******************************************************************************/
/*
	Private Key Parsing
	PKCS#1 - RSA specific
	PKCS#8 - General private key storage format
*/
#ifdef USE_PRIVATE_KEY_PARSING
#ifdef USE_RSA
PSPUBLIC int32 pkcs1ParsePrivBin(psPool_t *pool, unsigned char *p,
				uint32 size, psPubKey_t **key);
#ifdef MATRIX_USE_FILE_SYSTEM
PSPUBLIC int32 pkcs1ParsePrivFile(psPool_t *pool, char *fileName,
				char *password, psPubKey_t **outkey);
#endif /* MATRIX_USE_FILE_SYSTEM */				
#endif /* USE_RSA */
		
#ifdef MATRIX_USE_FILE_SYSTEM
PSPUBLIC int32 pkcs1DecodePrivFile(psPool_t *pool, char *fileName,
				char *password,	unsigned char **DERout, uint32 *DERlen);
#endif /* MATRIX_USE_FILE_SYSTEM */
						
#ifdef USE_PKCS8
PSPUBLIC int32 pkcs8ParsePrivBin(psPool_t *pool, unsigned char *p,
				int32 size, char *pass, psPubKey_t **key);
#ifdef MATRIX_USE_FILE_SYSTEM
#ifdef USE_PKCS12				
PSPUBLIC int32 psPkcs12Parse(psPool_t *pool, psX509Cert_t **cert,
				psPubKey_t **privKey, const unsigned char *file, int32 flags,
				unsigned char *importPass, int32 ipasslen,
				unsigned char *privkeyPass, int32 kpasslen);
#endif /* USE_PKCS12 */
#endif /* MATRIX_USE_FILE_SYSTEM */				
#endif /* USE_PKCS8 */
#endif /* USE_PRIVATE_KEY_PARSING */

/******************************************************************************/

/******************************************************************************/
#ifdef USE_PKCS5
/******************************************************************************/
/*
	PKCS#5 PBKDF v1 and v2 key generation
*/
PSPUBLIC void pkcs5pbkdf1(unsigned char *pass, uint32 passlen,
				unsigned char *salt, int32 iter, unsigned char *key);
PSPUBLIC void pkcs5pbkdf2(unsigned char *password, uint32 pLen, 
				 unsigned char *salt, uint32 sLen, int32 rounds,
				 unsigned char *key, uint32 kLen);
#endif /* USE_PKCS5 */

/******************************************************************************/
/*
	Public Key Cryptography
*/
PSPUBLIC psPubKey_t *psNewPubKey(psPool_t *pool);
PSPUBLIC void psFreePubKey(psPubKey_t *key);

/******************************************************************************/
#ifdef USE_RSA
/******************************************************************************/
/*
	RSA crypto
*/
PSPUBLIC int32 psRsaDecryptPriv(psPool_t *pool, psRsaKey_t *key,
					unsigned char *in, uint32 inlen,
					unsigned char *out, uint32 outlen, void *data);
PSPUBLIC int32 psRsaDecryptPub(psPool_t *pool, psRsaKey_t *key,
					unsigned char *in, uint32 inlen,
					unsigned char *out, uint32 outlen, void *data);
PSPUBLIC int32 psRsaEncryptPub(psPool_t *pool, psRsaKey_t *key,
				unsigned char *in, uint32 inlen,
				unsigned char *out, uint32 outlen, void *data);
PSPUBLIC int32 pubRsaDecryptSignedElement(psPool_t *pool, psPubKey_t *key, 
				unsigned char *in, uint32 inlen, unsigned char *out,
				uint32 outlen, void *data);
PSPUBLIC int32 psRsaEncryptPriv(psPool_t *pool, psRsaKey_t *key,
					unsigned char *in, uint32 inlen,
					unsigned char *out, uint32 outlen, void *data);
PSPUBLIC int32 privRsaEncryptSignedElement(psPool_t *pool, psPubKey_t *key,
				unsigned char *in, uint32 inlen, unsigned char *out,
				uint32 outlen, void *data);
PSPUBLIC int32 psRsaCrypt(psPool_t *pool, const unsigned char *in, uint32 inlen,
				unsigned char *out, uint32 *outlen,	psRsaKey_t *key,
				int32 type, void *data);
#endif /* USE_RSA */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_DH
/******************************************************************************/
/******************************************************************************/
/*
	PKCS#3 - Diffie-Hellman parameters
*/
PSPUBLIC int32 pkcs3ParseDhParamBin(psPool_t *pool, unsigned char *dhBin,
					int32 dhBinLen, psDhParams_t **key);
#ifdef MATRIX_USE_FILE_SYSTEM
PSPUBLIC int32 pkcs3ParseDhParamFile(psPool_t *pool, char *fileName,
					 psDhParams_t **key);
#endif /* MATRIX_USE_FILE_SYSTEM */
PSPUBLIC void pkcs3FreeDhParams(psDhParams_t *params);


PSPUBLIC int32 psDhKeyGen(psPool_t *pool, uint32 keysize, unsigned char *pBin,
					uint32 pLen, unsigned char *gBin, uint32 gLen,
					psDhKey_t *key, void *data);					
PSPUBLIC int32 psDhKeyGenInts(psPool_t *pool, uint32 keysize, pstm_int *p,
					pstm_int *g, psDhKey_t *key, void *data);
					
PSPUBLIC int32 psDhGenSecret(psPool_t *pool, psDhKey_t *private_key,
					psDhKey_t *public_key, unsigned char *pBin, uint32 pLen,
					unsigned char *outbuf, uint32 *outlen, void* data);
PSPUBLIC int32 psDhImportPubKey(psPool_t *pool, unsigned char *inbuf,
					uint32 inlen, psDhKey_t *key); 
PSPUBLIC int32 psDhExportPubKey(psPool_t *pool, psDhKey_t *key,
					unsigned char **out);					

PSPUBLIC int32 psDhExportParameters(psPool_t *pool, psDhParams_t *key,
					uint32 *pLen, unsigned char **p, uint32 *gLen,
					unsigned char **g);
PSPUBLIC void psDhFreeKey(psDhKey_t *key);
#endif /* USE_DH */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_X509
/******************************************************************************/
/*
	X.509 Certificate support	
*/
PSPUBLIC int32 psX509ParseCertFile(psPool_t *pool, char *fileName,
					psX509Cert_t **outcert, int32 flags);
PSPUBLIC int32 psX509ParseCert(psPool_t *pool, unsigned char *pp, uint32 size,
					psX509Cert_t **outcert, int32 flags);
PSPUBLIC void psX509FreeCert(psX509Cert_t *cert);
#ifdef USE_CERT_PARSE
PSPUBLIC int32 psX509AuthenticateCert(psPool_t *pool, psX509Cert_t *subjectCert,
					psX509Cert_t *issuerCert, psX509Cert_t **foundIssuer);
#endif
#ifdef USE_CRL
PSPUBLIC int32 psX509ParseCrl(psPool_t *pool, psX509Cert_t *CA, int append,
					unsigned char *crlBin, int32 crlBinLen);
#endif /* USE_CRL */					
#endif /* USE_X509 */
/******************************************************************************/

/******************************************************************************/
PSPUBLIC int32 psInitPrng(psRandom_t *ctx);
PSPUBLIC int32 psGetPrng(psRandom_t *ctx, unsigned char *bytes, uint32 size);
				

#ifdef USE_YARROW
PSPUBLIC int32 psYarrowStart(psYarrow_t *ctx);
PSPUBLIC int32 psYarrowAddEntropy(unsigned char *in, uint32 inlen,
			psYarrow_t *prng);
PSPUBLIC int32 psYarrowReseed(psYarrow_t *ctx);
PSPUBLIC uint32 psYarrowRead(unsigned char *out, uint32 outlen, psYarrow_t *cx);
PSPUBLIC int32 psYarrowDone(psYarrow_t *ctx);
PSPUBLIC int32 psYarrowExport(unsigned char *out, uint32 *outlen,
			psYarrow_t *ctx);
PSPUBLIC int32 psYarrowImport(unsigned char *in, uint32 inlen, psYarrow_t *ctx);
#endif /* USE_YARROW */
/******************************************************************************/

#endif /* _h_PS_CRYPTOAPI */
/******************************************************************************/

