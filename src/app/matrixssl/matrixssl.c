/*
 *	matrixssl.c
 *	Release $Name: MATRIXSSL-3-6-1-OPEN $
 *
 *	The session and authentication management portions of the MatrixSSL library
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
/******************************************************************************/

static const char copyright[] = 
"Copyright Inside Secure Corporation. All rights reserved.";

#if defined(USE_RSA) || defined(USE_ECC)	
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
static int32 verifyReadKeys(psPool_t *pool, sslKeys_t *keys);
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
#endif /* USE_RSA || USE_ECC */


#ifdef USE_SERVER_SIDE_SSL
/*
	Static session table for session cache and lock for multithreaded env
*/
#ifdef USE_MULTITHREADING
static psMutex_t			sessionTableLock;
static psMutex_t			prngLock;
#ifdef USE_STATELESS_SESSION_TICKETS
static psMutex_t			g_sessTicketLock;
#endif
#endif /* USE_MULTITHREADING */

static sslSessionEntry_t	sessionTable[SSL_SESSION_TABLE_SIZE];
static DLListEntry          sessionChronList;
static void initSessionEntryChronList(void);
#endif /* USE_SERVER_SIDE_SSL */

#if defined(USE_RSA) || defined(USE_ECC)
#ifdef MATRIX_USE_FILE_SYSTEM
static int32 matrixSslLoadKeyMaterial(sslKeys_t *keys, const char *certFile,
				const char *privFile, const char *privPass, const char *CAfile,
				int32 privKeyType);
#endif
static int32 matrixSslLoadKeyMaterialMem(sslKeys_t *keys,
				unsigned char *certBuf,	int32 certLen, unsigned char *privBuf,
				int32 privLen, unsigned char *CAbuf, int32 CAlen,
				int32 privKeyType);
#endif /* USE_RSA || USE_ECC */	

static psRandom_t gMatrixsslPrng;

 
/******************************************************************************/
/*
	Open and close the SSL module.  These routines are called once in the 
	lifetime of the application and initialize and clean up the library 
	respectively.
	The config param should always be passed as:
		MATRIXSSL_CONFIG
*/
static char	g_config[32] = "N";

int32 matrixSslOpenWithConfig(char *config)
{
	/* Use copyright to avoid compiler warning about it being unused */
	if (*copyright != 'C') {
		return PS_FAILURE;
	}
	if (*g_config == 'Y') {
		return PS_SUCCESS; /* Function has been called previously */
	}
	strncpy(g_config, MATRIXSSL_CONFIG, sizeof(g_config) - 1);
	if (strncmp(g_config, config, sizeof(g_config) - 1) != 0) {
		psErrorStr( "MatrixSSL config mismatch.\n" \
					"Library: " MATRIXSSL_CONFIG \
					"\nCurrent: %s\n", config);
		return -1;
	}
#if 0
	if (psCryptoOpen(PSCRYPTO_CONFIG) < 0) {
		psError("pscrypto open failure\n");
		return PS_FAILURE;
	}
#endif
#ifdef USE_PKCS11
	if (pkcs11Init(NULL) != CKR_OK) {
		psError("PKCS11 open failure\n");
		return PS_FAILURE;
	}
#endif
	psInitPrng(&gMatrixsslPrng);

#ifdef USE_SERVER_SIDE_SSL
	memset(sessionTable, 0x0, 
		sizeof(sslSessionEntry_t) * SSL_SESSION_TABLE_SIZE);
		
	initSessionEntryChronList();
#ifdef USE_MULTITHREADING		
	psCreateMutex(&sessionTableLock);
	psCreateMutex(&prngLock);
#ifdef USE_STATELESS_SESSION_TICKETS
	psCreateMutex(&g_sessTicketLock);
#endif
#endif /* USE_MULTITHREADING */
#endif /* USE_SERVER_SIDE_SSL */


	return PS_SUCCESS;
}

/*
	MatrixSSL PRNG retrieval
*/
int32 matrixSslGetPrngData(unsigned char *bytes, uint32 size)
{
	int32	rc;
#ifdef USE_MULTITHREADING
	psLockMutex(&prngLock);
#endif /* USE_MULTITHREADING */
	rc = psGetPrng(&gMatrixsslPrng, bytes, size);
#ifdef USE_MULTITHREADING		
	psUnlockMutex(&prngLock);
#endif /* USE_MULTITHREADING */
	return rc;
}

/*
	matrixSslClose
*/
void matrixSslClose(void)
{
#ifdef USE_SERVER_SIDE_SSL
	int32		i;

#ifdef USE_MULTITHREADING
	psLockMutex(&sessionTableLock);
#endif /* USE_MULTITHREADING */
	for (i = 0; i < SSL_SESSION_TABLE_SIZE; i++) {
		if (sessionTable[i].inUse > 1) {
			psTraceInfo("Warning: closing while session still in use\n");
		}
	}
	memset(sessionTable, 0x0, 
		sizeof(sslSessionEntry_t) * SSL_SESSION_TABLE_SIZE);
#ifdef USE_MULTITHREADING		
	psUnlockMutex(&sessionTableLock);
	psDestroyMutex(&sessionTableLock);
	psDestroyMutex(&prngLock);
#endif /* USE_MULTITHREADING */	
#endif /* USE_SERVER_SIDE_SSL */

#ifdef USE_PKCS11
#ifdef PKCS11_STATS
	pkcs11ShowObjects();
#endif
	pkcs11Close();
#endif	 /* USE_PKCS11 */
	//psCryptoClose();
}

/******************************************************************************/
/*
	Must call to allocate the key structure now.  After which, LoadRsaKeys,
	LoadDhParams and/or LoadPskKey can be called 
	
	Memory info:
	Caller must free keys with matrixSslDeleteKeys on function success
	Caller does not need to free keys on function failure
*/
int32 matrixSslNewKeys(sslKeys_t **keys)
{
	psPool_t	*pool = NULL;
	sslKeys_t	*lkeys;
	
	
	lkeys = psMalloc(pool, sizeof(sslKeys_t));
	if (lkeys == NULL) {
		return PS_MEM_FAIL;
	}
	memset(lkeys, 0x0, sizeof(sslKeys_t));
	lkeys->pool = pool;
	
	*keys = lkeys;
	return PS_SUCCESS;
}


#ifdef MATRIX_USE_FILE_SYSTEM
#ifdef USE_PKCS12

/* Have seen cases where the PKCS#12 files are not in a child-to-parent order */
static void ReorderCertChain(psX509Cert_t *a_cert)
{
	psX509Cert_t* prevCert = NULL;
	psX509Cert_t* nextCert = NULL;
	psX509Cert_t* currCert = a_cert;
 
	while (currCert) {
		nextCert = currCert->next;
        while (nextCert && memcmp(currCert->issuer.hash, nextCert->subject.hash,
				SHA1_HASH_SIZE) != 0) {
			prevCert = nextCert;
			nextCert = nextCert->next;
 
			if (nextCert && memcmp(currCert->issuer.hash,
					nextCert->subject.hash, SHA1_HASH_SIZE) == 0) {
				prevCert->next = nextCert->next;
				nextCert->next = currCert->next;
				currCert->next = nextCert;
				break;
			}
		}
		currCert = currCert->next;
	}
}

/******************************************************************************/
/*
	File should be a binary .p12 or .pfx 
*/
int32 matrixSslLoadPkcs12(sslKeys_t *keys, unsigned char *certFile,
			unsigned char *importPass, int32 ipasslen,
			unsigned char *macPass, int32 mpasslen, int32 flags)
{
	unsigned char	*mPass;
	psPool_t	*pool;
	int32		rc;

	if (keys == NULL) {
		return PS_ARG_FAIL;
	}
	pool = keys->pool;
	
	if (macPass == NULL) {
		mPass = importPass;
		mpasslen = ipasslen;
	} else {
		mPass = macPass;
	}
		
	if ((rc = psPkcs12Parse(pool, &keys->cert, &keys->privKey, certFile, flags,
			importPass, ipasslen, mPass, mpasslen)) < 0) {
		if (keys->cert) {
			psX509FreeCert(keys->cert);
			keys->cert = NULL;
		}
		if (keys->privKey) {
			psFreePubKey(keys->privKey);
			keys->privKey = NULL;
		}
		return rc;
	}
	ReorderCertChain(keys->cert);
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	if (verifyReadKeys(pool, keys) < PS_SUCCESS) {
		psTraceInfo("PKCS#12 parse success but material didn't validate\n");
		psX509FreeCert(keys->cert);
		psFreePubKey(keys->privKey);
		keys->cert = NULL;
		keys->privKey = NULL;
		return PS_CERT_AUTH_FAIL;
	}
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */	
	return PS_SUCCESS;
}
#endif /* USE_PKCS12 */

#ifdef USE_RSA	
int32 matrixSslLoadRsaKeys(sslKeys_t *keys, const char *certFile,
				const char *privFile, const char *privPass, const char *CAfile)
{
	return matrixSslLoadKeyMaterial(keys, certFile, privFile, privPass, CAfile,
				PS_RSA);

}
#endif /* USE_RSA */

#ifdef USE_ECC	
int32 matrixSslLoadEcKeys(sslKeys_t *keys, const char *certFile,
				const char *privFile, const char *privPass, const char *CAfile)
{
	return matrixSslLoadKeyMaterial(keys, certFile, privFile, privPass, CAfile,
				PS_ECC);

}
#endif /* USE_ECC */

#if defined(USE_RSA) || defined(USE_ECC)
static int32 matrixSslLoadKeyMaterial(sslKeys_t *keys, const char *certFile,
				const char *privFile, const char *privPass, const char *CAfile,
				int32 privKeyType)
{
	psPool_t	*pool;
	int32		err, flags;

	if (keys == NULL) {
		return PS_ARG_FAIL;
	}
	pool = keys->pool;

/*
	Setting flags to store raw ASN.1 stream for SSL CERTIFICATE message use
*/
	flags = CERT_STORE_UNPARSED_BUFFER;
	
#ifdef USE_CLIENT_AUTH
/*
	 If the CERTIFICATE_REQUEST message will possibly be needed we must
	 save aside the Distiguished Name portion of the certs for that message.
*/
	flags |= CERT_STORE_DN_BUFFER;
#endif /* USE_CLIENT_AUTH */

	if (certFile) {
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)	
		if (keys->cert != NULL) {
			return PS_UNSUPPORTED_FAIL;
		}
		if ((err = psX509ParseCertFile(pool, (char*)certFile,
				&keys->cert, flags)) < 0) {
			return err;
		}
		if (keys->cert->authFailFlags) {
			/* This should be the only no err, FailFlags case currently */
			psAssert(keys->cert->authFailFlags == PS_CERT_AUTH_FAIL_DATE_FLAG);
			psX509FreeCert(keys->cert);
			keys->cert = NULL;
			return PS_CERT_AUTH_FAIL_EXTENSION;
		}
#else
		psTraceStrInfo("Ignoring %s certFile in matrixSslReadKeys\n",
					(char*)certFile);
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */		
	}
/*
	Parse the private key file
*/
	if (privFile) {
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
		if (keys->privKey != NULL) {
			if (keys->cert) {
				psX509FreeCert(keys->cert);
				keys->cert = NULL;
			}
			return PS_UNSUPPORTED_FAIL;
		}
#ifdef USE_RSA			
		if (privKeyType == PS_RSA) {
			if ((err = pkcs1ParsePrivFile(pool, (char*)privFile,
					(char*)privPass, &keys->privKey)) < 0) {
				if (keys->cert) {	
					psX509FreeCert(keys->cert);
					keys->cert = NULL;
				}
				return err;
			}
		}
#endif /* USE_RSA */
#ifdef USE_ECC
		if (privKeyType == PS_ECC) {
			if ((err = psEcdsaParsePrivFile(pool, (char*)privFile,
					(char*)privPass, &keys->privKey)) < 0) {
				if (keys->cert) {	
					psX509FreeCert(keys->cert);
					keys->cert = NULL;
				}
				return err;
			}
		}
#endif /* USE_ECC */		
#else
		psTraceStrInfo("Ignoring %s privFile in matrixSslReadKeys\n",
					(char*)privFile);
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */			
	}

#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	if (verifyReadKeys(pool, keys) < PS_SUCCESS) {
		psTraceInfo("Cert parse success but material didn't validate\n");
		psX509FreeCert(keys->cert);
		psFreePubKey(keys->privKey);
		keys->cert = NULL;
		keys->privKey = NULL;
		return PS_CERT_AUTH_FAIL;
	}
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */

/*
	Not necessary to store binary representations of CA certs
*/
	flags &= ~CERT_STORE_UNPARSED_BUFFER;

	if (CAfile) {	
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
		if (keys->CAcerts != NULL) {
			return PS_UNSUPPORTED_FAIL;
		}
		err = psX509ParseCertFile(pool, (char*)CAfile, &keys->CAcerts, flags);
		if (err >= 0) {
			if (keys->CAcerts->authFailFlags) {
				/* This should be the only no err, FailFlags case currently */
				psAssert(keys->CAcerts->authFailFlags ==
					 PS_CERT_AUTH_FAIL_DATE_FLAG);
				psX509FreeCert(keys->CAcerts);
				keys->CAcerts = NULL;
				err = PS_CERT_AUTH_FAIL_EXTENSION;
			}
		}
		if (err < 0) {
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)				
			if (keys->cert) {
				psX509FreeCert(keys->cert);
				keys->cert = NULL;
			} 
			if (keys->privKey) {
				psFreePubKey(keys->privKey);
				keys->privKey = NULL;
			}
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */	
			return err;
		}
#else
		psTraceStrInfo("Ignoring %s CAfile in matrixSslReadKeys\n", (char*)CAfile);		
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
	}

	return PS_SUCCESS;
}
#endif /* USE_RSA || USE_ECC */
#endif /* MATRIX_USE_FILE_SYSTEM */

/******************************************************************************/
/*
	Memory buffer versions of ReadKeys

	This function supports cert chains and multiple CAs.  Just need to
	string them together and let psX509ParseCert handle it 
*/
#ifdef USE_RSA	
int32 matrixSslLoadRsaKeysMem(sslKeys_t *keys, unsigned char *certBuf,
			int32 certLen, unsigned char *privBuf, int32 privLen,
			unsigned char *CAbuf, int32 CAlen)
{
	return matrixSslLoadKeyMaterialMem(keys, certBuf, certLen, privBuf, privLen,
				CAbuf, CAlen, PS_RSA);

}
#endif /* USE_RSA */

#ifdef USE_ECC	
int32 matrixSslLoadEcKeysMem(sslKeys_t *keys, unsigned char *certBuf,
				int32 certLen, unsigned char *privBuf, int32 privLen,
				unsigned char *CAbuf, int32 CAlen)
{
	return matrixSslLoadKeyMaterialMem(keys, certBuf, certLen, privBuf, privLen,
				CAbuf, CAlen, PS_ECC);

}

#ifdef USE_PKCS11
/* 
	API to support loading existing PKCS#11 private key object into the
	sslKey_t structure that is passed to new session creation APIs.
		
	Usage:
	This function would	be called instead of matrixSslLoadEcKeysMem so the
	application would initialize a session like this:
	
		...
		matrixSslNewKeys(&keys);
		matrixSslPkcs11LoadEcKeysMem(keys, ...
		matrixSslNewServerSession(&ssl, keys, ...
		... app work ...
		matrixSslDeleteKeys(keys);
*/
int32 matrixSslPkcs11LoadEcKeysMem(sslKeys_t *keys,
				unsigned char *certBuf,	int32 certLen,
				CK_SESSION_HANDLE privSess, CK_OBJECT_HANDLE privObj,
				unsigned char *CAbuf, int32 CAlen)
{
	psPool_t	*pool;
	psPubKey_t	*privkey;
	psEccKey_t	*ecckey;
	int32		err, flags = 0;

	if (keys == NULL) {
		return PS_ARG_FAIL;
	}
	pool = keys->pool;
	
	
	/* Identity Certificate component */
	/*	Setting flags to store raw ASN.1 stream for SSL CERTIFICATE use */
	flags = CERT_STORE_UNPARSED_BUFFER;
	
#ifdef USE_CLIENT_AUTH
	/*	Setting flag to store raw ASN.1 DN stream for CERTIFICATE_REQUEST */
	flags |= CERT_STORE_DN_BUFFER;
#endif /* USE_CLIENT_AUTH */
	
	if (certBuf) {	
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
		if (keys->cert != NULL) {
			return PS_UNSUPPORTED_FAIL;
		}
		if ((err = psX509ParseCert(pool, certBuf, (uint32)certLen, &keys->cert,
				flags)) < 0) {
			psX509FreeCert(keys->cert);
			keys->cert = NULL;
			return err;
		}
#else
		psTraceInfo("Ignoring certBuf in matrixSslPkcs11LoadEcKeysMem\n");
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */			
	}
	

	/* Private key component.  In the standard parse case, all the info
		about the private key is stored in the ASN.1 itself.  In this
		case we are going to assume the certificate is the correct identity
		and can pull the curve and size information straight out of that */
	privkey = NULL;
	privkey = psNewPubKey(pool);
	if (privkey == NULL) {
		psError("Memory allocation error in matrixSslPkcs11LoadEcKeysMem\n");
		psX509FreeCert(keys->cert);
		keys->cert = NULL;
		return PS_MEM_FAIL;
	}
	privkey->type = PS_ECC;
	ecckey = &(privkey->key->ecc);
	ecckey->type = PRIVKEY_TYPE;
	ecckey->sess = privSess;
	ecckey->obj = privObj;
	ecckey->external = 1; /* Don't destroy object at DeleteKey time */
	/* Curve and key size information from certificate */
	ecckey->dp = keys->cert->publicKey.key->ecc.dp;
	privkey->keysize = ecckey->dp->size * 2;
	keys->privKey = privkey;	


	/* CA component */
	/* Not necessary to store binary representations of CA certs */
	flags &= ~CERT_STORE_UNPARSED_BUFFER;	
	
	if (CAbuf) {
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
		if (keys->CAcerts != NULL) {
			return PS_UNSUPPORTED_FAIL;
		}
		if ((err = psX509ParseCert(pool, CAbuf, (uint32)CAlen, &keys->CAcerts,
				flags)) < 0) {
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)		
			psFreePubKey(keys->privKey);
			psX509FreeCert(keys->cert);
			psX509FreeCert(keys->CAcerts);
			keys->privKey = NULL;
			keys->cert = keys->CAcerts = NULL;
#endif			
			return err;
		}
#else
		psTraceInfo("Ignoring CAbuf in matrixSslPkcs11LoadEcKeysMem\n");		
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
	}

	return PS_SUCCESS;
}
#endif /* USE_PKCS11 */
#endif /* USE_ECC */

#if defined(USE_RSA) || defined(USE_ECC)
static int32 matrixSslLoadKeyMaterialMem(sslKeys_t *keys,
				unsigned char *certBuf,	int32 certLen, unsigned char *privBuf,
				int32 privLen, unsigned char *CAbuf, int32 CAlen,
				int32 privKeyType)
{
	psPool_t	*pool;
	int32		err, flags = 0;

	if (keys == NULL) {
		return PS_ARG_FAIL;
	}
	pool = keys->pool;
	
/*
	Setting flags to store raw ASN.1 stream for SSL CERTIFICATE message use
*/
	flags = CERT_STORE_UNPARSED_BUFFER;
	
#ifdef USE_CLIENT_AUTH
/*
	Setting flag to store raw ASN.1 DN stream for CERTIFICATE_REQUEST
*/
	flags |= CERT_STORE_DN_BUFFER;
#endif /* USE_CLIENT_AUTH */
	
	if (certBuf) {	
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
		if (keys->cert != NULL) {
			psTraceInfo("WARNING: An identity certificate already exists\n");
			return PS_UNSUPPORTED_FAIL;
		}
		if ((err = psX509ParseCert(pool, certBuf, (uint32)certLen, &keys->cert,
				flags)) < 0) {
			psX509FreeCert(keys->cert);
			keys->cert = NULL;
			return err;
		}
#else
		psTraceInfo("Ignoring certBuf in matrixSslReadKeysMem\n");
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */			
	}
	
	if (privBuf) {
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
		if (keys->privKey != NULL) {
			return PS_UNSUPPORTED_FAIL;
		}
#ifdef USE_RSA		
		if (privKeyType == PS_RSA) {		
			if ((err = pkcs1ParsePrivBin(pool, privBuf, (uint32)privLen,
					&keys->privKey)) < 0) {
#ifdef USE_PKCS8
				/* Attempt a PKCS#8 but mem parse doesn't take password */ 
				if ((err = pkcs8ParsePrivBin(pool, privBuf, (uint32)privLen,
						NULL, &keys->privKey)) < 0) {
					psX509FreeCert(keys->cert); keys->cert = NULL;
					return err;
				}
#else					
				psX509FreeCert(keys->cert); keys->cert = NULL;
				return err;
#endif
			}
		}
#endif /* USE_RSA */
#ifdef USE_ECC
		if (privKeyType == PS_ECC) {
			if ((err = psEcdsaParsePrivKey(pool, privBuf, (uint32)privLen,
					&keys->privKey, NULL)) < 0) {
#ifdef USE_PKCS8
				/* Attempt a PKCS#8 but mem parse doesn't take password */ 
				if ((err = pkcs8ParsePrivBin(pool, privBuf, (uint32)privLen,
						NULL, &keys->privKey)) < 0) {
					psX509FreeCert(keys->cert); keys->cert = NULL;
					return err;
				}
#else					
				psX509FreeCert(keys->cert); keys->cert = NULL;
				return err;
#endif				
			}
		}
#endif /* USE_ECC */

#else
		psTraceInfo("Ignoring privBuf in matrixSslReadKeysMem\n");
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */		
	}
	
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	if (verifyReadKeys(pool, keys) < PS_SUCCESS) {
		psX509FreeCert(keys->cert);
		psFreePubKey(keys->privKey);
		keys->privKey = NULL;
		keys->cert = NULL;
		return PS_CERT_AUTH_FAIL;
	}
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */

/*
	 Not necessary to store binary representations of CA certs
*/
	flags &= ~CERT_STORE_UNPARSED_BUFFER;	
	
	if (CAbuf) {
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
		if (keys->CAcerts != NULL) {
			return PS_UNSUPPORTED_FAIL;
		}
		if ((err = psX509ParseCert(pool, CAbuf, (uint32)CAlen, &keys->CAcerts,
				flags)) < 0) {
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)		
			psFreePubKey(keys->privKey);
			psX509FreeCert(keys->cert);
			psX509FreeCert(keys->CAcerts);
			keys->privKey = NULL;
			keys->cert = keys->CAcerts = NULL;
#endif			
			return err;
		}
#else
		psTraceInfo("Ignoring CAbuf in matrixSslReadKeysMem\n");		
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
	}

	return PS_SUCCESS;
}
#endif /* USE_RSA || USE_ECC */

/******************************************************************************/
/*
	This will free the struct and any key material that was loaded via:
		matrixSslLoadRsaKeys
		matrixSslLoadDhParams
		matrixSslLoadPsk	
*/
void matrixSslDeleteKeys(sslKeys_t *keys)
{
#ifdef USE_PSK_CIPHER_SUITE
	psPsk_t		*psk, *next;
#endif /* USE_PSK_CIPHER_SUITE */
#if defined(USE_STATELESS_SESSION_TICKETS) && defined(USE_SERVER_SIDE_SSL)
	psSessionTicketKeys_t *tick, *nextTick;
#endif
	
	if (keys == NULL) {
		return;
	}
#ifndef USE_ONLY_PSK_CIPHER_SUITE	
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)	
	if (keys->cert) {
		psX509FreeCert(keys->cert);
	}
	
	if (keys->privKey) {
		psFreePubKey(keys->privKey);
	}
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
	
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	if (keys->CAcerts) {
		psX509FreeCert(keys->CAcerts);
	}
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

#ifdef REQUIRE_DH_PARAMS
	if (keys->dhParams) {
		pkcs3FreeDhParams(keys->dhParams);
	}
#endif /* REQUIRE_DH_PARAMS */

#ifdef USE_PSK_CIPHER_SUITE
	if (keys->pskKeys) {
		psk = keys->pskKeys; 
		while (psk) {
			psFree(psk->pskKey);
			psFree(psk->pskId);
			next = psk->next;
			psFree(psk);
			psk = next;
		}
	}
#endif /* USE_PSK_CIPHER_SUITE */

#if defined(USE_STATELESS_SESSION_TICKETS) && defined(USE_SERVER_SIDE_SSL)
	if (keys->sessTickets) {
		tick = keys->sessTickets;
		while (tick) {
			nextTick = tick->next;
			psFree(tick);
			tick = nextTick;
		}
	}
#endif

	psFree(keys);
}

#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
#if defined(USE_RSA) || defined(USE_ECC)	
/*
	Validate the cert chain and the private key for the material passed
	to matrixSslReadKeys.  Good to catch any user certifiate errors as
	soon as possible
*/
static int32 verifyReadKeys(psPool_t *pool, sslKeys_t *keys)
{
#ifdef USE_CERT_PARSE
	psX509Cert_t	*tmp, *found;
#endif

	if (keys->cert == NULL && keys->privKey == NULL) {
		return PS_SUCCESS;
	}	
/*
	 Not allowed to have a certficate with no matching private key or 
	 private key with no cert to match with
*/
	if (keys->cert != NULL && keys->privKey == NULL) {
		psTraceInfo("No private key given to matrixSslReadKeys cert\n");
		return PS_CERT_AUTH_FAIL;
	}
	if (keys->privKey != NULL && keys->cert == NULL) {
		psTraceInfo("No cert given with private key to matrixSslReadKeys\n");
		return PS_CERT_AUTH_FAIL;
	}
#ifdef USE_CERT_PARSE	
/*
	If this is a chain, we can validate it here with psX509AuthenticateCert
	Don't check the error return code from this call because the chaining
	usage restrictions will test parent-most cert for self-signed.
	 
	But we can look at 'authStatus' on all but the final cert to see
	if the rest looks good
*/
	if (keys->cert != NULL && keys->cert->next != NULL) {
		found = NULL;
		psX509AuthenticateCert(pool, keys->cert, NULL, &found);
		tmp = keys->cert;
		while (tmp->next != NULL) {
			if (tmp->authStatus != PS_TRUE) {
				psTraceInfo("Failed to authenticate cert chain\n");
				return PS_CERT_AUTH_FAIL;
			}
			tmp = tmp->next;
		}
	}

#ifdef USE_RSA
	if (keys->privKey != NULL && keys->privKey->type == PS_RSA) {
/*
		Testing the N member just as a sanity measure rather than
		attempting a full RSA crypt operation
*/
		if (pstm_cmp(&(keys->privKey->key->rsa.N),
				   &(keys->cert->publicKey.key->rsa.N)) != PSTM_EQ) {
			psTraceInfo("Private key doesn't match cert\n");	
			return PS_CERT_AUTH_FAIL;
		}
	}
#endif /* USE_RSA */
#endif /* USE_CERT_PARSE */	
	return PS_SUCCESS;
}
#endif /* USE_RSA || USE_ECC */
#endif	/* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
/******************************************************************************/


#ifdef REQUIRE_DH_PARAMS
/******************************************************************************/
/*
	User level API to assign the DH parameter file to the server application.
*/
#ifdef MATRIX_USE_FILE_SYSTEM
int32 matrixSslLoadDhParams(sslKeys_t *keys, const char *paramFile)
{
	if (keys == NULL) {
		return PS_ARG_FAIL;
	}
	return pkcs3ParseDhParamFile(keys->pool, (char*)paramFile, &keys->dhParams);
}
#endif /* MATRIX_USE_FILE_SYSTEM */

/******************************************************************************/
int32 matrixSslLoadDhParamsMem(sslKeys_t *keys,  unsigned char *dhBin,
			int32 dhBinLen)
{
	if (keys == NULL) {
		return PS_ARG_FAIL;
	}
	return pkcs3ParseDhParamBin(keys->pool, dhBin, dhBinLen, &keys->dhParams);
}
#endif /* REQUIRE_DH_PARAMS */

/******************************************************************************/
/*
	New SSL protocol context
	This structure is associated with a single SSL connection.  Each socket
	using SSL should be associated with a new SSL context.

	certBuf and privKey ARE NOT duplicated within the server context, in order
	to minimize memory usage with multiple simultaneous requests.  They must 
	not be deleted by caller until all server contexts using them are deleted.
*/
int32 matrixSslNewSession(ssl_t **ssl, sslKeys_t *keys, sslSessionId_t *session,
						int32 flags)
{
	psPool_t	*pool = NULL;
	ssl_t		*lssl;
	int32		specificVersion;
#ifdef USE_STATELESS_SESSION_TICKETS
	uint32		i;
#endif	

/*
	First API level chance to make sure a user is not attempting to use
	client or server support that was not built into this library compile
*/
#ifndef USE_SERVER_SIDE_SSL
	if (flags & SSL_FLAGS_SERVER) {
		psTraceInfo("SSL_FLAGS_SERVER passed to matrixSslNewSession but MatrixSSL lib was not compiled with server support\n");
		return PS_ARG_FAIL;
	}
#endif

#ifndef USE_CLIENT_SIDE_SSL
	if (!(flags & SSL_FLAGS_SERVER)) {
		psTraceInfo("SSL_FLAGS_SERVER was not passed to matrixSslNewSession but MatrixSSL was not compiled with client support\n");
		return PS_ARG_FAIL;
	}
#endif

#ifndef USE_CLIENT_AUTH
	if (flags & SSL_FLAGS_CLIENT_AUTH) {
		psTraceInfo("SSL_FLAGS_CLIENT_AUTH passed to matrixSslNewSession but MatrixSSL was not compiled with USE_CLIENT_AUTH enabled\n");
		return PS_ARG_FAIL;
	}
#endif

	if (flags & SSL_FLAGS_SERVER) {
#ifndef USE_PSK_CIPHER_SUITE
		if (keys == NULL) {
			psTraceInfo("NULL keys parameter passed to matrixSslNewSession\n");
			return PS_ARG_FAIL;
		}
#endif /* USE_PSK_CIPHER_SUITE */
		if (session != NULL) {
			psTraceInfo("Ignoring session parameter to matrixSslNewSession\n");
		}
	}

	lssl = psMalloc(pool, sizeof(ssl_t));
	if (lssl == NULL) {
		psTraceInfo("Out of memory for ssl_t in matrixSslNewSession\n");
		return PS_MEM_FAIL;
	}
	memset(lssl, 0x0, sizeof(ssl_t));

#ifdef USE_PKCS11_TLS_HS_HASH
	/* Init hash contexts to INVALID */
	lssl->sec.msgHashSha256 = CK_INVALID_HANDLE;
	lssl->sec.msgHashSha256Final = CK_INVALID_HANDLE;
#ifdef USE_CLIENT_AUTH
	lssl->sec.msgHashSha256CertVerify = CK_INVALID_HANDLE;
	lssl->sec.msgHashSha384CertVerify = CK_INVALID_HANDLE;
#endif
#endif /* USE_PKCS11_TLS_HS_HASH */

#ifdef USE_AES_GCM
	lssl->nonceCtrLen = TLS_GCM_NONCE_LEN;
#endif	
/*
	Data buffers
*/
	lssl->outsize = SSL_DEFAULT_OUT_BUF_SIZE;
	lssl->outbuf = psMalloc(MATRIX_NO_POOL, lssl->outsize);
	if (lssl->outbuf == NULL) {
		psTraceInfo("Out of memory for outbuf in matrixSslNewSession\n");
		psFree(lssl);
		return PS_MEM_FAIL;
	}
	lssl->insize = SSL_DEFAULT_IN_BUF_SIZE;
	lssl->inbuf = psMalloc(MATRIX_NO_POOL, lssl->insize);
	if (lssl->inbuf == NULL) {
		psTraceInfo("Out of memory for inbuf in matrixSslNewSession\n");
		psFree(lssl->outbuf);
		psFree(lssl);
		return PS_MEM_FAIL;
	}

	lssl->sPool = pool;
	lssl->keys = keys;
	lssl->cipher = sslGetCipherSpec(lssl, SSL_NULL_WITH_NULL_NULL);
	sslActivateReadCipher(lssl);
	sslActivateWriteCipher(lssl);
	
	lssl->recordHeadLen = SSL3_HEADER_LEN;
	lssl->hshakeHeadLen = SSL3_HANDSHAKE_HEADER_LEN;
	
#ifdef SSL_REHANDSHAKES_ENABLED
	lssl->rehandshakeCount = DEFAULT_RH_CREDITS;
#endif /* SSL_REHANDSHAKES_ENABLED */
		

	if (flags & SSL_FLAGS_SERVER) {
		lssl->flags |= SSL_FLAGS_SERVER;
/*
		Client auth can only be requested by server, not set by client
*/
		if (flags & SSL_FLAGS_CLIENT_AUTH) {
			lssl->flags |= SSL_FLAGS_CLIENT_AUTH;
		}
		lssl->hsState = SSL_HS_CLIENT_HELLO;
		
		/* Is caller requesting specific protocol version for this client?
			Make sure it's enabled and use specificVersion var for err */
		specificVersion = 0;
		if (flags & SSL_FLAGS_SSLV3) {
#ifndef DISABLE_SSLV3		
			lssl->majVer = SSL3_MAJ_VER;
			lssl->minVer = SSL3_MIN_VER;
#else
			specificVersion = 1;
#endif			
		}

		if (flags & SSL_FLAGS_TLS_1_0) {
#ifdef USE_TLS
#ifndef DISABLE_TLS_1_0		
			lssl->majVer = TLS_MAJ_VER;
			lssl->minVer = TLS_MIN_VER;
#else
			specificVersion = 1; /* TLS enabled but TLS_1_0 disabled */
#endif
#else
			specificVersion = 1; /* TLS not even enabled */
#endif
		}

		if (flags & SSL_FLAGS_TLS_1_1) {
#ifdef USE_TLS_1_1
#ifndef DISABLE_TLS_1_1		
			lssl->majVer = TLS_MAJ_VER;
			lssl->minVer = TLS_1_1_MIN_VER;
#else
			specificVersion = 1; /* TLS_1_1 enabled but TLS_1_1 disabled */
#endif
#else
			specificVersion = 1; /* TLS not even enabled */
#endif		
		}

		if (flags & SSL_FLAGS_TLS_1_2) {
#ifdef USE_TLS_1_2		
			lssl->majVer = TLS_MAJ_VER;
			lssl->minVer = TLS_1_2_MIN_VER;
#else
			specificVersion = 1; /* TLS_1_2 disabled */
#endif
		}

		if (specificVersion) {
			psTraceInfo("ERROR: protocol version isn't compiled into matrix\n");
			matrixSslDeleteSession(lssl);
			return PS_ARG_FAIL;
		}
		
		
	} else {
/*
		Client is first to set protocol version information based on
		compile and/or the 'flags' parameter so header information in
		the handshake messages will be correctly set.
		
		Look for specific version first... but still have to make sure library
		has been compiled to support it
*/
		specificVersion = 0;

		if (flags & SSL_FLAGS_SSLV3) {
#ifndef DISABLE_SSLV3		
			lssl->majVer = SSL3_MAJ_VER;
			lssl->minVer = SSL3_MIN_VER;
			specificVersion = 1;
#else
			specificVersion = 2;
#endif			
		}

		if (flags & SSL_FLAGS_TLS_1_0) {
#ifdef USE_TLS
#ifndef DISABLE_TLS_1_0		
			lssl->majVer = TLS_MAJ_VER;
			lssl->minVer = TLS_MIN_VER;
			lssl->flags |= SSL_FLAGS_TLS;
			specificVersion = 1;
#else
			specificVersion = 2; /* TLS enabled but TLS_1_0 disabled */
#endif
#else
			specificVersion = 2; /* TLS not even enabled */
#endif		
		}

		if (flags & SSL_FLAGS_TLS_1_1) {
#ifdef USE_TLS_1_1
#ifndef DISABLE_TLS_1_1		
			lssl->majVer = TLS_MAJ_VER;
			lssl->minVer = TLS_1_1_MIN_VER;
			lssl->flags |= SSL_FLAGS_TLS | SSL_FLAGS_TLS_1_1;
			specificVersion = 1;
#else
			specificVersion = 2; /* TLS_1_1 enabled but TLS_1_1 disabled */
#endif
#else
			specificVersion = 2; /* TLS not even enabled */
#endif				
		}

		if (flags & SSL_FLAGS_TLS_1_2) {
#ifdef USE_TLS_1_2		
			lssl->majVer = TLS_MAJ_VER;
			lssl->minVer = TLS_1_2_MIN_VER;
			lssl->flags |= SSL_FLAGS_TLS | SSL_FLAGS_TLS_1_1 | SSL_FLAGS_TLS_1_2;
			specificVersion = 1;
#else
			specificVersion = 2; /* TLS_1_2 disabled */
#endif
		}

		if (specificVersion == 2) {
			psTraceInfo("ERROR: protocol version isn't compiled into matrix\n");
			matrixSslDeleteSession(lssl);
			return PS_ARG_FAIL;
		}
		
		if (specificVersion == 0) {
			/* Highest available if not specified (or not legal value) */
#ifdef USE_TLS
#ifndef DISABLE_TLS_1_0
			lssl->majVer = TLS_MAJ_VER;
			lssl->minVer = TLS_MIN_VER;
#endif		
#if defined(USE_TLS_1_1) && !defined(DISABLE_TLS_1_1)
			lssl->majVer = TLS_MAJ_VER;
			lssl->minVer = TLS_1_1_MIN_VER;
			lssl->flags |= SSL_FLAGS_TLS_1_1;
#endif /* USE_TLS_1_1 */
#ifdef USE_TLS_1_2
			lssl->majVer = TLS_MAJ_VER;
			lssl->minVer = TLS_1_2_MIN_VER;
			lssl->flags |= SSL_FLAGS_TLS_1_2 | SSL_FLAGS_TLS_1_1;
#endif
			if (lssl->majVer == 0) {
				/* USE_TLS enabled but all DISABLE_TLS versions are enabled so
					use SSLv3.  Compile time tests would catch if no versions
					are	enabled at all */
				lssl->majVer = SSL3_MAJ_VER;
				lssl->minVer = SSL3_MIN_VER;
			} else {
				lssl->flags |= SSL_FLAGS_TLS;
			}
		

#else /* USE_TLS */
			lssl->majVer = SSL3_MAJ_VER;
			lssl->minVer = SSL3_MIN_VER;
#endif /* USE_TLS */
		} /* end non-specific version */


		lssl->hsState = SSL_HS_SERVER_HELLO;
		if (session != NULL && session->cipherId != SSL_NULL_WITH_NULL_NULL) {
			lssl->cipher = sslGetCipherSpec(lssl, session->cipherId);
			if (lssl->cipher == NULL) {
				psTraceInfo("Invalid session id to matrixSslNewSession\n");
			} else {
#ifndef USE_PKCS11_TLS_ALGS
				memcpy(lssl->sec.masterSecret, session->masterSecret, 
					SSL_HS_MASTER_SIZE);
#endif // TODO PKCS11 
				lssl->sessionIdLen = SSL_MAX_SESSION_ID_SIZE;
				memcpy(lssl->sessionId, session->id, SSL_MAX_SESSION_ID_SIZE);
#ifdef USE_STATELESS_SESSION_TICKETS
				/* Possible no sessionId here at all if tickets used instead.
					Will know if all 0s */
				lssl->sessionIdLen = 0;	
				for (i = 0; i < SSL_MAX_SESSION_ID_SIZE; i++) {
					if (session->id[i] != 0x0) {
						lssl->sessionIdLen = SSL_MAX_SESSION_ID_SIZE;
						break;
					}
				}
#endif
			}
		}
		lssl->sid = session;
	}
	/* Clear these to minimize damage on a protocol parsing bug */
	memset(lssl->inbuf, 0x0, lssl->insize);
	memset(lssl->outbuf, 0x0, lssl->outsize);
	lssl->err = SSL_ALERT_NONE;
	*ssl = lssl;
	return PS_SUCCESS;
}

#ifdef USE_UNIFIED_PKCS11
static void pkcs11DestroyKeys(CK_SESSION_HANDLE ses, ssl_t *ssl)
{
	if (ssl->sec.writeKey != CK_INVALID_HANDLE) {
		pkcs11DestroyObject(ses, ssl->sec.writeKey);
	}
	if (ssl->sec.wKeyptr != CK_INVALID_HANDLE &&
			ssl->sec.wKeyptr != ssl->sec.writeKey) {
		pkcs11DestroyObject(ses, ssl->sec.wKeyptr);
	}
	if (ssl->sec.readKey != CK_INVALID_HANDLE) {
		pkcs11DestroyObject(ses, ssl->sec.readKey);
	}
	if (ssl->sec.rKeyptr != CK_INVALID_HANDLE &&
			ssl->sec.rKeyptr != ssl->sec.readKey) {
		pkcs11DestroyObject(ses, ssl->sec.rKeyptr);
	}
	
	if (ssl->sec.writeMAC != CK_INVALID_HANDLE) {
		pkcs11DestroyObject(ses, ssl->sec.writeMAC);
	}
	if (ssl->sec.readMAC != CK_INVALID_HANDLE) {
		pkcs11DestroyObject(ses, ssl->sec.readMAC);
	}
	if (ssl->sec.wMACptr != CK_INVALID_HANDLE &&
			ssl->sec.wMACptr != ssl->sec.writeMAC) {
		pkcs11DestroyObject(ses, ssl->sec.wMACptr);
	}
	if (ssl->sec.rMACptr != CK_INVALID_HANDLE &&
			ssl->sec.rMACptr != ssl->sec.readMAC) {
		pkcs11DestroyObject(ses, ssl->sec.rMACptr);
	}
}
#endif /* UNIFIED */

/******************************************************************************/
/*
	Delete an SSL session.  Some information on the session may stay around
	in the session resumption cache.
	SECURITY - We memset relevant values to zero before freeing to reduce 
	the risk of our keys floating around in memory after we're done.
*/
void matrixSslDeleteSession(ssl_t *ssl)
{
#ifdef USE_PKCS11
#ifdef USE_UNIFIED_PKCS11
	CK_SESSION_HANDLE	hSes;
#endif
	CK_SESSION_INFO	sesInfo;
#endif

	if (ssl == NULL) {
		return;
	}


	ssl->flags |= SSL_FLAGS_CLOSED;
/*
	If we have a sessionId, for servers we need to clear the inUse flag in 
	the session cache so the ID can be replaced if needed.  In the client case
	the caller should have called matrixSslGetSessionId already to copy the
	master secret and sessionId, so free it now.

	In all cases except a successful updateSession call on the server, the
	master secret must be freed.
*/
#ifdef USE_SERVER_SIDE_SSL
	if (ssl->sessionIdLen > 0 && (ssl->flags & SSL_FLAGS_SERVER)) {
		matrixUpdateSession(ssl);
	}
#ifdef USE_STATELESS_SESSION_TICKETS
	if ((ssl->flags & SSL_FLAGS_SERVER) && ssl->sid) {
		/* No allocated members possible on server side */
		psFree(ssl->sid);
	}
#endif
#endif /* USE_SERVER_SIDE_SSL */
	ssl->sessionIdLen = 0;

#ifndef USE_ONLY_PSK_CIPHER_SUITE
	if (ssl->expectedName) {
		psFree(ssl->expectedName);
	}
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	if (ssl->sec.cert) {
		psX509FreeCert(ssl->sec.cert);
		ssl->sec.cert = NULL;
	}

#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

#ifdef REQUIRE_DH_PARAMS
	if (ssl->sec.dhP) {
		psFree(ssl->sec.dhP); ssl->sec.dhP = NULL;
	}
	if (ssl->sec.dhG) {
		psFree(ssl->sec.dhG); ssl->sec.dhG = NULL;
	}
	psDhFreeKey(&ssl->sec.dhKeyPub);
	psDhFreeKey(&ssl->sec.dhKeyPriv);
#endif /* REQUIRE_DH_PARAMS	*/

#ifdef USE_ECC_CIPHER_SUITE
	if (ssl->sec.eccKeyPub) psEccFreeKey(&ssl->sec.eccKeyPub);
	if (ssl->sec.eccKeyPriv) psEccFreeKey(&ssl->sec.eccKeyPriv);
#endif /* USE_ECC_CIPHER_SUITE */	

/*
	Premaster could also be allocated if this DeleteSession is the result
	of a failed handshake.  This test is fine since all frees will NULL pointer
*/
	if (ssl->sec.premaster) {
#ifdef USE_UNIFIED_PKCS11
		/* Premaster object is held in premasterSize in this case.  Depending
			on when the error happen, the session will either be in a dedicated
			structure member or encoded in premaster itself */
		if (C_GetSessionInfo(ssl->sec.pkcs11Ses, &sesInfo) == CKR_OK) {
			hSes = ssl->sec.pkcs11Ses;
		} else {
			hSes = ssl->sec.premaster[3] << 24;
        	hSes += ssl->sec.premaster[2] << 16;
        	hSes += ssl->sec.premaster[1] << 8;
        	hSes += ssl->sec.premaster[0];	
		}
		if (ssl->sec.premasterSize != CK_INVALID_HANDLE) {
#ifdef PKCS11_STATS
			psTraceInfo("Destroying premaster object at DeleteSession\n");
#endif
			if (pkcs11DestroyObject(hSes, ssl->sec.premasterSize) != CKR_OK) {
				psTraceInfo("Error destroying premaster obj\n");
			}
			ssl->sec.premasterSize = CK_INVALID_HANDLE;
		}
#endif
		psFree(ssl->sec.premaster);
	}
#ifdef USE_UNIFIED_PKCS11
	/* The master secret is also stored as an object and is used in
		PRF for handshake hashing.  Could be here as well */
	if (ssl->sec.masterSecret != CK_INVALID_HANDLE) {
#ifdef PKCS11_STATS
		psTraceInfo("Destroying master object at DeleteSession\n");
#endif
		if (C_GetSessionInfo(ssl->sec.pkcs11Ses, &sesInfo) != CKR_OK) {
			psTraceInfo("Error: master object exists without session id\n");
		} else {
			if (pkcs11DestroyObject(ssl->sec.pkcs11Ses, ssl->sec.masterSecret)
					!= CKR_OK) {
				psTraceInfo("Error destroying premaster obj\n");
			}
			ssl->sec.masterSecret = CK_INVALID_HANDLE;
		}
	}
	/* Session itself is closed below through encryptCtx */
#endif /*  UNIFIED */
	if (ssl->fragMessage) {
		psFree(ssl->fragMessage);
	}


#ifdef USE_PKCS11_TLS_HS_HASH
#ifdef USE_TLS_1_2
	if (C_GetSessionInfo(ssl->sec.msgHashSha256, &sesInfo) == CKR_OK) {
		pkcs11CloseSession(ssl->sec.msgHashSha256);
	}
	if (C_GetSessionInfo(ssl->sec.msgHashSha256Final, &sesInfo) == CKR_OK) {
		pkcs11CloseSession(ssl->sec.msgHashSha256Final);
	}
	if (C_GetSessionInfo(ssl->sec.msgHashSha384, &sesInfo) == CKR_OK) {
		pkcs11CloseSession(ssl->sec.msgHashSha384);
	}
	if (C_GetSessionInfo(ssl->sec.msgHashSha384Final, &sesInfo) == CKR_OK) {
		pkcs11CloseSession(ssl->sec.msgHashSha384Final);
	}
#ifdef USE_CLIENT_AUTH
	if (C_GetSessionInfo(ssl->sec.msgHashSha256CertVerify, &sesInfo) == CKR_OK){
		pkcs11CloseSession(ssl->sec.msgHashSha256CertVerify);
	}
	if (C_GetSessionInfo(ssl->sec.msgHashSha384CertVerify, &sesInfo) == CKR_OK){
		pkcs11CloseSession(ssl->sec.msgHashSha384CertVerify);
	}
#endif /* USE_CLIENT_AUTH */
#endif /* USE_TLS_1_2 */
#endif /* USE_PKCS11_TLS_HS_HASH */
#ifdef USE_UNIFIED_PKCS11
	if (C_GetSessionInfo(ssl->sec.pkcs11Ses, &sesInfo) == CKR_OK) {
		pkcs11DestroyKeys(ssl->sec.pkcs11Ses, ssl);
		pkcs11CloseSession(ssl->sec.pkcs11Ses);
	}	
	if (C_GetSessionInfo(ssl->sec.oldCrypt, &sesInfo) == CKR_OK) {
		pkcs11CloseSession(ssl->sec.oldCrypt);
	}
#endif /* UNIFIED_PKCS11 */
#ifdef USE_PKCS11_SYMMETRIC
	if (C_GetSessionInfo(ssl->sec.encryptCtx, &sesInfo) == CKR_OK) {
		pkcs11CloseSession(ssl->sec.encryptCtx);
	}
	if (C_GetSessionInfo(ssl->sec.decryptCtx, &sesInfo) == CKR_OK) {
		pkcs11CloseSession(ssl->sec.decryptCtx);
	}
#endif /* USE_PKCS11_SYMMETRIC */


/*
	Free the data buffers, clear any remaining user data
*/
	memset(ssl->inbuf, 0x0, ssl->insize);
	memset(ssl->outbuf, 0x0, ssl->outsize);
	psFree(ssl->outbuf);
	psFree(ssl->inbuf);

	clearPkaAfter(ssl);
	clearFlightList(ssl);
/*
	The cipher and mac contexts are inline in the ssl structure, so
	clearing the structure clears those states as well.
*/
	memset(ssl, 0x0, sizeof(ssl_t));
	psFree(ssl);
}


/******************************************************************************/
/*
	Generic session option control for changing already connected sessions.
	(ie. rehandshake control).  arg param is future for options that may
	require a value.
*/
void matrixSslSetSessionOption(ssl_t *ssl, int32 option, void *arg)
{
	if (option == SSL_OPTION_FULL_HANDSHAKE) {
#ifdef USE_SERVER_SIDE_SSL
		if (ssl->flags & SSL_FLAGS_SERVER) {
			matrixClearSession(ssl, 1);
		}
#endif /* USE_SERVER_SIDE_SSL */
		ssl->sessionIdLen = 0;
		memset(ssl->sessionId, 0x0, SSL_MAX_SESSION_ID_SIZE);
	}

#ifdef SSL_REHANDSHAKES_ENABLED	
	if (option == SSL_OPTION_DISABLE_REHANDSHAKES) {
		ssl->rehandshakeCount = -1;
	}
	/* Get one credit if re-enabling */
	if (option == SSL_OPTION_REENABLE_REHANDSHAKES) {
		ssl->rehandshakeCount = 1;
	}
#endif
		
#if defined(USE_CLIENT_AUTH) && defined(USE_SERVER_SIDE_SSL) 
	if (ssl->flags & SSL_FLAGS_SERVER) {
		if (option == SSL_OPTION_DISABLE_CLIENT_AUTH) {
			ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
		} else if (option == SSL_OPTION_ENABLE_CLIENT_AUTH) {
			ssl->flags |= SSL_FLAGS_CLIENT_AUTH;
			matrixClearSession(ssl, 1);
		}
	}
#endif /* USE_CLIENT_AUTH && USE_SERVER_SIDE_SSL */
}

/******************************************************************************/
/*
	Will be true if the cipher suite is an 'anon' variety OR if the
	user certificate callback returned SSL_ALLOW_ANON_CONNECTION
*/
void matrixSslGetAnonStatus(ssl_t *ssl, int32 *certArg)
{
	*certArg = ssl->sec.anon;
}


#ifdef USE_SSL_INFORMATIONAL_TRACE
void matrixSslPrintHSDetails(ssl_t *ssl)
{
	if (ssl->hsState == SSL_HS_DONE) {
		psTraceInfo("\n");
		if (ssl->minVer == SSL3_MIN_VER) {
			psTraceInfo("SSL 3.0 ");
		} else if (ssl->minVer == TLS_MIN_VER) {
			psTraceInfo("TLS 1.0 ");
		} else if (ssl->minVer == TLS_1_1_MIN_VER) {
			psTraceInfo("TLS 1.1 ");
		} else if (ssl->minVer == TLS_1_2_MIN_VER) {
			psTraceInfo("TLS 1.2 ");
		}
		psTraceInfo("connection established: ");
		switch (ssl->cipher->ident) {
			case SSL_RSA_WITH_NULL_MD5:
				psTraceInfo("SSL_RSA_WITH_NULL_MD5\n");
				break;
			case SSL_RSA_WITH_NULL_SHA:
				psTraceInfo("SSL_RSA_WITH_NULL_SHA\n");
				break;
			case SSL_RSA_WITH_RC4_128_MD5:
				psTraceInfo("SSL_RSA_WITH_RC4_128_MD5\n");
				break;
			case SSL_RSA_WITH_RC4_128_SHA:
				psTraceInfo("SSL_RSA_WITH_RC4_128_SHA\n");
				break;
			case SSL_RSA_WITH_3DES_EDE_CBC_SHA:
				psTraceInfo("SSL_RSA_WITH_3DES_EDE_CBC_SHA\n");
				break;
			case TLS_RSA_WITH_AES_128_CBC_SHA:
				psTraceInfo("TLS_RSA_WITH_AES_128_CBC_SHA\n");
				break;
			case TLS_RSA_WITH_AES_256_CBC_SHA:
				psTraceInfo("TLS_RSA_WITH_AES_256_CBC_SHA\n");
				break;
			case SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
				psTraceInfo("SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA\n");
				break;
			case SSL_DH_anon_WITH_RC4_128_MD5:
				psTraceInfo("SSL_DH_anon_WITH_RC4_128_MD5\n");
				break;
			case SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
				psTraceInfo("SSL_DH_anon_WITH_3DES_EDE_CBC_SHA\n");
				break;
			case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
				psTraceInfo("TLS_DHE_RSA_WITH_AES_128_CBC_SHA\n");
				break;
			case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
				psTraceInfo("TLS_DHE_RSA_WITH_AES_256_CBC_SHA\n");
				break;
			case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
				psTraceInfo("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256\n");
				break;
			case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
				psTraceInfo("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256\n");
				break;
			case TLS_DH_anon_WITH_AES_128_CBC_SHA:
				psTraceInfo("TLS_DH_anon_WITH_AES_128_CBC_SHA\n");
				break;
			case TLS_DH_anon_WITH_AES_256_CBC_SHA:
				psTraceInfo("TLS_DH_anon_WITH_AES_256_CBC_SHA\n");
				break;
			case TLS_RSA_WITH_AES_128_CBC_SHA256:
				psTraceInfo("TLS_RSA_WITH_AES_128_CBC_SHA256\n");
				break;
			case TLS_RSA_WITH_AES_256_CBC_SHA256:
				psTraceInfo("TLS_RSA_WITH_AES_256_CBC_SHA256\n");
				break;
			case TLS_RSA_WITH_SEED_CBC_SHA:
				psTraceInfo("TLS_RSA_WITH_SEED_CBC_SHA\n");
				break;
			case TLS_RSA_WITH_IDEA_CBC_SHA:
				psTraceInfo("TLS_RSA_WITH_IDEA_CBC_SHA\n");
				break;	
			case TLS_PSK_WITH_AES_128_CBC_SHA:
				psTraceInfo("TLS_PSK_WITH_AES_128_CBC_SHA\n");
				break;
			case TLS_PSK_WITH_AES_128_CBC_SHA256:
				psTraceInfo("TLS_PSK_WITH_AES_128_CBC_SHA256\n");
				break;
			case TLS_PSK_WITH_AES_256_CBC_SHA384:
				psTraceInfo("TLS_PSK_WITH_AES_256_CBC_SHA384\n");
				break;	
			case TLS_PSK_WITH_AES_256_CBC_SHA:
				psTraceInfo("TLS_PSK_WITH_AES_256_CBC_SHA\n");
				break;
			case TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
				psTraceInfo("TLS_DHE_PSK_WITH_AES_128_CBC_SHA\n");
				break;
			case TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
				psTraceInfo("TLS_DHE_PSK_WITH_AES_256_CBC_SHA\n");
				break;
			case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
				psTraceInfo("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA\n");
				break;
			case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
				psTraceInfo("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA\n");
				break;
			case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
				psTraceInfo("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA\n");
				break;
			case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
				psTraceInfo("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA\n");
				break;
			case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
				psTraceInfo("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA\n");
				break;
			case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
				psTraceInfo("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA\n");
				break;	
			case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
				psTraceInfo("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256\n");
				break;	
			case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
				psTraceInfo("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384\n");
				break;	
			case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
				psTraceInfo("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA\n");
				break;
			case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
				psTraceInfo("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\n");
				break;	
			case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
				psTraceInfo("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n");
				break;	
			case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
				psTraceInfo("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA\n");
				break;
			case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
				psTraceInfo("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256\n");
				break;	
			case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
				psTraceInfo("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384\n");
				break;	
			case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
				psTraceInfo("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256\n");
				break;	
			case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
				psTraceInfo("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384\n");
				break;	
			case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
				psTraceInfo("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA\n");
				break;
			case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
				psTraceInfo("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256\n");
				break;
			case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
				psTraceInfo("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384\n");
				break;	
			case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
				psTraceInfo("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256\n");
				break;
			case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
				psTraceInfo("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384\n");
				break;	
			case TLS_RSA_WITH_AES_128_GCM_SHA256:
				psTraceInfo("TLS_RSA_WITH_AES_128_GCM_SHA256\n");
				break;
			case TLS_RSA_WITH_AES_256_GCM_SHA384:
				psTraceInfo("TLS_RSA_WITH_AES_256_GCM_SHA384\n");
				break;	
			case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
				psTraceInfo("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\n");
				break;
			case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
				psTraceInfo("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\n");
				break;
			case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
				psTraceInfo("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256\n");
				break;
			case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
				psTraceInfo("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384\n");
				break;
			default:
				psTraceIntInfo("!!!! DEFINE ME %d !!!!\n", ssl->cipher->ident);
		}
	}
	return;
}
#endif

/******************************************************************************/
/*
	Returns PS_TRUE if we've completed the SSL handshake.
*/
int32 matrixSslHandshakeIsComplete(ssl_t *ssl)
{	
	return (ssl->hsState == SSL_HS_DONE) ? PS_TRUE : PS_FALSE;
}

#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
/******************************************************************************/
/*
	Set a custom callback to receive the certificate being presented to the
	session to perform custom authentication if needed

	NOTE: Must define either USE_CLIENT_SIDE_SSL or USE_CLIENT_AUTH
	in matrixConfig.h
*/
void matrixSslSetCertValidator(ssl_t *ssl,
		int32 (*certValidator)(void *, psX509Cert_t *, int32))
{
	if ((ssl != NULL) && (certValidator != NULL)) {
#ifndef USE_ONLY_PSK_CIPHER_SUITE
		ssl->sec.validateCert = certValidator;
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */	
	}
}
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */

#ifdef USE_SERVER_SIDE_SSL
static void initSessionEntryChronList(void)
{
	uint32	i;
	DLListInit(&sessionChronList);
	/* Assign every session table entry with their ID from the start */
	for (i = 0; i < SSL_SESSION_TABLE_SIZE; i++) {
		DLListInsertTail(&sessionChronList, &sessionTable[i].chronList);
		sessionTable[i].id[0] = (unsigned char)(i & 0xFF);
		sessionTable[i].id[1] = (unsigned char)((i & 0xFF00) >> 8);
		sessionTable[i].id[2] = (unsigned char)((i & 0xFF0000) >> 16);
		sessionTable[i].id[3] = (unsigned char)((i & 0xFF000000) >> 24);
	}
}
/******************************************************************************/
/*
	Register a session in the session resumption cache.  If successful (rc >=0),
	the ssl sessionId and sessionIdLength fields will be non-NULL upon
	return.
*/
int32 matrixRegisterSession(ssl_t *ssl)
{
#ifndef USE_PKCS11_TLS_ALGS
	uint32				i;
	sslSessionEntry_t	*sess;
	DLListEntry			*pList;
	unsigned char		*id;

	if (!(ssl->flags & SSL_FLAGS_SERVER)) {
		return PS_FAILURE;
	}

#ifdef USE_STATELESS_SESSION_TICKETS
	/* Tickets override the other resumption mechanism */
	if (ssl->sid &&
			(ssl->sid->sessionTicketFlag == SESS_TICKET_FLAG_RECVD_EXT)) {
		/* Have recieved new ticket usage request by client */
		return PS_SUCCESS;
	}
#endif

/*
	Iterate the session table, looking for an empty entry (cipher null), or
	the oldest entry that is not in use
*/
#ifdef USE_MULTITHREADING
	psLockMutex(&sessionTableLock);
#endif /* USE_MULTITHREADING */

	if (DLListIsEmpty(&sessionChronList)) {
		/* All in use */
#ifdef USE_MULTITHREADING		
		psUnlockMutex(&sessionTableLock);
#endif /* USE_MULTITHREADING */			
		return PS_LIMIT_FAIL;

	}
	/* GetHead Detaches */
	pList = DLListGetHead(&sessionChronList);
	sess = DLListGetContainer(pList, sslSessionEntry_t, chronList);
	id = sess->id;
	i = (id[3] << 24) + (id[2] << 16) + (id[1] << 8) + id[0];
	if (i >= SSL_SESSION_TABLE_SIZE) {
#ifdef USE_MULTITHREADING			
		psUnlockMutex(&sessionTableLock);
#endif /* USE_MULTITHREADING */		
		return PS_LIMIT_FAIL;
	}	
	
/*
	Register the incoming masterSecret and cipher, which could still be null, 
	depending on when we're called.
*/
	memcpy(sessionTable[i].masterSecret, ssl->sec.masterSecret,
		SSL_HS_MASTER_SIZE);
	sessionTable[i].cipher = ssl->cipher;
	sessionTable[i].inUse += 1;	
/*
	The sessionId is the current serverRandom value, with the first 4 bytes
	replaced with the current cache index value for quick lookup later.
	FUTURE SECURITY - Should generate more random bytes here for the session
	id.  We re-use the server random as the ID, which is OK, since it is
	sent plaintext on the network, but an attacker listening to a resumed
	connection will also be able to determine part of the original server
	random used to generate the master key, even if he had not seen it
	initially.
*/
	memcpy(sessionTable[i].id + 4, ssl->sec.serverRandom,
		min(SSL_HS_RANDOM_SIZE, SSL_MAX_SESSION_ID_SIZE) - 4);
	ssl->sessionIdLen = SSL_MAX_SESSION_ID_SIZE;

	memcpy(ssl->sessionId, sessionTable[i].id, SSL_MAX_SESSION_ID_SIZE);
/*
	startTime is used to check expiry of the entry

	The versions are stored, because a cached session must be reused 
	with same SSL version.
*/
	psGetTime(&sessionTable[i].startTime);
	sessionTable[i].majVer = ssl->majVer;
	sessionTable[i].minVer = ssl->minVer;
#ifdef USE_MULTITHREADING	
	psUnlockMutex(&sessionTableLock);
#endif /* USE_MULTITHREADING */	
	return i;
#else /* PKCS11 TODO */
	psTraceInfo("Session resumption not supported in PKCS#11\n");
	return PS_SUCCESS;
#endif
}

/******************************************************************************/
/*
	Decrement inUse to keep the reference count meaningful
*/
int32 matrixClearSession(ssl_t *ssl, int32 remove)
{
	unsigned char	*id;
	uint32	i;

	if (ssl->sessionIdLen <= 0) {
		return PS_ARG_FAIL;
	}
	id = ssl->sessionId;
	
	i = (id[3] << 24) + (id[2] << 16) + (id[1] << 8) + id[0];
	if (i >= SSL_SESSION_TABLE_SIZE) {
		return PS_LIMIT_FAIL;
	}
#ifdef USE_MULTITHREADING	
	psLockMutex(&sessionTableLock);
#endif /* USE_MULTITHREADING */
	sessionTable[i].inUse -= 1;
	if (sessionTable[i].inUse == 0) {
		DLListInsertTail(&sessionChronList, &sessionTable[i].chronList);
	}
	
/*
	If this is a full removal, actually delete the entry.  Also need to
	clear any RESUME flag on the ssl connection so a new session
	will be correctly registered.
*/
	if (remove) {
		memset(ssl->sessionId, 0x0, SSL_MAX_SESSION_ID_SIZE);
		ssl->sessionIdLen = 0;
		ssl->flags &= ~SSL_FLAGS_RESUMED;
		/* Always preserve the id for chronList */
		memset(sessionTable[i].id + 4, 0x0, SSL_MAX_SESSION_ID_SIZE - 4);
		memset(sessionTable[i].masterSecret, 0x0, SSL_HS_MASTER_SIZE);
		sessionTable[i].cipher = NULL;
	}
#ifdef USE_MULTITHREADING	
	psUnlockMutex(&sessionTableLock);
#endif /* USE_MULTITHREADING */	
	return PS_SUCCESS;
}

/******************************************************************************/
/*
	Look up a session ID in the cache.  If found, set the ssl masterSecret
	and cipher to the pre-negotiated values
*/
int32 matrixResumeSession(ssl_t *ssl)
{
#ifndef USE_PKCS11_TLS_ALGS
	psTime_t		accessTime;
	unsigned char	*id;
	uint32	i;

	if (!(ssl->flags & SSL_FLAGS_SERVER)) {
		return PS_ARG_FAIL;
	}
	if (ssl->sessionIdLen <= 0) {
		return PS_ARG_FAIL;
	}
	id = ssl->sessionId;

	i = (id[3] << 24) + (id[2] << 16) + (id[1] << 8) + id[0];
#ifdef USE_MULTITHREADING		
	psLockMutex(&sessionTableLock);
#endif /* USE_MULTITHREADING */
	if (i >= SSL_SESSION_TABLE_SIZE || sessionTable[i].cipher == NULL) {
#ifdef USE_MULTITHREADING			
		psUnlockMutex(&sessionTableLock);
#endif /* USE_MULTITHREADING */		
		return PS_LIMIT_FAIL;
	}
/*
	Id looks valid.  Update the access time for expiration check.
	Expiration is done on daily basis (86400 seconds)
*/
	psGetTime(&accessTime);
	if ((memcmp(sessionTable[i].id, id, 
			(uint32)min(ssl->sessionIdLen, SSL_MAX_SESSION_ID_SIZE)) != 0) ||
			(psDiffMsecs(sessionTable[i].startTime,	accessTime) >
			SSL_SESSION_ENTRY_LIFE) || (sessionTable[i].majVer != ssl->majVer)
			|| (sessionTable[i].minVer != ssl->minVer)) {
#ifdef USE_MULTITHREADING			
		psUnlockMutex(&sessionTableLock);
#endif /* USE_MULTITHREADING */
		return PS_FAILURE;
	}

	memcpy(ssl->sec.masterSecret, sessionTable[i].masterSecret,
		SSL_HS_MASTER_SIZE);
	ssl->cipher = sessionTable[i].cipher;
	sessionTable[i].inUse += 1;
	if (sessionTable[i].inUse == 1) {
		DLListRemove(&sessionTable[i].chronList);
	}
#ifdef USE_MULTITHREADING		
	psUnlockMutex(&sessionTableLock);
#endif /* USE_MULTITHREADING */	

#else /* PKCS11 TODO */
	psTraceInfo("Session resumption not supported in PKCS#11\n");
#endif
	return PS_SUCCESS;
}

/******************************************************************************/
/*
	Update session information in the cache.
	This is called when we've determined the master secret and when we're
	closing the connection to update various values in the cache.
*/
int32 matrixUpdateSession(ssl_t *ssl)
{
#ifndef USE_PKCS11_TLS_ALGS
	unsigned char	*id;
	uint32	i;

	if (!(ssl->flags & SSL_FLAGS_SERVER)) {
		return PS_ARG_FAIL;
	}
	if ((id = ssl->sessionId) == NULL) {
		return PS_ARG_FAIL;
	}
	if (ssl->sessionIdLen == 0) {
		/* No table entry.  matrixRegisterSession was full of inUse entries */
		return PS_LIMIT_FAIL;
	}
	i = (id[3] << 24) + (id[2] << 16) + (id[1] << 8) + id[0];
	if (i >= SSL_SESSION_TABLE_SIZE) {
		return PS_LIMIT_FAIL;
	}
/*
	If there is an error on the session, invalidate for any future use
*/
#ifdef USE_MULTITHREADING
	psLockMutex(&sessionTableLock);
#endif /* USE_MULTITHREADING */		
	sessionTable[i].inUse += ssl->flags & SSL_FLAGS_CLOSED ? -1 : 0;
	if (sessionTable[i].inUse == 0) {
		/* End of the line */
		DLListInsertTail(&sessionChronList, &sessionTable[i].chronList);
	}
	if (ssl->flags & SSL_FLAGS_ERROR) {
		memset(sessionTable[i].masterSecret, 0x0, SSL_HS_MASTER_SIZE);
		sessionTable[i].cipher = NULL;
#ifdef USE_MULTITHREADING		
		psUnlockMutex(&sessionTableLock);
#endif /* USE_MULTITHREADING */			
		return PS_FAILURE;
	}
	memcpy(sessionTable[i].masterSecret, ssl->sec.masterSecret,
		SSL_HS_MASTER_SIZE);
	sessionTable[i].cipher = ssl->cipher;
#ifdef USE_MULTITHREADING	
	psUnlockMutex(&sessionTableLock);
#endif /* USE_MULTITHREADING */		
#else
	psTraceInfo("Session resumption not supported in PKCS#11\n");
#endif
	return PS_SUCCESS;
}

/* If client sent a ServerNameIndication extension, see if we have those
	keys to load */
int32 matrixServerSetKeysSNI(ssl_t *ssl, char *host, int32 hostLen)
{
	sslKeys_t	*keys;
	
	if (ssl->sni_cb) {
		ssl->sniUsed++; /* extension was actually handled */
		keys = NULL;
		(ssl->sni_cb)((void*)ssl, host, hostLen, &keys) ;
		if (keys) {
			ssl->keys = keys;
			return 0;
		}
		return PS_UNSUPPORTED_FAIL; /* callback didn't provide keys */
	}
	
	return 0; /* No callback registered.  Go with default */
}

#ifdef USE_STATELESS_SESSION_TICKETS
/* This implementation supports AES-128/AES-256_CBC and HMAC-SHA256 */


/*
	Remove a named key from the list.
	
	NOTE: If this list can get very large the faster DLList API should be
	used instead of this single linked list.
*/
int32 matrixSslDeleteSessionTicketKey(sslKeys_t *keys, unsigned char name[16])
{
	psSessionTicketKeys_t	*lkey, *prev;
	
#ifdef USE_MULTITHREADING
	psLockMutex(&g_sessTicketLock);
#endif
	lkey = keys->sessTickets;
	prev = NULL;
	while (lkey) {
		if (lkey->inUse == 0 && (memcmp(lkey->name, name, 16) == 0)) {
			if (prev == NULL) {
				/* removing the first in the list */
				if (lkey->next == NULL) {
					/* no more list == no more session ticket support */
					psFree(lkey);
					keys->sessTickets = NULL;
#ifdef USE_MULTITHREADING
					psUnlockMutex(&g_sessTicketLock);
#endif
					return PS_SUCCESS;
				}
				/* first in list but not alone */
				keys->sessTickets = lkey->next;
				psFree(lkey);
#ifdef USE_MULTITHREADING
				psUnlockMutex(&g_sessTicketLock);
#endif
				return PS_SUCCESS;
			}
			/* Middle of list.  Join previous with our next */
			prev->next = lkey->next;
			psFree(lkey);
#ifdef USE_MULTITHREADING
			psUnlockMutex(&g_sessTicketLock);
#endif
			return PS_SUCCESS;
		}
		prev = lkey;
		lkey = lkey->next;
	}
#ifdef USE_MULTITHREADING
	psUnlockMutex(&g_sessTicketLock);
#endif
	return PS_FAILURE; /* not found */

}

/*	This will be called on ticket decryption if the named key is not
	in the current local list */
void matrixSslSetSessionTicketCallback(sslKeys_t *keys,
		int32 (*ticket_cb)(void *, unsigned char[16], short))
{
	keys->ticket_cb = ticket_cb;
}

/* The first in the list will be the one used for all newly issued tickets */
int32 matrixSslLoadSessionTicketKeys(sslKeys_t *keys, unsigned char name[16],
		unsigned char *symkey, short symkeyLen,
		unsigned char *hashkey, short hashkeyLen)
{
	psSessionTicketKeys_t	*keylist, *prev;
	int32					i = 0;
	
	
	/* AES-128 or AES-256 */
	if (symkeyLen != 16 && symkeyLen != 32) {
		return PS_LIMIT_FAIL;
	}
	/* SHA256 only */
	if (hashkeyLen != 32) {
		return PS_LIMIT_FAIL;
	}
	
#ifdef USE_MULTITHREADING
	psLockMutex(&g_sessTicketLock);
#endif
	if (keys->sessTickets == NULL) {
		/* first one */
		keys->sessTickets = psMalloc(keys->pool, sizeof(psSessionTicketKeys_t));
		if (keys->sessTickets == NULL) {
#ifdef USE_MULTITHREADING
			psUnlockMutex(&g_sessTicketLock);
#endif
			return PS_MEM_FAIL;
		}
		keylist = keys->sessTickets;
	} else {
		/* append */
		keylist = keys->sessTickets;
		while (keylist) {
			prev = keylist;
			keylist = keylist->next;
			i++;
		}
		if (i > SSL_SESSION_TICKET_LIST_LEN) {
			psTraceInfo("Session ticket list > SSL_SESSION_TICKET_LIST_LEN\n");
#ifdef USE_MULTITHREADING
			psUnlockMutex(&g_sessTicketLock);
#endif
			return PS_LIMIT_FAIL;
		}
		keylist = psMalloc(keys->pool, sizeof(psSessionTicketKeys_t));
		if (keylist == NULL) {
#ifdef USE_MULTITHREADING
			psUnlockMutex(&g_sessTicketLock);
#endif
			return PS_MEM_FAIL;
		}
		prev->next = keylist;
	}
	
	memset(keylist, 0x0, sizeof(psSessionTicketKeys_t));
	keylist->hashkeyLen = hashkeyLen;
	keylist->symkeyLen = symkeyLen;
	memcpy(keylist->name, name, 16);
	memcpy(keylist->hashkey, hashkey, hashkeyLen);
	memcpy(keylist->symkey, symkey, symkeyLen);
#ifdef USE_MULTITHREADING
	psUnlockMutex(&g_sessTicketLock);
#endif
	return PS_SUCCESS;
}

/* Size of encrypted session ticket using 16-byte block	cipher and SHA-256 */
int32 matrixSessionTicketLen(void)
{
	int32	len = 0;
	
	/* Master secret, 2 version, 2 cipher suite, 4 timestamp are encypted */
	len += SSL_HS_MASTER_SIZE + 2 + 2 + 4;
	len += psPadLenPwr2(len, 16);
	/* Name, IV and MAC plaintext */
	len	+= 16 + 16 + SHA256_HASH_SIZE;
	return len;
}

/* Plaintext Format:
	4 bytes lifetime hint
	2 bytes length of following:
		16 bytes name
		16 bytes IV
		<encrypt>
		2 bytes protocol version
		2 bytes cipher suite
		48 bytes master secret
		4 bytes timestamp
		<padding /encrypt>
		32 byte HMAC starting at 'name'
*/
int32 matrixCreateSessionTicket(ssl_t *ssl, unsigned char *out, int32 *outLen)
{
	int32					len, ticketLen, pad;
	uint32					timeSecs;
	psTime_t				t;
	psCipherContext_t		ctx;
	psHmacContext_t			dgst;
	psSessionTicketKeys_t	*keys;
	unsigned char			*enc, *c = out;
	unsigned char			randno[16];
	
	ticketLen = matrixSessionTicketLen();
	if ((ticketLen + 6) > *outLen) {
		return PS_LIMIT_FAIL;
	}
	
	/* Lifetime hint taken from define in matrixsslConfig.h */
	timeSecs = SSL_SESSION_ENTRY_LIFE / 1000; /* it's in milliseconds */
	*c = (unsigned char)((timeSecs & 0xFF000000) >> 24); c++;
	*c = (unsigned char)((timeSecs & 0xFF0000) >> 16); c++;
	*c = (unsigned char)((timeSecs & 0xFF00) >> 8); c++;
	*c = (unsigned char)(timeSecs & 0xFF); c++;
	
	/* Len of ticket */
	*c = (ticketLen & 0xFF00) >> 8; c++;
	*c = ticketLen & 0xFF; c++;
	
	/* Do the heavier CPU stuff outside lock */
	timeSecs = psGetTime(&t);
	psGetEntropy(randno, 16); /* make up an IV */
	
#ifdef USE_MULTITHREADING
	psLockMutex(&g_sessTicketLock);
#endif
	/* Ticket itself */
	keys = ssl->keys->sessTickets;
	/* name */
	memcpy(c, keys->name, 16);
	c += 16;
	memcpy(c, randno, 16); /*IV */
	c += 16;
	enc = c; /* encrypt start */
	*c = ssl->majVer; c++;
	*c = ssl->minVer; c++;
	*c = (ssl->cipher->ident & 0xFF00) >> 8; c++;
	*c = ssl->cipher->ident & 0xFF; c++;
	memcpy(c, ssl->sec.masterSecret, SSL_HS_MASTER_SIZE);
	c += SSL_HS_MASTER_SIZE;
	
	
	*c = (unsigned char)((timeSecs & 0xFF000000) >> 24); c++;
	*c = (unsigned char)((timeSecs & 0xFF0000) >> 16); c++;
	*c = (unsigned char)((timeSecs & 0xFF00) >> 8); c++;
	*c = (unsigned char)(timeSecs & 0xFF); c++;
	
	len = SSL_HS_MASTER_SIZE + 4 + 4;
	
	pad = psPadLenPwr2(len, 16);
	c += sslWritePad(c, (unsigned char)pad);
	len += pad;
	
	/* out + 6 + 16 (name) is pointing at IV */
	psAesInit((psAesCipherContext_t *)&ctx, out + 6 + 16, keys->symkey, keys->symkeyLen);
	psAesEncrypt((psAesCipherContext_t *)&ctx, enc, enc, len);

	/* HMAC starting from the Name */
	psHmacSha2Init(&dgst, keys->hashkey, keys->hashkeyLen,
		SHA256_HASH_SIZE);
	psHmacSha2Update(&dgst, out + 6, len + 16 + 16, SHA256_HASH_SIZE);
	psHmacSha2Final(&dgst, c, SHA256_HASH_SIZE);
#ifdef USE_MULTITHREADING
	psUnlockMutex(&g_sessTicketLock);
#endif
	*outLen = len + SHA256_HASH_SIZE + 16 + 16 + 6;
	return PS_SUCCESS;
}

/* Note: careful, this function assumes the lock is on so must relock before
	leaving if SUCCESS case.  Failure assumes it's unlocked */
static int32 getTicketKeys(ssl_t *ssl, unsigned char *c,
				psSessionTicketKeys_t **keys)
{
	psSessionTicketKeys_t	*lkey;
	unsigned char			name[16];
	short					cachedTicket = 0;

	/* First 16 bytes are the key name */
	memcpy(name, c, 16);
	
	*keys = NULL;
	/* check our cached list beginning with our own encryption key */
	lkey = ssl->keys->sessTickets;
	while (lkey) {
		if (memcmp(lkey->name, name, 16) == 0) {
			lkey->inUse = 1;
			*keys = lkey;
			/* Have the key.  Invoke callback with SUCCESS */
			if (ssl->keys->ticket_cb) {
				cachedTicket++;
				break;
			} else {
				return PS_SUCCESS;
			}
		}
		lkey = lkey->next;
	}
	/* didn't find it.  Ask user */
	if (ssl->keys->ticket_cb) {
#ifdef USE_MULTITHREADING
		/* Unlock. Cback will likely call matrixSslLoadSessionTicketKeys */
		psUnlockMutex(&g_sessTicketLock);
#endif
		if (ssl->keys->ticket_cb((struct sslKeys_t*)ssl->keys, name,
				cachedTicket) < 0) {
			lkey->inUse = 0; /* inUse could be set in the odd case where we
				found the cached key but the user didn't want to use it. */
			return PS_FAILURE; /* user couldn't find it either */
		} else {
			/* found it */
#ifdef USE_MULTITHREADING
			psLockMutex(&g_sessTicketLock);
#endif
			if (cachedTicket == 0) {
				/* it's been found and added at end of list.  confirm this */
				lkey = ssl->keys->sessTickets;
				if (lkey == NULL) {
#ifdef USE_MULTITHREADING
					psUnlockMutex(&g_sessTicketLock);
#endif
					return PS_FAILURE; /* user claims they added, but empty */
				}
				while (lkey->next) {
					lkey = lkey->next;
				}
				if (memcmp(lkey->name, c, 16) != 0) {
#ifdef USE_MULTITHREADING
					psUnlockMutex(&g_sessTicketLock);
#endif
					return PS_FAILURE; /* user claims to have added, but... */
				}
				lkey->inUse = 1;
				*keys = lkey;
			}
			return PS_SUCCESS;
		}
	}
	return PS_FAILURE; /* not in list and no callback registered */
}

int32 matrixUnlockSessionTicket(ssl_t *ssl, unsigned char *in, int32 inLen)
{
	unsigned char		*c, *enc;
	unsigned char		hash[SHA256_HASH_SIZE];
	unsigned char		name[16];
	psSessionTicketKeys_t	*keys;
	psHmacContext_t		dgst;
	psCipherContext_t	ctx;
	int32				len;
	psTime_t			t;
	uint32				majVer, minVer, cipherSuite, time, now;
	
	c = in;
	
	len = inLen;

#ifdef USE_MULTITHREADING
	psLockMutex(&g_sessTicketLock);
#endif
	if (getTicketKeys(ssl, c, &keys) < 0) {
		psTraceInfo("No key found for session ticket\n");
		/* We've been unlocked in getTicketKeys */
		return PS_FAILURE;
	}
	
	/* Mac is over the name, IV and encrypted data */
	psHmacSha2Init(&dgst, keys->hashkey, keys->hashkeyLen,
		SHA256_HASH_SIZE);
	psHmacSha2Update(&dgst, c, len - SHA256_HASH_SIZE, SHA256_HASH_SIZE);
	psHmacSha2Final(&dgst, hash, SHA256_HASH_SIZE);
	
	memcpy(name, c, 16);
	c += 16;
	
	/* out is pointing at IV */
	psAesInit((psAesCipherContext_t *)&ctx, c, keys->symkey, keys->symkeyLen);
	psAesDecrypt((psAesCipherContext_t *)&ctx, c + 16, c + 16, len - 16 - 16 - SHA256_HASH_SIZE);
	keys->inUse = 0;
#ifdef USE_MULTITHREADING
	psUnlockMutex(&g_sessTicketLock);
#endif
	
	/* decrypted marker */
	enc = c + 16;
	
	c+= (len - 16 - SHA256_HASH_SIZE); /* already moved past name */
	
	if (memcmp(hash, c, SHA256_HASH_SIZE) != 0) {
		psTraceInfo("HMAC check failure on session ticket\n");
		return PS_FAILURE;
	}
	
	majVer = *enc; enc++;
	minVer = *enc; enc++;
	
	/* Match protcol version */
	if (majVer != ssl->majVer || minVer != ssl->minVer) {
		psTraceInfo("Protocol check failure on session ticket\n");
		return PS_FAILURE;
	}
	
	cipherSuite = *enc << 8; enc++;
	cipherSuite += *enc; enc++;
	
	/* Force cipher suite */
	if ((ssl->cipher = sslGetCipherSpec(ssl, cipherSuite)) == NULL) {
		psTraceInfo("Cipher suite check failure on session ticket\n");
		return PS_FAILURE;
	}
	
	/* Set aside masterSecret */
	memcpy(ssl->sid->masterSecret, enc, SSL_HS_MASTER_SIZE);
	enc += SSL_HS_MASTER_SIZE;
	
	/* Check lifetime */
	time = *enc << 24; enc++;
	time += *enc << 16; enc++;
	time += *enc << 8; enc++;
	time += *enc; enc++;
	
	now = psGetTime(&t);
	
	if ((now - time) > (SSL_SESSION_ENTRY_LIFE / 1000)) {
		/* Expired session ticket.  New one will be issued */
		psTraceInfo("Session ticket was expired\n");
		return PS_FAILURE;
	}
	ssl->sid->cipherId = cipherSuite;
	
	return PS_SUCCESS;
}
#endif /* USE_STATELESS_SESSION_TICKETS */
#endif /* USE_SERVER_SIDE_SSL */

#ifdef USE_CLIENT_SIDE_SSL
/******************************************************************************/
/*
	Get session information from the ssl structure and populate the given
	session structure.  Session will contain a copy of the relevant session
	information, suitable for creating a new, resumed session.

	NOTE: Must define USE_CLIENT_SIDE_SSL in matrixConfig.h 
	
	sslSessionId_t myClientSession;
	
	...&myClientSession
*/
int32 matrixSslGetSessionId(ssl_t *ssl, sslSessionId_t *session)
{

	if (ssl == NULL || ssl->flags & SSL_FLAGS_SERVER || session == NULL) {
		return PS_ARG_FAIL;
	}

	if (ssl->cipher != NULL && ssl->cipher->ident != SSL_NULL_WITH_NULL_NULL && 
			ssl->sessionIdLen == SSL_MAX_SESSION_ID_SIZE) {
		session->cipherId = ssl->cipher->ident;
		memcpy(session->id, ssl->sessionId, ssl->sessionIdLen);
#ifndef USE_PKCS11_TLS_ALGS
		memcpy(session->masterSecret, ssl->sec.masterSecret, 
			SSL_HS_MASTER_SIZE);
#endif /* TODO: pkcs11 */
		return PS_SUCCESS;
	}
#ifdef USE_STATELESS_SESSION_TICKETS
	if (ssl->cipher != NULL && ssl->cipher->ident != SSL_NULL_WITH_NULL_NULL && 
			session->sessionTicket != NULL && session->sessionTicketLen > 0) {
		session->cipherId = ssl->cipher->ident;
#ifndef USE_PKCS11_TLS_ALGS
		memcpy(session->masterSecret, ssl->sec.masterSecret, 
			SSL_HS_MASTER_SIZE);
#endif /* TODO: pkcs11 */
		return PS_SUCCESS;	
	}
#endif	

	return PS_FAILURE;
}


int32 matrixSslCreateSNIext(psPool_t *pool, unsigned char *host, int32 hostLen,
	unsigned char **extOut, int32 *extLen)
{
	unsigned char	*c;
	
	*extLen = hostLen + 5;
	if ((c = psMalloc(pool, *extLen)) == NULL) {
		return PS_MEM_FAIL;
	}
	memset(c, 0, *extLen);
	*extOut = c;
	
	*c = ((hostLen + 3) & 0xFF00) >> 8; c++;
	*c = (hostLen + 3) & 0xFF; c++;
	c++; /* host_name enum */
	*c = (hostLen & 0xFF00) >> 8; c++;
	*c = hostLen  & 0xFF; c++;
	memcpy(c, host, hostLen);
	return PS_SUCCESS;
}
#endif /* USE_CLIENT_SIDE_SSL */

/******************************************************************************/
/*
	Rehandshake. Free any allocated sec members that will be repopulated
*/
void sslResetContext(ssl_t *ssl)
{
#ifdef USE_CLIENT_SIDE_SSL
	if (!(ssl->flags & SSL_FLAGS_SERVER)) {
		ssl->anonBk = ssl->sec.anon;
		ssl->flagsBk = ssl->flags;
		ssl->bFlagsBk = ssl->bFlags;
	}
#endif
	ssl->sec.anon = 0;
#ifdef USE_SERVER_SIDE_SSL
	if (ssl->flags & SSL_FLAGS_SERVER) {
		matrixClearSession(ssl, 0);
	}
#endif /* USE_SERVER_SIDE_SSL */

#ifdef USE_DHE_CIPHER_SUITE
	ssl->flags &= ~SSL_FLAGS_DHE_KEY_EXCH;
	ssl->flags &= ~SSL_FLAGS_DHE_WITH_RSA;
#ifdef USE_ANON_DH_CIPHER_SUITE
	ssl->flags &= ~SSL_FLAGS_ANON_CIPHER;
#endif /* USE_ANON_DH_CIPHER_SUITE */
#ifdef USE_ECC_CIPHER_SUITE	
	ssl->flags &= ~SSL_FLAGS_ECC_CIPHER;
	ssl->flags &= ~SSL_FLAGS_DHE_WITH_RSA;
	ssl->flags &= ~SSL_FLAGS_DHE_WITH_DSA;
#endif /* USE_ECC_CIPHER_SUITE */
#endif /* USE_DHE_CIPHER_SUITE */

#ifdef USE_PSK_CIPHER_SUITE
	ssl->flags &= ~SSL_FLAGS_PSK_CIPHER;
#endif /* USE_PSK_CIPHER_SUITE */

	ssl->bFlags = 0;  /* Reset buffer control */
}

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)

static int wildcardMatch(char *wild, char *s)
{
	char *c, *e;

	c = wild;
	if (*c == '*') {
		c++;
		//TODO - this is actually a parse error
		if (*c != '.') return -1;
		if (strchr(s, '@')) return -1;
		if ((e = strchr(s, '.')) == NULL) return -1;
		if (strcasecmp(c, e) == 0) return 0;
	} else if (*c == '.') {
		//TODO - this is actually a parse error
		return -1;
	} else if (strcasecmp(c, s) == 0) {
		return 0;
	}
	return -1;
}

/******************************************************************************/
/*
	Subject certs is the leaf first chain of certs from the peer
	Issuer certs is a flat list of trusted CAs loaded by LoadKeys
*/
int32 matrixValidateCerts(psPool_t *pool, psX509Cert_t *subjectCerts,
							psX509Cert_t *issuerCerts, char *expectedName,
							psX509Cert_t **foundIssuer)
{
	psX509Cert_t		*ic, *sc;
	x509GeneralName_t	*n;
	x509v3extensions_t	*ext;
	char				ip[16];
	int32				rc, pathLen = 0;
	
	*foundIssuer = NULL;
/*
	Case #1 is no issuing cert.  Going to want to check that the final
	subject cert presented is a SelfSigned CA
*/
	if (issuerCerts == NULL) {
		return psX509AuthenticateCert(pool, subjectCerts, NULL, foundIssuer);
	}
/*
	Case #2 is an issuing cert AND possibly a chain of subjectCerts.
 */
	sc = subjectCerts;
	if ((ic = sc->next) != NULL) {
/*
		 We do have a chain. Authenticate the chain before even looking
		 to our issuer CAs.
*/
		while (ic->next != NULL) {
			if ((rc = psX509AuthenticateCert(pool, sc, ic, foundIssuer))
					< PS_SUCCESS) {
				return rc; 
			}
			if (ic->extensions.bc.pathLenConstraint >= 0) {
				/* Make sure the pathLen is not exceeded */
				if (ic->extensions.bc.pathLenConstraint < pathLen) {
					psTraceInfo("Authentication failed due to X.509 pathLen\n");
					sc->authStatus = PS_CERT_AUTH_FAIL_PATH_LEN;
					return PS_CERT_AUTH_FAIL_PATH_LEN;
				}
			}
			pathLen++;
			sc = sc->next;
			ic = sc->next;
		}
/*
		Test using the parent-most in chain as the subject 
*/
		if ((rc = psX509AuthenticateCert(pool, sc, ic, foundIssuer))
				< PS_SUCCESS) {
			return rc; 
		}
		if (ic->extensions.bc.pathLenConstraint >= 0) {
			/* Make sure the pathLen is not exceeded */
			if (ic->extensions.bc.pathLenConstraint < pathLen) {
				psTraceInfo("Authentication failed due to X.509 pathLen\n");
				sc->authStatus = PS_CERT_AUTH_FAIL_PATH_LEN;
				return PS_CERT_AUTH_FAIL_PATH_LEN;
			}
		}
		pathLen++;
/*
		Lastly, set subject to the final cert for the real issuer test below
*/
		sc = sc->next;
	}
	
/*
	 Now loop through the issuer certs and see if we can authenticate this chain
	 
	 If subject cert was a chain, that has already been authenticated above so
	 we only need to pass in the single parent-most cert to be tested against
*/
	*foundIssuer = NULL;
	ic = issuerCerts;
	while (ic != NULL) {
		sc->authStatus = PS_FALSE;
		if ((rc = psX509AuthenticateCert(pool, sc, ic, foundIssuer))
				== PS_SUCCESS) {
			if (ic->extensions.bc.pathLenConstraint >= 0) {
				/* Make sure the pathLen is not exceeded */
				if (ic->extensions.bc.pathLenConstraint < pathLen) {
					psTraceInfo("Authentication failed due to X.509 pathLen\n");
					rc = sc->authStatus = PS_CERT_AUTH_FAIL_PATH_LEN;
					return rc;
				}
			}

			/* Validate extensions of leaf certificate */
			ext = &subjectCerts->extensions;

			/* Validate extended key usage */
			if (ext->critFlags & EXT_CRIT_FLAG(EXT_EXTND_KEY_USAGE)) {
				if (!(ext->ekuFlags & (EXT_KEY_USAGE_TLS_SERVER_AUTH | 
						EXT_KEY_USAGE_TLS_CLIENT_AUTH))) {
					_psTrace("End-entity certificate not for TLS usage!\n");
					subjectCerts->authFailFlags |= PS_CERT_AUTH_FAIL_EKU_FLAG;
					rc = subjectCerts->authStatus = PS_CERT_AUTH_FAIL_EXTENSION;
				}
			}

			/* Check the subject/altSubject. Should match requested domain */
			if (expectedName == NULL) {
				return rc;
			}
			if (wildcardMatch(subjectCerts->subject.commonName, 
					expectedName) == 0) {
				return rc;
			}
			for (n = ext->san; n != NULL; n = n->next) {
				if (n->id == GN_DNS) {
					if (wildcardMatch((char *)n->data, expectedName) == 0) {
						return rc;
					}
				} else if (n->id == GN_EMAIL) {
					/* Email doesn't have wildcards */
					if (strcasecmp((char *)n->data, expectedName) == 0) {
						return rc;
					}
				} else if (n->id == GN_IP) {
					snprintf(ip, 15, "%u.%u.%u.%u", 
						(unsigned char)(n->data[0]),
						(unsigned char )(n->data[1]),
						(unsigned char )(n->data[2]),
						(unsigned char )(n->data[3]));
					ip[15] = '\0';
					if (strcmp(ip, expectedName) == 0) {
						return rc;
					}
				}
			}
			psTraceInfo("Authentication failed: no matching subject\n");
			subjectCerts->authFailFlags |= PS_CERT_AUTH_FAIL_SUBJECT_FLAG;
			rc = subjectCerts->authStatus = PS_CERT_AUTH_FAIL_EXTENSION;
			return rc;
		} else if (rc == PS_MEM_FAIL) {
/*
			OK to fail on the authentication because there may be a list here
			but MEM failures prevent us from continuing at all.
*/
			return rc;
		}
		ic = ic->next;
	}
/*
	Success would have returned if it happen
*/
	return PS_CERT_AUTH_FAIL;
}
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */

/******************************************************************************/
/*
	Calls a user defined callback to allow for manual validation of the
	certificate.
*/
int32 matrixUserCertValidator(ssl_t *ssl, int32 alert,
						psX509Cert_t *subjectCert, sslCertCb_t certValidator)
{
	int32			status;

/*
	If there is no callback, return PS_SUCCESS because there has already been
	a test for the case where the certificate did NOT PASS pubkey test
	and a callback does not exist to manually handle.  
	
	It is highly recommended that the user manually verify, but the cert
	material has internally authenticated and the user has implied that
	is sufficient enough.
*/
	if (certValidator == NULL) {
		psTraceInfo("Internal cert auth passed. No user callback registered\n");
		return PS_SUCCESS;
	}
	
/*
	Finally, let the user know what the alert status is and 
	give them the cert material to access.  Any non-zero value in alert
	indicates there is a pending fatal alert.	
	 
	The user can look at authStatus members if they want to examine the cert
	that did not pass.
*/
	if (alert == SSL_ALERT_NONE) {
		status = 0;
	} else {
		status = alert;
	}

/*
	The user callback
*/
	return certValidator(ssl, subjectCert, status);
}
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */


/******************************************************************************/
#ifdef USE_MATRIXSSL_STATS
void matrixSslRegisterStatCallback(ssl_t *ssl, void (*stat_cb)(void *ssl,
		void *stats_ptr, int32 type, int32 value), void *stats_ptr)
{
	ssl->statCb = stat_cb;
	ssl->statsPtr = stats_ptr;
}

void matrixsslUpdateStat(ssl_t *ssl, int32 type, int32 value)
{
	if (ssl->statCb) {
		(ssl->statCb)(ssl, ssl->statsPtr, type, value);
	}
}

#endif /* USE_MATRIXSSL_STATS */
/******************************************************************************/

