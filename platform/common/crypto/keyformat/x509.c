/*
 *	x509.c
 *	Release $Name: MATRIXSSL-3-6-1-OPEN $
 *
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
#include "cryptocore.h"
#if TLS_CONFIG_HARD_CRYPTO
#include "wm_crypto_hard.h"
#endif
#ifdef POSIX
#include <time.h>
#endif

/******************************************************************************/
#ifdef USE_X509
/******************************************************************************/

#define MAX_CERTS_PER_FILE		16

#ifdef USE_CERT_PARSE
/*
	Certificate extensions
*/
#define IMPLICIT_ISSUER_ID		1
#define IMPLICIT_SUBJECT_ID		2
#define EXPLICIT_EXTENSION		3

/*
	Distinguished Name attributes
*/
#define ATTRIB_COUNTRY_NAME		6
#define ATTRIB_LOCALITY			7
#define ATTRIB_ORGANIZATION		10
#define ATTRIB_ORG_UNIT			11
#define ATTRIB_DN_QUALIFIER		46
#define ATTRIB_STATE_PROVINCE	8
#define ATTRIB_COMMON_NAME		3

static const struct {
		unsigned char	hash[16];
		int32			id;
} extTable[] = {
	{ { 0xa5, 0xc4, 0x5e, 0x9a, 0xa3, 0xbb, 0x71, 0x2f, 0x07,
		0xf7, 0x4c, 0xd0, 0xcd, 0x95, 0x65, 0xda }, EXT_BASIC_CONSTRAINTS },
	{ { 0xf5, 0xab, 0x88, 0x49, 0xc4, 0xfd, 0xa2, 0x64, 0x6d,
		0x06, 0xa2, 0x3e, 0x83, 0x9b, 0xef, 0xbb }, EXT_KEY_USAGE },
	{ { 0x91, 0x54, 0x28, 0xcc, 0x81, 0x59, 0x8c, 0x71, 0x8c,
		0x53, 0xa8, 0x4d, 0xeb, 0xd3, 0xc2, 0x18 }, EXT_SUBJ_KEY_ID },
	{ { 0x48, 0x2d, 0xff, 0x49, 0xf7, 0xab, 0x93, 0xe8, 0x1f,
		0x57, 0xb5, 0xaf, 0x7f, 0xaa, 0x31, 0xbb }, EXT_AUTH_KEY_ID },
	{ { 0x5c, 0x70, 0xcb, 0xf5, 0xa4, 0x07, 0x5a, 0xcc, 0xd1,
		0x55, 0xd2, 0x44, 0xdd, 0x62, 0x2c, 0x0c }, EXT_ALT_SUBJECT_NAME },
	{ { 0xec, 0x90, 0xac, 0x73, 0xc4, 0x94, 0x66, 0x8d, 0xb0,
		0x21, 0xd0, 0xe7, 0x5c, 0x55, 0xae, 0x33 }, EXT_CRL_DIST_PTS },
	{ { 0xba, 0x71, 0x0c, 0xec, 0x2b, 0x68, 0xf7, 0xbf, 0x08,
		0x3d, 0x28, 0xf3, 0xb3, 0x12, 0xc3, 0xcb }, EXT_AUTH_INFO_ACC },
	{ { 0xd5, 0x62, 0x88, 0xbb, 0xd4, 0x8c, 0x4d, 0xbb, 0xdb,
		0x1a, 0xe5, 0xa9, 0xff, 0x20, 0xdd, 0xde }, EXT_NAME_CONSTRAINTS },
	{ { 0x20, 0x15, 0x83, 0x52, 0xd4, 0x45, 0x52, 0xb1, 0x0e,
		0x99, 0x93, 0x8b, 0x5e, 0xe9, 0xca, 0x82 }, EXT_EXTND_KEY_USAGE },
	{ { 0 }, -1 } /* Must be last for proper termination */
};

/*
	Hybrid ASN.1/X.509 cert parsing helpers
*/
static int32 getExplicitVersion(unsigned char **pp, uint32 len, int32 expVal,
						int32 *val);
static int32 getTimeValidity(psPool_t *pool, unsigned char **pp, uint32 len,
				int32 *notBeforeTimeType, int32 *notAfterTimeType,
				char **notBefore, char **notAfter);
static int32 getImplicitBitString(psPool_t *pool, unsigned char **pp,
				uint32 len,	int32 impVal, unsigned char **bitString,
				uint32 *bitLen);
static int32 validateDateRange(psX509Cert_t *cert);

#ifdef USE_RSA
static int32 x509ConfirmSignature(unsigned char *sigHash, unsigned char *sigOut,
							uint32 sigLen);
#endif
		
#ifdef USE_CRL
static void x509FreeRevoked(x509revoked_t **revoked);
#endif
		
#endif /* USE_CERT_PARSE */
		

/******************************************************************************/
#ifdef MATRIX_USE_FILE_SYSTEM
/******************************************************************************/

static int32 pemCertFileBufToX509(psPool_t *pool, unsigned char *fileBuf,
		int32 fileBufLen, psList_t **x509certList);
/******************************************************************************/
/*
	Open a PEM X.509 certificate file and parse it
	
	Memory info:
		Caller must free outcert with psX509FreeCert on function success
		Caller does not have to free outcert on function failure
*/
int32 psX509ParseCertFile(psPool_t *pool, char *fileName,
						psX509Cert_t **outcert, int32 flags)
{
	int32			fileBufLen, err;
	unsigned char	*fileBuf;
	psList_t		*fileList, *currentFile, *x509list, *frontX509;
	psX509Cert_t	*currentCert, *firstCert, *prevCert;

	*outcert = NULL;
/*
	First test to see if there are multiple files being passed in.
	Looking for a semi-colon delimiter
*/
	if ((err = psParseList(pool, fileName, ';', &fileList)) < 0) {
		return err;
	}
	currentFile = fileList;
	firstCert = prevCert = NULL;
/*
	Recurse each individual file
*/
	while (currentFile) {
		if ((err = psGetFileBuf(pool, (char*)currentFile->item, &fileBuf,
				&fileBufLen)) < PS_SUCCESS) {
			psFreeList(fileList);
			if (firstCert) psX509FreeCert(firstCert);
			return err;
		}

		if ((err = pemCertFileBufToX509(pool, fileBuf, fileBufLen, &x509list))
				< PS_SUCCESS) {
			psFreeList(fileList);
			psFree(fileBuf);
			if (firstCert) psX509FreeCert(firstCert);
			return err;
		}
		psFree(fileBuf);

		frontX509 = x509list;
/*
		Recurse each individual cert buffer from within the file 
*/
		while (x509list != NULL) {	
			if ((err = psX509ParseCert(pool, x509list->item, x509list->len,
					&currentCert, flags)) < PS_SUCCESS) {
				psX509FreeCert(currentCert);	
				psFreeList(fileList);
				psFreeList(frontX509);
				if (firstCert) psX509FreeCert(firstCert);
				return err;
			}

			x509list = x509list->next;
			if (firstCert == NULL) {
				firstCert = currentCert;
			} else {
				prevCert->next = currentCert;
			}
			prevCert = currentCert;
			currentCert = currentCert->next;
		}
		currentFile = currentFile->next;
		psFreeList(frontX509);
	}
	psFreeList(fileList);

	*outcert = firstCert;

	return PS_SUCCESS;
}

/******************************************************************************/
/*
*/
static int32 pemCertFileBufToX509(psPool_t *pool, unsigned char *fileBuf,
		int32 fileBufLen, psList_t **x509certList)
{
	psList_t		*front, *prev, *current;
	char			*start, *end, *endTmp, *chFileBuf;

	*x509certList = NULL;
	if (fileBufLen < 0 || fileBuf == NULL) {
		psTraceCrypto("Bad parameters to pemCertFileBufToX509\n");
		return PS_ARG_FAIL;
	}
	front = current = psMalloc(pool, sizeof(psList_t));
	if (current == NULL) {
		psError("Memory allocation error first pemCertFileBufToX509\n");
		return PS_MEM_FAIL;
	}
	memset(current, 0x0, sizeof(psList_t));
	chFileBuf = (char*)fileBuf;
	while (fileBufLen > 0) {
		if (((start = strstr(chFileBuf, "-----BEGIN")) != NULL) &&
				((start = strstr(chFileBuf, "CERTIFICATE-----")) != NULL) &&
				((end = strstr(start, "-----END")) != NULL) &&
				((endTmp = strstr(end,"CERTIFICATE-----")) != NULL)) {
			start += strlen("CERTIFICATE-----");
			if (current == NULL) {
				current = psMalloc(pool, sizeof(psList_t));
				if (current == NULL) {
					psFreeList(front);
					psError("Memory allocation error: pemCertFileBufToX509\n");
					return PS_MEM_FAIL;
				}
				memset(current, 0x0, sizeof(psList_t));
				prev->next = current;
			}
			current->len = (int32)(end - start);
			end = endTmp + strlen("CERTIFICATE-----");
			while (*end == '\x0d' || *end == '\x0a' || *end == '\x09'
				   || *end == ' ') {
				end++;
			}
		} else {
			psFreeList(front);
			psTraceCrypto("File buffer does not look to be X.509 PEM format\n");
			return PS_PARSE_FAIL;
		}
		current->item = psMalloc(pool, current->len);
		if (current->item == NULL) {
			psFreeList(front);
			psError("Memory allocation error: pemCertFileBufToX509\n");
			return PS_MEM_FAIL;
		}
		memset(current->item, '\0', current->len);
		
		fileBufLen -= (int32)((unsigned char*)end - fileBuf);
		fileBuf = (unsigned char*)end;
		
		if (psBase64decode((unsigned char*)start, current->len, current->item,
							 (uint32*)&current->len) != 0) {
			psFreeList(front);
			psTraceCrypto("Unable to base64 decode certificate\n");
			return PS_PARSE_FAIL;
		}
		prev = current;
		current = current->next;
		chFileBuf = (char*)fileBuf;
	}
	*x509certList = front;
	return PS_SUCCESS;
}
#endif /* MATRIX_USE_FILE_SYSTEM */
/******************************************************************************/


/******************************************************************************/
/*
	Parse an X509 v3 ASN.1 certificate stream
	http://tools.ietf.org/html/rfc3280
		
	flags
		CERT_STORE_UNPARSED_BUFFER 
		CERT_STORE_DN_BUFFER
		
	Memory info:
		Caller must always free outcert with psX509FreeCert.  Even on failure
*/
int32 psX509ParseCert(psPool_t *pool, unsigned char *pp, uint32 size, 
						psX509Cert_t **outcert, int32 flags)
{
	psX509Cert_t		*cert;
	unsigned char		*p, *end, *certStart;
	uint32				len;
	int32				parsing, rc;
#ifdef USE_CERT_PARSE	
	psDigestContext_t	hashCtx;
	unsigned char		*certEnd;
	uint32				certLen;
	int32				plen;
#endif	

/*
	Allocate the cert structure right away.  User MUST always call
	psX509FreeCert regardless of whether this function succeeds.
	memset is important because the test for NULL is what is used
	to determine what to free
*/
	*outcert = cert = psMalloc(pool, sizeof(psX509Cert_t));
	if (cert == NULL) {
		psError("Memory allocation failure in psX509ParseCert\n");
		return PS_MEM_FAIL;
	}
	memset(cert, 0x0, sizeof(psX509Cert_t));
	
	p = pp;
	end = p + size;
/*
	Certificate  ::=  SEQUENCE  {
		tbsCertificate		TBSCertificate,
		signatureAlgorithm	AlgorithmIdentifier,
		signatureValue		BIT STRING }
*/
	parsing = 1;
	while (parsing) {

		certStart = p;	
		if ((rc = getAsnSequence(&p, (uint32)(end - p), &len)) < 0) {
			psTraceCrypto("Initial cert parse error\n");
			return rc;
		}
/*
		 If the user has specified to keep the ASN.1 buffer in the X.509
		 structure, now is the time to account for it
*/
		if (flags & CERT_STORE_UNPARSED_BUFFER) {
			cert->binLen = len + (int32)(p - certStart);
			cert->unparsedBin = psMalloc(pool, cert->binLen);
			if (cert->unparsedBin == NULL) {
				psError("Memory allocation error in psX509ParseCert\n");
				return PS_MEM_FAIL;
			}
			memcpy(cert->unparsedBin, certStart, cert->binLen);
		}
		
#ifdef USE_CERT_PARSE
		certStart = p;
/*	
		TBSCertificate  ::=  SEQUENCE  {
		version			[0]		EXPLICIT Version DEFAULT v1,
		serialNumber			CertificateSerialNumber,
		signature				AlgorithmIdentifier,
		issuer					Name,
		validity				Validity,
		subject					Name,
		subjectPublicKeyInfo	SubjectPublicKeyInfo,
		issuerUniqueID	[1]		IMPLICIT UniqueIdentifier OPTIONAL,
							-- If present, version shall be v2 or v3
		subjectUniqueID	[2]	IMPLICIT UniqueIdentifier OPTIONAL,
							-- If present, version shall be v2 or v3
		extensions		[3]	EXPLICIT Extensions OPTIONAL
							-- If present, version shall be v3	}
*/
		if ((rc = getAsnSequence(&p, (uint32)(end - p), &len)) < 0) {
			psTraceCrypto("ASN sequence parse error\n");
			return rc;
		}
		certEnd = p + len;
		certLen = certEnd - certStart;

/*
		Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
*/
		if ((rc = getExplicitVersion(&p, (uint32)(end - p), 0, &cert->version))
				< 0) {
			psTraceCrypto("ASN version parse error\n");
			return rc;
		}
		if (cert->version != 2) {		
			psTraceIntCrypto("ERROR: non-v3 certificate version %d insecure\n",
				cert->version);
			return PS_PARSE_FAIL;
		}
/*
		CertificateSerialNumber  ::=  INTEGER
		There is a special return code for a missing serial number that
		will get written to the parse warning flag
*/
		if ((rc = getSerialNum(pool, &p, (uint32)(end - p), &cert->serialNumber,
				&cert->serialNumberLen)) < 0) {
			psTraceCrypto("ASN serial number parse error\n");
			return rc;
		}
/*
		AlgorithmIdentifier  ::=  SEQUENCE  {
		algorithm				OBJECT IDENTIFIER,
		parameters				ANY DEFINED BY algorithm OPTIONAL }
*/
		if ((rc = getAsnAlgorithmIdentifier(&p, (uint32)(end - p),
				&cert->certAlgorithm, &plen)) < 0) {
			psTraceCrypto("Couldn't parse algorithm identifier for certAlgorithm\n");
			return rc;
		}
		if (plen != 0) {
			psTraceCrypto("Unsupported X.509 certAlgorithm\n");
			return PS_UNSUPPORTED_FAIL;
		}
/*
		Name ::= CHOICE {
		RDNSequence }

		RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

		RelativeDistinguishedName ::= SET OF AttributeTypeAndValue

		AttributeTypeAndValue ::= SEQUENCE {
		type	AttributeType,
		value	AttributeValue }

		AttributeType ::= OBJECT IDENTIFIER

		AttributeValue ::= ANY DEFINED BY AttributeType
*/
		if ((rc = psX509GetDNAttributes(pool, &p, (uint32)(end - p),
				&cert->issuer, flags)) < 0) {
			psTraceCrypto("Couldn't parse issuer DN attributes\n");
			return rc;
		}
/*
		Validity ::= SEQUENCE {
		notBefore	Time,
		notAfter	Time	}
*/
		if ((rc = getTimeValidity(pool, &p, (uint32)(end - p),
				&cert->notBeforeTimeType, &cert->notAfterTimeType,
				&cert->notBefore, &cert->notAfter)) < 0) {
			psTraceCrypto("Couldn't parse validity\n");
			return rc;
		}

		/* SECURITY - platforms without a date function will always succeed */
		if ((rc = validateDateRange(cert)) < 0) {
			psTraceCrypto("Validity date check failed\n");
			return rc;
		}
/*
		Subject DN
*/
		if ((rc = psX509GetDNAttributes(pool, &p, (uint32)(end - p),
				&cert->subject,	flags)) < 0) {
			psTraceCrypto("Couldn't parse subject DN attributes\n");
			return rc;
		}
/*
		SubjectPublicKeyInfo  ::=  SEQUENCE  {
		algorithm			AlgorithmIdentifier,
		subjectPublicKey	BIT STRING	}
*/
		if ((rc = getAsnSequence(&p, (uint32)(end - p), &len)) < 0) {
			psTraceCrypto("Couldn't get ASN sequence for pubKeyAlgorithm\n");
			return rc;
		}
		if ((rc = getAsnAlgorithmIdentifier(&p, (uint32)(end - p),
				&cert->pubKeyAlgorithm, &plen)) < 0) {
			psTraceCrypto("Couldn't parse algorithm id for pubKeyAlgorithm\n");
			return rc;
		}
/*
		Allocate for generic type and then populate with correct type
		based on pubKeyAlgorithm OID
*/
		cert->publicKey.key = psMalloc(pool, sizeof(pubKeyUnion_t));
		if (cert->publicKey.key == NULL) {
			psError("Memory allocation error in psX509ParseCert\n");
			return PS_MEM_FAIL;
		}
		memset(cert->publicKey.key, 0x0, sizeof(pubKeyUnion_t));
		if (cert->pubKeyAlgorithm == OID_ECDSA_KEY_ALG) {
#ifdef USE_ECC
			if (plen == 0 || plen > (int32)(end - p)) {
				psTraceCrypto("Bad params on EC OID\n");
				return PS_PARSE_FAIL;
			}
			if (getEcPubKey(pool, &p, (int32)(end - p),
					(psEccKey_t*)(&cert->publicKey.key->ecc)) < 0) {
				return PS_PARSE_FAIL;
			} 
			cert->publicKey.type = PS_ECC;
			cert->publicKey.keysize = cert->publicKey.key->ecc.dp->size * 2;
			if (cert->publicKey.keysize < (MIN_ECC_SIZE / 8)) {
				psTraceIntCrypto("ECC key size < %d\n", MIN_ECC_SIZE);
				return PS_PARSE_FAIL;
			}
#else /* USE_ECC */
			psTraceCrypto("ECC public key algorithm not enabled in cert parse");
			return PS_UNSUPPORTED_FAIL;
#endif /* USE_ECC */
		} else if (cert->pubKeyAlgorithm == OID_RSA_KEY_ALG) {
			psAssert(plen == 0); /* No parameters on RSA pub key OID */
#ifdef USE_RSA
			if ((rc = getAsnRsaPubKey(pool, &p, (uint32)(end - p),
				(psRsaKey_t*)(&cert->publicKey.key->rsa))) < 0) {
				psTraceCrypto("Couldn't get RSA pub key from cert\n");
				return rc;
			}
			cert->publicKey.type = PS_RSA;
			cert->publicKey.keysize = cert->publicKey.key->rsa.size;
			if (cert->publicKey.keysize < (MIN_RSA_SIZE / 8)) {
				psTraceIntCrypto("RSA key size < %d\n", MIN_RSA_SIZE);
				return PS_PARSE_FAIL;
			}
#else /* USE_RSA */
			psTraceCrypto("RSA public key algorithm disabled in cert parse\n");
			return PS_UNSUPPORTED_FAIL;
#endif /* USE_RSA */
		} else {
			psTraceCrypto("Unsupported public key algorithm in cert parse\n");
			return PS_UNSUPPORTED_FAIL;
		}

/*
		As the next three values are optional, we can do a specific test here
*/
		if (*p != (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
			if (getImplicitBitString(pool, &p, (uint32)(end - p),
						IMPLICIT_ISSUER_ID, &cert->uniqueIssuerId,
						&cert->uniqueIssuerIdLen) < 0 ||
					getImplicitBitString(pool, &p, (uint32)(end - p),
						IMPLICIT_SUBJECT_ID, &cert->uniqueSubjectId,
						&cert->uniqueSubjectIdLen) < 0 ||
					getExplicitExtensions(pool, &p, (uint32)(end - p),
						EXPLICIT_EXTENSION, &cert->extensions, 0) < 0) {
				psTraceCrypto("There was an error parsing a certificate\n");
				psTraceCrypto("extension.  This is likely caused by an\n");
				psTraceCrypto("extension format that is not currently\n");
				psTraceCrypto("recognized.  Please email Inside support\n");
				psTraceCrypto("to add support for the extension.\n\n");
				return PS_PARSE_FAIL;
			}
		}
/*
		This is the end of the cert.  Do a check here to be certain
*/
		if (certEnd != p) {
			psTraceCrypto("Error.  Expecting end of cert\n");
			return PS_LIMIT_FAIL;
		}
		
/*
		Reject any cert that doesn't have a commonName or a subjectAltName 
*/
		if (cert->subject.commonName == NULL && cert->extensions.san == NULL) {
			psTraceCrypto("Error. Cert has no name information\n");
			return PS_PARSE_FAIL;
		}
/*
		Certificate signature info
*/
		if ((rc = getAsnAlgorithmIdentifier(&p, (uint32)(end - p),
				&cert->sigAlgorithm, &plen)) < 0) {
			psTraceCrypto("Couldn't get algorithm identifier for sigAlgorithm\n");
			return rc;
		}
		if (plen != 0) {
			psTraceCrypto("Unsupported X.509 sigAlgorithm\n");
			return PS_UNSUPPORTED_FAIL;
		}
/*
		Signature algorithm must match that specified in TBS cert
*/
		if (cert->certAlgorithm != cert->sigAlgorithm) {
			psTraceCrypto("Parse error: mismatched signature type\n");
			return PS_CERT_AUTH_FAIL;
		}
		
/*
		Compute the hash of the cert here for CA validation
*/
		if (cert->certAlgorithm == OID_SHA1_RSA_SIG) {
			psSha1Init(&hashCtx);
			psSha1Update(&hashCtx, certStart, certLen);
			psSha1Final(&hashCtx, cert->sigHash);
		}
#ifdef ENABLE_MD5_SIGNED_CERTS
		else if (cert->certAlgorithm == OID_MD5_RSA_SIG) {
			psMd5Init(&hashCtx);
			psMd5Update(&hashCtx, certStart, certLen);
			psMd5Final(&hashCtx, cert->sigHash);
		}
#endif
#ifdef USE_SHA256		 
		else if (cert->certAlgorithm == OID_SHA256_RSA_SIG) {
			psSha256Init(&hashCtx);
			psSha256Update(&hashCtx, certStart, certLen);
			psSha256Final(&hashCtx, cert->sigHash);
		}
#endif /* USE_SHA256 */	
#ifdef USE_SHA384		 
		else if (cert->certAlgorithm == OID_SHA384_RSA_SIG) {
			psSha384Init(&hashCtx);
			psSha384Update(&hashCtx, certStart, certLen);
			psSha384Final(&hashCtx, cert->sigHash);
		}
#endif /* USE_SHA256 */
#ifdef USE_SHA512		 
		else if (cert->certAlgorithm == OID_SHA512_RSA_SIG) {
			psSha512Init(&hashCtx);
			psSha512Update(&hashCtx, certStart, certLen);
			psSha512Final(&hashCtx, cert->sigHash);
		}
#endif /* USE_SHA512 */
#ifdef USE_MD2
		else if (cert->certAlgorithm == OID_MD2_RSA_SIG) {
			psMd2Init(&hashCtx);
			psMd2Update(&hashCtx, certStart, certLen);
			psMd2Final(&hashCtx, cert->sigHash);
		}
#endif /* USE_MD2 */
#ifdef USE_ECC
		else if (cert->certAlgorithm == OID_SHA1_ECDSA_SIG) {
			psSha1Init(&hashCtx);
			psSha1Update(&hashCtx, certStart, certLen);
			psSha1Final(&hashCtx, cert->sigHash);
		}
#ifdef USE_SHA256
		else if (cert->certAlgorithm == OID_SHA256_ECDSA_SIG) {
			psSha256Init(&hashCtx);
			psSha256Update(&hashCtx, certStart, certLen);
			psSha256Final(&hashCtx, cert->sigHash);
		}
#endif /* USE_SHA256 */
#ifdef USE_SHA384
		else if (cert->certAlgorithm == OID_SHA384_ECDSA_SIG) {
			psSha384Init(&hashCtx);
			psSha384Update(&hashCtx, certStart, certLen);
			psSha384Final(&hashCtx, cert->sigHash);
		}
#endif /* USE_SHA384 */
#ifdef USE_SHA512
		else if (cert->certAlgorithm == OID_SHA512_ECDSA_SIG) {
			psSha512Init(&hashCtx);
			psSha512Update(&hashCtx, certStart, certLen);
			psSha512Final(&hashCtx, cert->sigHash);
		}
#endif /* USE_SHA512 */
#endif /* USE_ECC */		
		/* 6 empty bytes is plenty enough to know if sigHash didn't calculate */
		if (memcmp(cert->sigHash, "\0\0\0\0\0\0", 6) == 0) {
			psTraceIntCrypto("No library signature alg support for cert: %d\n",
				cert->certAlgorithm);
			return PS_UNSUPPORTED_FAIL;
		}


		if ((rc = psX509GetSignature(pool, &p, (uint32)(end - p),
				&cert->signature, &cert->signatureLen)) < 0) {
			psTraceCrypto("Couldn't parse signature\n");
			return rc;
		}
		
#else /* !USE_CERT_PARSE */
		p = certStart + len + (int32)(p - certStart);
#endif /* USE_CERT_PARSE */
/*
		The ability to parse additional chained certs is a PKI product
		feature addition.  Chaining in MatrixSSL is handled internally.
*/
		if (p != end) {
			if (*p == 0x0 && *(p + 1) == 0x0) {
				parsing = 0; /* An indefinite length stream was passed in */
				/* caller will have to deal with skipping these becuase they
					would have read off the TL of this ASN.1 stream */
			} else {
				cert->next = psMalloc(pool, sizeof(psX509Cert_t));
				if (cert->next == NULL) {
					psError("Memory allocation error in psX509ParseCert\n");
					return PS_MEM_FAIL;
				}
				cert = cert->next;
				memset(cert, 0x0, sizeof(psX509Cert_t));
#ifdef USE_CERT_PARSE
#endif
			}
		} else {
			parsing = 0;
		}
	}
		
	return (int32)(p - pp);
}

#ifdef USE_CERT_PARSE
void x509FreeExtensions(x509v3extensions_t *extensions)
{

	x509GeneralName_t		*active, *inc;
	
	if (extensions->san) {
		active = extensions->san;
		while (active != NULL) {
			inc = active->next;
			psFree(active->data);
			psFree(active);
			active = inc;
		}
	}

#ifdef USE_CRL
	if (extensions->crlDist) {
		active = extensions->crlDist;
		while (active != NULL) {
			inc = active->next;
			psFree(active->data);
			psFree(active);
			active = inc;
		}
	}
#endif /* CRL */

#ifdef USE_FULL_CERT_PARSE
	if (extensions->nameConstraints.excluded) {
		active = extensions->nameConstraints.excluded;
		while (active != NULL) {
			inc = active->next;
			psFree(active->data);
			psFree(active);
			active = inc;
		}
	}
	if (extensions->nameConstraints.permitted) {
		active = extensions->nameConstraints.permitted;
		while (active != NULL) {
			inc = active->next;
			psFree(active->data);
			psFree(active);
			active = inc;
		}
	}
#endif /* USE_FULL_CERT_PARSE */
	if (extensions->sk.id)		psFree(extensions->sk.id);
	if (extensions->ak.keyId)	psFree(extensions->ak.keyId);
	if (extensions->ak.serialNum) psFree(extensions->ak.serialNum);
	if (extensions->ak.attribs.commonName)
		psFree(extensions->ak.attribs.commonName);
	if (extensions->ak.attribs.country) psFree(extensions->ak.attribs.country);
	if (extensions->ak.attribs.state) psFree(extensions->ak.attribs.state);
	if (extensions->ak.attribs.locality)
		psFree(extensions->ak.attribs.locality);
	if (extensions->ak.attribs.organization)
		psFree(extensions->ak.attribs.organization);
	if (extensions->ak.attribs.orgUnit) psFree(extensions->ak.attribs.orgUnit);
	if (extensions->ak.attribs.dnenc) psFree(extensions->ak.attribs.dnenc);
}
#endif /* USE_CERT_PARSE */

/******************************************************************************/
/*
	User must call after all calls to psX509ParseCert
	(we violate the coding standard a bit here for clarity)
*/
void psX509FreeCert(psX509Cert_t *cert)
{
	psX509Cert_t			*curr, *next;

	curr = cert;
	while (curr) {
		if (curr->unparsedBin)			psFree(curr->unparsedBin);
#ifdef USE_CERT_PARSE		
		psX509FreeDNStruct(&curr->issuer);
		psX509FreeDNStruct(&curr->subject);
		if (curr->serialNumber)			psFree(curr->serialNumber);
		if (curr->notBefore)			psFree(curr->notBefore);
		if (curr->notAfter)				psFree(curr->notAfter);
		if (curr->signature)			psFree(curr->signature);
		if (curr->uniqueIssuerId)		psFree(curr->uniqueIssuerId);
		if (curr->uniqueSubjectId)		psFree(curr->uniqueSubjectId);


		if (curr->publicKey.key) {
#ifdef USE_RSA
			if (curr->pubKeyAlgorithm == OID_RSA_KEY_ALG) {
				pstm_clear(&(curr->publicKey.key->rsa.N));
				pstm_clear(&(curr->publicKey.key->rsa.e));
			}
#endif /* USE_RSA */

#ifdef USE_ECC
#ifdef USE_NATIVE_ECC
			if (curr->pubKeyAlgorithm == OID_ECDSA_KEY_ALG) {
				if (curr->publicKey.key->ecc.pubkey.x.dp) {
					pstm_clear(&(curr->publicKey.key->ecc.pubkey.x));
				}
				if (curr->publicKey.key->ecc.pubkey.y.dp) {
					pstm_clear(&(curr->publicKey.key->ecc.pubkey.y));
				}
				if (curr->publicKey.key->ecc.pubkey.z.dp) {
					pstm_clear(&(curr->publicKey.key->ecc.pubkey.z));
				}
				if (curr->publicKey.key->ecc.k.dp) {
					pstm_clear(&(curr->publicKey.key->ecc.k));
				}
			}
#endif
#ifdef USE_PKCS11_ECC
			if (curr->pubKeyAlgorithm == OID_ECDSA_KEY_ALG) {
				if (curr->publicKey.key->ecc.pubkey.value) {
					psFree(curr->publicKey.key->ecc.pubkey.value);
				}
			}
#endif
#endif /* USE_ECC */
			psFree(curr->publicKey.key);
		}


		x509FreeExtensions(&curr->extensions);
#ifdef USE_CRL
		x509FreeRevoked(&curr->revoked);
#endif
#endif /* USE_CERT_PARSE */
		next = curr->next;
		psFree(curr);
		curr = next;
	}
}	

#ifdef USE_CERT_PARSE
/******************************************************************************/
/*
	Currently just returning the raw BIT STRING and size in bytes
*/
int32 psX509GetSignature(psPool_t *pool, unsigned char **pp, uint32 len,
					unsigned char **sig, uint32 *sigLen)
{
	unsigned char   *p = *pp, *end;
	int32           ignore_bits;
	uint32			llen;

	end = p + len;
	if (len < 1 || (*(p++) != ASN_BIT_STRING) ||
			getAsnLength(&p, len - 1, &llen) < 0 || (uint32)(end - p) < llen) {
        psTraceCrypto("Initial parse error in getSignature\n");
		return PS_PARSE_FAIL;
	}
	ignore_bits = *p++;
/*
	We assume this is always 0.
*/
	psAssert(ignore_bits == 0);
/*
	Length included the ignore_bits byte
*/
	*sigLen = llen - 1;
	*sig = psMalloc(pool, *sigLen);
	if (*sig == NULL) {
		psError("Memory allocation error in getSignature\n");
		return PS_MEM_FAIL;
	}
	memcpy(*sig, p, *sigLen);
	*pp = p + *sigLen;
	return PS_SUCCESS;
}

/******************************************************************************/
/*
	Validate the expected name against a subset of the GeneralName rules
	for DNS, Email and IP types.
	We assume the expected name is not maliciously entered. If it is, it may
	match an invalid GeneralName in a remote cert chain.
	Returns 0 on valid format, PS_FAILURE on invalid format of GeneralName 
*/
int psX509ValidateGeneralName(char *n)
{
	char		*c;
	int			atfound;	/* Ampersand found */
	int			notip;		/* Not an ip address */

	if (n == NULL) return 0;

	/* Must be at least one character */
	if (*n == '\0') return PS_FAILURE;

	atfound = notip = 0;
	for (c = n; *c != '\0'; c++ ) {

		/* Negative tests first in the loop */
		/* Can't have any combination of . and - and @ together */
		if (c != n) {
			if (*c == '.' && *(c-1) == '.') return PS_FAILURE;
			if (*c == '.' && *(c-1) == '-') return PS_FAILURE;
			if (*c == '.' && *(c-1) == '@') return PS_FAILURE;
			if (*c == '-' && *(c-1) == '.') return PS_FAILURE;
			if (*c == '-' && *(c-1) == '-') return PS_FAILURE;
			if (*c == '-' && *(c-1) == '@') return PS_FAILURE;
			if (*c == '@' && *(c-1) == '.') return PS_FAILURE;
			if (*c == '@' && *(c-1) == '-') return PS_FAILURE;
			if (*c == '@' && *(c-1) == '@') return PS_FAILURE;
		}

		/* Note whether we have hit a non numeric name */
		if (*c != '.' && (*c < '0' || *c > '9')) notip++;

		/* Now positive tests */
		/* Cannot start or end with . or -, but can contain them */
		if (c != n && *(c + 1) != '\0' && (*c == '.' || *c == '-')) continue;
		/* Can contain at most one @ , and not at the start or end */
		if (*c == '@') {
			atfound++;
			if (c != n && *(c + 1) != '\0' && atfound == 1) {
				continue;
			}
		}
		/* Numbers allowed generally */
		if (*c >= '0' && *c <= '9') continue;
		/* Upper and lowercase characters allowed */
		if (*c >= 'A' && *c <= 'Z') continue;
		if (*c >= 'a' && *c <= 'z') continue;

		/* Everything else is a failure */
		return PS_FAILURE;
	}
	/* if it's not an IP, it can't start with a number */
	if (notip && (*n >= '0' && *n <= '9')) return PS_FAILURE;

	/* We could at this point store whether it is a DNS, Email or IP */
	
	return 0;
}

/******************************************************************************/
/*
	Extension lookup helper for getExplicitExtensions below
*/	
static int32 lookupExt(unsigned char md5hash[MD5_HASH_SIZE])
{
	int32				i, j;
	const unsigned char	*tmp;

	for (i = 0; ;i++) {
		if (extTable[i].id == -1) {
			//psTraceCrypto("Couldn't find cert extension in lookupExt\n");
			return PS_FAILURE;
		}
		tmp = extTable[i].hash;
		for (j = 0; j < MD5_HASH_SIZE; j++) {
			if (md5hash[j] != tmp[j]) {
				break;
			}
			if (j == MD5_HASH_SIZE - 1) {
				return extTable[i].id;
			}
		}
	}
//	return PS_FAILURE;  /* Not reachable */
}

/******************************************************************************/
/*
	Parses a sequence of GeneralName types
	TODO: the actual types should be parsed.  Just copying data blob

	GeneralName ::= CHOICE {
		otherName						[0]		OtherName,
		rfc822Name						[1]		IA5String,
		dNSName							[2]		IA5String,
		x400Address						[3]		ORAddress,
		directoryName					[4]		Name,
		ediPartyName					[5]		EDIPartyName,
		uniformResourceIdentifier		[6]		IA5String,
		iPAddress						[7]		OCTET STRING,
		registeredID					[8]		OBJECT IDENTIFIER }
*/
static int32 parseGeneralNames(psPool_t *pool, unsigned char **buf, int32 len,
				unsigned char *extEnd, x509GeneralName_t **name)
{
	uint32				otherNameLen;
	unsigned char		*p, *c, *save;
	x509GeneralName_t	*activeName, *firstName, *prevName;
	
	if (*name == NULL) {
		firstName = NULL;
	} else {
		firstName = *name;
	}
	p = *buf;
	
	while (len > 0) {
		if (firstName == NULL) {
			activeName = firstName = psMalloc(pool,	sizeof(x509GeneralName_t));
			if (activeName == NULL) {
				return PS_MEM_FAIL;
			}
			memset(firstName, 0x0, sizeof(x509GeneralName_t));
			*name = firstName;
		} else {
/*
			Find the end
*/
			prevName = firstName;
			activeName = firstName->next;
			while (activeName != NULL) {
				prevName = activeName;
				activeName = activeName->next;
			}
			prevName->next = psMalloc(pool,	sizeof(x509GeneralName_t));
			if (prevName->next == NULL) {
				/* TODO: free the list */
				return PS_MEM_FAIL;
			}
			activeName = prevName->next;
			memset(activeName, 0x0, sizeof(x509GeneralName_t));
		}
		activeName->id = (typeof(activeName->id))(*p & 0xF);
		p++; len--;
		switch (activeName->id) {
			case GN_OTHER:
				memcpy(activeName->name, "other", 5);
				/*  OtherName ::= SEQUENCE {
					type-id    OBJECT IDENTIFIER,
					value      [0] EXPLICIT ANY DEFINED BY type-id }
				*/
				save = p;
				if (getAsnLength(&p, (uint32)(extEnd - p), &otherNameLen) < 0 ||
						otherNameLen < 1 ||
						(uint32)(extEnd - p) < otherNameLen) {
					psTraceCrypto("ASN parse error SAN otherName\n");
					return PS_PARSE_FAIL;
				}
				if (*(p++) != ASN_OID || getAsnLength(&p, (int32)(extEnd - p),
						&activeName->oidLen) < 0){
					psTraceCrypto("ASN parse error SAN otherName oid\n");
					return -1;
				}
				memcpy(activeName->oid, p, activeName->oidLen);
				p += activeName->oidLen;
				/* value looks like
					0xA0, <len>, <TYPE>, <dataLen>, <data>
				
					We're supporting only string-type TYPE so just skipping	it
				*/
				p += 1; /* A0 */
				if (getAsnLength(&p, (uint32)(extEnd - p), &otherNameLen) < 0 ||
						otherNameLen < 1 ||
						(uint32)(extEnd - p) < otherNameLen) {
					psTraceCrypto("ASN parse error SAN otherName value\n");
					return PS_PARSE_FAIL;
				}
				p += 1; /* TYPE */
				len -= (p - save);
				break;
			case GN_EMAIL:
				memcpy(activeName->name, "email", 5);
				break;
			case GN_DNS:
				memcpy(activeName->name, "DNS", 3);
				break;
			case GN_X400:
				memcpy(activeName->name, "x400Address", 11);
				break;
			case GN_DIR:
				memcpy(activeName->name, "directoryName", 13);
				break;
			case GN_EDI:
				memcpy(activeName->name, "ediPartyName", 12);
				break;
			case GN_URI:
				memcpy(activeName->name, "URI", 3);
				break;
			case GN_IP:
				memcpy(activeName->name, "iPAddress", 9);
				break;
			case GN_REGID:
				memcpy(activeName->name, "registeredID", 12);
				break;
			default:
				memcpy(activeName->name, "unknown", 7);
				break;
		}
		
		save = p;
		if (getAsnLength(&p, (uint32)(extEnd - p), &activeName->dataLen) < 0 ||
				activeName->dataLen < 1 ||
				(uint32)(extEnd - p) < activeName->dataLen) {
			psTraceCrypto("ASN len error in parseGeneralNames\n");
			return PS_PARSE_FAIL;
		}	
		len -= (p - save);
		
		/*	Currently we validate that the IA5String fields are printable
			At a minimum, this prevents attacks with null terminators or
			invisible characters in the certificate.
			Additional validation of name format is done indirectly
			via byte comparison to the expected name in ValidateGeneralName 
			or directly by the user in the certificate callback */
		switch (activeName->id) {
			case GN_EMAIL:
			case GN_DNS:
			case GN_URI:
				save = p + activeName->dataLen;
				for (c = p; c < save; c++) {
					if (*c <= ' ' || *c > '~') {
						psTraceCrypto("ASN invalid GeneralName character\n");
						return PS_PARSE_FAIL;
					}
				}
				break;
			case GN_IP:
				if (activeName->dataLen < 4) {
					psTraceCrypto("Unknown GN_IP format\n");
					return PS_PARSE_FAIL;
				}
				break;
			default:
				break;
		}

		activeName->data = psMalloc(pool, activeName->dataLen + 1);
		if (activeName->data == NULL) {
			psError("Memory allocation error: activeName->data\n");
			return PS_MEM_FAIL;
		}
		/* This guarantees data is null terminated, even for non IA5Strings */
		memset(activeName->data, 0x0, activeName->dataLen + 1);
		memcpy(activeName->data, p, activeName->dataLen);

		p = p + activeName->dataLen;
		len -= activeName->dataLen; 
	}
	*buf = p;
	return PS_SUCCESS;
}

/******************************************************************************/
/*
	X509v3 extensions
*/

/* ExtendedKeyUsage. OID sums */
enum {
	EKU_TLS_SERVER_AUTH = 71,
	EKU_TLS_CLIENT_AUTH,
	EKU_CODE_SIGNING,
	EKU_EMAIL_PROTECTION,
	EKU_TIME_STAMPING = 78,
	EKU_OCSP_SIGNING
};

int32 getExplicitExtensions(psPool_t *pool, unsigned char **pp, 
								 uint32 inlen, int32 expVal,
								 x509v3extensions_t *extensions, int32 known)
{
	unsigned char		*p = *pp, *end;
	unsigned char		*extEnd, *extStart, *save;
	int32				noid;
	unsigned char		critical;
	uint32				len, fullExtLen, subExtLen;
	unsigned char		oid[MD5_HASH_SIZE];
	psDigestContext_t	md5ctx;
#ifdef USE_FULL_CERT_PARSE
	unsigned char			*subSave;
	int32					nc = 0;
#endif

	end = p + inlen;
	if (inlen < 1) {
		return PS_ARG_FAIL;
	}
	if (known) {
		goto KNOWN_EXT;
	}
/*
	Not treating this as an error because it is optional.
*/
	if (*p != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | expVal)) {
		return 0;
	}
	p++;
	if (getAsnLength(&p, (uint32)(end - p), &len) < 0 ||
			(uint32)(end - p) < len) {
		psTraceCrypto("Initial getAsnLength failure in extension parse\n");
		return PS_PARSE_FAIL;
	}
KNOWN_EXT:
/*
	Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

	Extension  ::=  SEQUENCE {
		extnID		OBJECT IDENTIFIER,
		extnValue	OCTET STRING	}
*/
	if (getAsnSequence(&p, (uint32)(end - p), &len) < 0) {
		psTraceCrypto("Initial getAsnSequence failure in extension parse\n");
		return PS_PARSE_FAIL;
	}
	extEnd = p + len;
	while ((p != extEnd) && *p == (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
		if (getAsnSequence(&p, (uint32)(extEnd - p), &fullExtLen) < 0) {
			psTraceCrypto("getAsnSequence failure in extension parse\n");
			return PS_PARSE_FAIL;
		}
		extStart = p;
/*
		Conforming CAs MUST support key identifiers, basic constraints,
		key usage, and certificate policies extensions
	
		id-ce-authorityKeyIdentifier	OBJECT IDENTIFIER ::=  { id-ce 35 }
		id-ce-basicConstraints			OBJECT IDENTIFIER ::=  { id-ce 19 } 133
		id-ce-keyUsage					OBJECT IDENTIFIER ::=  { id-ce 15 }
		id-ce-certificatePolicies		OBJECT IDENTIFIER ::=  { id-ce 32 }
		id-ce-subjectAltName			OBJECT IDENTIFIER ::=  { id-ce 17 }  131
		id-ce-nameConstraints			OBJECT IDENTIFIER ::=  { id-ce 30 }
	
*/
		if (extEnd - p < 1 || *p++ != ASN_OID) {
			psTraceCrypto("Malformed extension header\n");
			return PS_PARSE_FAIL;
		}
		
		if (getAsnLength(&p, (uint32)(extEnd - p), &len) < 0 ||
				(uint32)(extEnd - p) < len) {
			psTraceCrypto("Malformed extension length\n");
			return PS_PARSE_FAIL;
		}
/*
		Send the OID through a digest to get the unique id
*/
		psMd5Init(&md5ctx);
		while (len-- > 0) {
			psMd5Update(&md5ctx, p, sizeof(char));
			p++;
		}
		psMd5Final(&md5ctx, oid);
		noid = lookupExt(oid);

/*
		Possible boolean value here for 'critical' id.  It's a failure if a
		critical extension is found that is not supported
*/
		critical = 0;
		if (*p == ASN_BOOLEAN) {
			p++;
			if (*p++ != 1) {
				psTraceCrypto("Error parsing critical id for cert extension\n");
				return PS_PARSE_FAIL;
			}
			if (*p > 0) {
				/* Officially DER TRUE must be 0xFF, openssl is more lax */
				if (*p != 0xFF) {
					psTraceCrypto("Warning: DER BOOLEAN TRUE should be 0xFF\n");
				}
				critical = 1;
			}
			p++;
		}
		if (extEnd - p < 1 || (*p++ != ASN_OCTET_STRING) ||
				getAsnLength(&p, (uint32)(extEnd - p), &len) < 0 || 
				(uint32)(extEnd - p) < len) {
			psTraceCrypto("Expecting OCTET STRING in ext parse\n");
			return PS_PARSE_FAIL;
		}

		/* Set bits 1..9 to indicate criticality of known extensions */
		if (critical) {
			extensions->critFlags |= EXT_CRIT_FLAG(noid);
		}

		switch (noid) {
/*
			 BasicConstraints ::= SEQUENCE {
				cA						BOOLEAN DEFAULT FALSE,
				pathLenConstraint		INTEGER (0..MAX) OPTIONAL }
*/
			case EXT_BASIC_CONSTRAINTS:
				if (getAsnSequence(&p, (uint32)(extEnd - p), &len) < 0) {
					psTraceCrypto("Error parsing BasicConstraints extension\n");
					return PS_PARSE_FAIL;
				}
/*
				"This goes against PKIX guidelines but some CAs do it and some
				software requires this to avoid interpreting an end user
				certificate as a CA."
					- OpenSSL certificate configuration doc

				basicConstraints=CA:FALSE
*/
				if (len == 0) {
					break;
				}
/*
				Have seen some certs that don't include a cA bool.
*/
				if (*p == ASN_BOOLEAN) {
					p++;
					if (*p++ != 1) {
						psTraceCrypto("Error parsing BasicConstraints CA bool\n");
						return PS_PARSE_FAIL;
					}
					/* Officially DER TRUE must be 0xFF, openssl is more lax */
					if (*p > 0 && *p != 0xFF) {
						psTraceCrypto("Warning: cA TRUE should be 0xFF\n");
					} 
					extensions->bc.cA = *p++;
				} else {
					extensions->bc.cA = 0;
				}
/*
				Now need to check if there is a path constraint. Only makes
				sense if cA is true.  If it's missing, there is no limit to
				the cert path
*/
				if (*p == ASN_INTEGER) {
					if (getAsnInteger(&p, (uint32)(extEnd - p),
							&(extensions->bc.pathLenConstraint)) < 0) {
						psTraceCrypto("Error parsing BasicConstraints pathLen\n");	
						return PS_PARSE_FAIL;
					}
				} else {
					extensions->bc.pathLenConstraint = -1;
				}
				break;
				
			case EXT_ALT_SUBJECT_NAME:
				if (getAsnSequence(&p, (uint32)(extEnd - p), &len) < 0) {
					psTraceCrypto("Error parsing altSubjectName extension\n");
					return PS_PARSE_FAIL;
				}
				if (parseGeneralNames(pool, &p, len, extEnd, &extensions->san)
						< 0) {
					psTraceCrypto("Error parsing altSubjectName names\n");
					return PS_PARSE_FAIL;
				}
				
				break;
				
			case EXT_KEY_USAGE:
/*
				KeyUsage ::= BIT STRING {
					digitalSignature		(0),
					nonRepudiation			(1),
					keyEncipherment			(2),
					dataEncipherment		(3),
					keyAgreement			(4),
					keyCertSign				(5),
					cRLSign					(6),
					encipherOnly			(7),
					decipherOnly			(8) }
*/
				if (*p++ != ASN_BIT_STRING) {
					psTraceCrypto("Error parsing keyUsage extension\n");
					return PS_PARSE_FAIL;
				}
				if (getAsnLength(&p, (int32)(extEnd - p), &len) < 0 || 
						(uint32)(extEnd - p) < len) {
					psTraceCrypto("Malformed keyUsage extension\n");
					return PS_PARSE_FAIL;
				}
/*
				If the lenth is 3, then there are two bytes of flags, otherwise
				there is one byte of flags. There are only two bytes of flags
				if the KEY_USAGE_DECIPHER_ONLY bit is specified.
*/
				switch (len) {
				case 3:
					if (p[2] == (KEY_USAGE_DECIPHER_ONLY >> 8) && p[0] == 7) {
						extensions->keyUsageFlags |= KEY_USAGE_DECIPHER_ONLY;
					} else {
						return PS_PARSE_FAIL;
					}
					/* fall through */
				case 2:
					extensions->keyUsageFlags |= p[1];
					break;
				default:
					return PS_PARSE_FAIL;
				}
				p = p + len;
				break;
				
			case EXT_EXTND_KEY_USAGE:
				if (getAsnSequence(&p, (int32)(extEnd - p), &fullExtLen) < 0) {
					psTraceCrypto("Error parsing authKeyId extension\n");
					return PS_PARSE_FAIL;
				}
				save = p;
				subExtLen = 0; /* borrowing as index */
				while (fullExtLen > 0) {
					if (getAsnOID(&p, (uint32)(end - p),
							&noid, 0, (int32*)&len) < 0) {
						psTraceCrypto("OID parse fail EXTND_KEY_USAGE\n");
						return PS_PARSE_FAIL;
					}
					if (fullExtLen < (p - save)) {
						psTraceCrypto("Inner OID parse fail EXTND_KEY_USAGE\n");
						return PS_PARSE_FAIL;
					}
					fullExtLen -= (p - save);
					save = p;
					switch (noid) {
					case EKU_TLS_SERVER_AUTH:
						extensions->ekuFlags |= EXT_KEY_USAGE_TLS_SERVER_AUTH;
						break;
					case EKU_TLS_CLIENT_AUTH:
						extensions->ekuFlags |= EXT_KEY_USAGE_TLS_CLIENT_AUTH;
						break;
					case EKU_CODE_SIGNING:
						extensions->ekuFlags |= EXT_KEY_USAGE_CODE_SIGNING;
						break;
					case EKU_EMAIL_PROTECTION:
						extensions->ekuFlags |= EXT_KEY_USAGE_EMAIL_PROTECTION;
						break;
					case EKU_TIME_STAMPING:
						extensions->ekuFlags |= EXT_KEY_USAGE_TIME_STAMPING;
						break;
					case EKU_OCSP_SIGNING:
						extensions->ekuFlags |= EXT_KEY_USAGE_OCSP_SIGNING;
						break;
					default:
						psTraceCrypto("WARNING: Unknown EXT_KEY_USAGE \n");
						break;
					} /* end switch */
				}
				break;
	
#ifdef USE_FULL_CERT_PARSE

			case EXT_NAME_CONSTRAINTS:
				if (critical) {
					/* We're going to fail if critical since no real
						pattern matching is happening yet */
					psTraceCrypto("ERROR: critical nameConstraints unsupported\n");
					return PS_PARSE_FAIL;
				}
				if (getAsnSequence(&p, (int32)(extEnd - p), &fullExtLen) < 0) {
					psTraceCrypto("Error parsing authKeyId extension\n");
					return PS_PARSE_FAIL;
				}
				while (fullExtLen > 0) { 
					save = p;
					
					if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0)) {
						/* permittedSubtrees */
						p++;
						nc = 0;
					}
					if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1)) {
						/* excludedSubtrees */
						p++;
						nc = 1;
					}
					if (getAsnLength(&p, (uint32)(extEnd - p), &subExtLen) < 0 ||
							subExtLen < 1 || (uint32)(extEnd - p) < subExtLen) {
						psTraceCrypto("ASN get len error in nameConstraint\n");
						return PS_PARSE_FAIL;
					}
					if (fullExtLen < (subExtLen + (p - save))) {
						psTraceCrypto("fullExtLen parse fail nameConstraint\n");
						return PS_PARSE_FAIL;
					}
					fullExtLen -= subExtLen + (p - save);
					while (subExtLen > 0) {
						subSave = p;
						if (getAsnSequence(&p, (int32)(extEnd - p), &len) < 0) {
							psTraceCrypto("Error parsing nameConst ext\n");
							return PS_PARSE_FAIL;
						}
						if (subExtLen < (len + (p - subSave))) {
							psTraceCrypto("subExtLen fail nameConstraint\n");
							return PS_PARSE_FAIL;
						}
						subExtLen -= len + (p - subSave);
						if (nc == 0) {
							if (parseGeneralNames(pool, &p, len, extEnd,
								&extensions->nameConstraints.permitted) < 0) {
							 psTraceCrypto("Error parsing nameConstraint\n");
							 return PS_PARSE_FAIL;
							}
						} else {
							if (parseGeneralNames(pool, &p, len, extEnd,
								&extensions->nameConstraints.excluded) < 0) {
							 psTraceCrypto("Error parsing nameConstraint\n");
							 return PS_PARSE_FAIL;
							}
						}
					}
				}
				break;

#ifdef USE_CRL
			case EXT_CRL_DIST_PTS:
			
				if (getAsnSequence(&p, (int32)(extEnd - p), &fullExtLen) < 0) {
					psTraceCrypto("Error parsing authKeyId extension\n");
					return PS_PARSE_FAIL;
				}
					
				while (fullExtLen > 0) { 
					save = p;
					if (getAsnSequence(&p, (uint32)(extEnd - p), &len) < 0) {
						psTraceCrypto("getAsnSequence fail in crldist parse\n");
						return PS_PARSE_FAIL;
					}
					if (fullExtLen < (len + (p - save))) {
						psTraceCrypto("fullExtLen parse fail crldist\n");
						return PS_PARSE_FAIL;
					}
					fullExtLen -= len + (p - save);					
					/* All memebers are optional */
					if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0)) {
						/* DistributionPointName */
						p++;
						if (getAsnLength(&p, (uint32)(extEnd - p), &len) < 0 ||
								len < 1 || (uint32)(extEnd - p) < len) {
							psTraceCrypto("ASN get len error in CRL extension\n");
							return PS_PARSE_FAIL;
						}			
									
						if ((*p & 0xF) == 0) { /* fullName (GeneralNames) */
							p++;
							if (getAsnLength(&p, (uint32)(extEnd - p), &len) < 0 ||
									len < 1 || (uint32)(extEnd - p) < len) {
								psTraceCrypto("ASN get len error in CRL extension\n");
								return PS_PARSE_FAIL;
							}	
							if (parseGeneralNames(pool, &p, len, extEnd,
									&extensions->crlDist) > 0) {
								psTraceCrypto("dist gen name parse fail\n");
								return PS_PARSE_FAIL;
							}
						} else if ((*p & 0xF) == 1) { /* RelativeDistName */
							p++;
							/* RelativeDistName not parsed */
							if (getAsnLength(&p, (uint32)(extEnd - p), &len) < 0
									|| len < 1 || (uint32)(extEnd - p) < len) {
								psTraceCrypto("ASN get len error in CRL extension\n");
								return PS_PARSE_FAIL;
							}
							p += len;
						} else {
							psTraceCrypto("DistributionPointName parse fail\n");
							return PS_PARSE_FAIL;
						}						
					}
					if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1)) {
						p++;
						/* ReasonFlags not parsed */
						if (getAsnLength(&p, (uint32)(extEnd - p), &len) < 0 ||
								len < 1 || (uint32)(extEnd - p) < len) {
							psTraceCrypto("ASN get len error in CRL extension\n");
							return PS_PARSE_FAIL;
						}
						p += len;
					}
					if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 2)) {
						p++;
						/* General Names not parsed */
						if (getAsnLength(&p, (uint32)(extEnd - p), &len) < 0 ||
								len < 1 || (uint32)(extEnd - p) < len) {
							psTraceCrypto("ASN get len error in CRL extension\n");
							return PS_PARSE_FAIL;
						}
						p += len;
					}					
				}
				break;
#endif /* USE_CRL */
#endif /* FULL_CERT_PARSE */			

			case EXT_AUTH_KEY_ID:
/*
				AuthorityKeyIdentifier ::= SEQUENCE {
				keyIdentifier			[0] KeyIdentifier			OPTIONAL,
				authorityCertIssuer		[1] GeneralNames			OPTIONAL,
				authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL }

				KeyIdentifier ::= OCTET STRING
*/
				if (getAsnSequence(&p, (int32)(extEnd - p), &len) < 0) {
					psTraceCrypto("Error parsing authKeyId extension\n");
					return PS_PARSE_FAIL;
				}
/*
				Have seen a cert that has a zero length ext here.  Let it pass.
*/
				if (len == 0) {
					break;
				}
/*
				All memebers are optional
*/
				if (*p == (ASN_CONTEXT_SPECIFIC | ASN_PRIMITIVE | 0)) {
					p++;
					if (getAsnLength(&p, (int32)(extEnd - p), 
							&extensions->ak.keyLen) < 0 ||
							(uint32)(extEnd - p) < extensions->ak.keyLen) {
						psTraceCrypto("Error keyLen in authKeyId extension\n");
						return PS_PARSE_FAIL;
					}
					extensions->ak.keyId =psMalloc(pool, extensions->ak.keyLen);
					if (extensions->ak.keyId == NULL) {
						psError("Mem allocation err: extensions->ak.keyId\n");
						return PS_MEM_FAIL; 
					}
					memcpy(extensions->ak.keyId, p, extensions->ak.keyLen);
					p = p + extensions->ak.keyLen;
				}
				if (*p == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1)) {
					p++;
					if (getAsnLength(&p, (int32)(extEnd - p), &len) < 0 ||
							len < 1 || (uint32)(extEnd - p) < len) {
						psTraceCrypto("ASN get len error in authKeyId extension\n");
						return PS_PARSE_FAIL;
					}
					if ((*p ^ ASN_CONTEXT_SPECIFIC ^ ASN_CONSTRUCTED) != 4) {
						/* We are just dealing with DN formats here */
						psTraceIntCrypto("Error auth key-id name type: %d\n",
							*p ^ ASN_CONTEXT_SPECIFIC ^ ASN_CONSTRUCTED);
						return PS_PARSE_FAIL;
					}
					p++;
					if (getAsnLength(&p, (int32)(extEnd - p), &len) < 0 || 
							(uint32)(extEnd - p) < len) {
						psTraceCrypto("ASN get len error2 in authKeyId extension\n");
						return PS_PARSE_FAIL;
					}
					if (psX509GetDNAttributes(pool, &p, (int32)(extEnd - p),
							&(extensions->ak.attribs), 0) < 0) {
						psTraceCrypto("Error parsing ak.attribs\n");
						return PS_PARSE_FAIL;
					}
				}
				if ((*p == (ASN_CONTEXT_SPECIFIC | ASN_PRIMITIVE | 2)) ||
						(*p == ASN_INTEGER)){
/*
					Treat as a serial number (not a native INTEGER)
*/
					if (getSerialNum(pool, &p, (int32)(extEnd - p),
							&(extensions->ak.serialNum), &len) < 0) {
						psTraceCrypto("Error parsing ak.serialNum\n");
						return PS_PARSE_FAIL;
					}
					extensions->ak.serialNumLen = len;
				}
				break;

			case EXT_SUBJ_KEY_ID:
/*
				The value of the subject key identifier MUST be the value
				placed in the key identifier field of the Auth Key Identifier
				extension of certificates issued by the subject of
				this certificate.
*/
				if (*p++ != ASN_OCTET_STRING || getAsnLength(&p,
						(int32)(extEnd - p), &(extensions->sk.len)) < 0 ||
						(uint32)(extEnd - p) < extensions->sk.len) {
					psTraceCrypto("Error parsing subjectKeyId extension\n");
					return PS_PARSE_FAIL;
				}
				extensions->sk.id = psMalloc(pool, extensions->sk.len);
				if (extensions->sk.id == NULL) {
					psError("Memory allocation error extensions->sk.id\n");
					return PS_MEM_FAIL;
				}
				memcpy(extensions->sk.id, p, extensions->sk.len);
				p = p + extensions->sk.len;
				break;
			default:
				/* Unsupported or skipping because USE_FULL_CERT_PARSE undefd */
				if (critical) {
					psTraceCrypto("Unknown critical ext encountered.\n");
#ifndef ALLOW_UNKNOWN_CRITICAL_EXTENSIONS
					_psTrace("An unrecognized critical extension was\n");
					_psTrace("encountered.  X.509 specifications say\n");
					_psTrace("connections must be terminated in this case.\n");
					_psTrace("Define ALLOW_UNKNOWN_CRITICAL_EXTENSIONS to\n");
					_psTrace("bypass this rule if testing and email Inside\n");
					_psTrace("support to inquire about this extension.\n\n");
					return PS_PARSE_FAIL;
#else
#ifdef WIN32
#pragma message("IGNORING UNKNOWN CRITICAL EXTENSIONS IS A SECURITY RISK")
#else
#warning "IGNORING UNKNOWN CRITICAL EXTENSIONS IS A SECURITY RISK"
#endif
#endif
				}
				p++;
/*
				Skip over based on the length reported from the ASN_SEQUENCE
				surrounding the entire extension.  It is not a guarantee that
				the value of the extension itself will contain it's own length.
*/
				p = p + (fullExtLen - (p - extStart));
				break;
		}
	}
	*pp = p;
	return 0;
}

/******************************************************************************/
/*
    Although a certificate serial number is encoded as an integer type, that
    doesn't prevent it from being abused as containing a variable length
    binary value.  Get it here.
*/ 
int32 getSerialNum(psPool_t *pool, unsigned char **pp, uint32 len,
                        unsigned char **sn, uint32 *snLen)
{
	unsigned char   *p = *pp;
	uint32           vlen;

	if ((*p != (ASN_CONTEXT_SPECIFIC | ASN_PRIMITIVE | 2)) &&
			(*p != ASN_INTEGER)) {
		psTraceCrypto("X.509 getSerialNum failed on first bytes\n");
        return PS_PARSE_FAIL;
    }
    p++;

    if (len < 1 || getAsnLength(&p, len - 1, &vlen) < 0 || (len - 1) < vlen) {
        psTraceCrypto("ASN getSerialNum failed\n");
        return PS_PARSE_FAIL;
    }
    *snLen = vlen;
	
	if (vlen > 0) {
		*sn = psMalloc(pool, vlen);
		if (*sn == NULL) {
			psError("Memory allocation failure in getSerialNum\n");
			return PS_MEM_FAIL;
		}
		memcpy(*sn, p, vlen);
		p += vlen;
	}
	*pp = p;
	return PS_SUCCESS;
}

/******************************************************************************/
/*
	Explicit value encoding has an additional tag layer
*/
static int32 getExplicitVersion(unsigned char **pp, uint32 len, int32 expVal,
				int32 *val)
{
	unsigned char   *p = *pp;
	uint32           exLen;

	if (len < 1) {
		psTraceCrypto("Invalid length to getExplicitVersion\n");
		return PS_PARSE_FAIL;
	}
/*
	This is an optional value, so don't error if not present.  The default
	value is version 1
*/ 
	if (*p != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | expVal)) {
		*val = 0;
		return PS_SUCCESS;
	}
	p++;
	if (getAsnLength(&p, len - 1, &exLen) < 0 || (len - 1) < exLen) {
		psTraceCrypto("getAsnLength failure in getExplicitVersion\n");
		return PS_PARSE_FAIL;
	}
	if (getAsnInteger(&p, exLen, val) < 0) {
		psTraceCrypto("getAsnInteger failure in getExplicitVersion\n");
		return PS_PARSE_FAIL;
	}
	*pp = p;
	return PS_SUCCESS;
}

/******************************************************************************/
/*
	Validate the dates in the cert to machine date
	SECURITY - always succeeds on systems without date support
	Returns
		0 on success
		PS_CERT_AUTH_FAIL_DATE if date is out of range
		PS_FAILURE on parse error
*/
static int validateDateRange(psX509Cert_t *cert)
{
#ifdef POSIX
	struct tm	t;
	time_t		rawtime;
	char		*c;
	int			y, m, d;

	time(&rawtime);
	localtime_r(&rawtime, &t);
	/* Localtime does months from 0-11 and (year-1900)! Normalize it. */
	t.tm_mon++;
	t.tm_year += 1900;

	/* Validate the 'not before' date */
	if ((c = cert->notBefore) == NULL) {
		return PS_FAILURE;
	}
	if (strlen(c) < 8) {
		return PS_FAILURE;
	}
	/* UTCTIME, defined in 1982, has just a 2 digit year */
	if (cert->notBeforeTimeType == ASN_UTCTIME) {
		y =  2000 + 10 * (c[0] - '0') + (c[1] - '0'); c += 2;
	} else {
		y = 1000 * (c[0] - '0') + 100 * (c[1] - '0') +
		10 * (c[2] - '0') + (c[3] - '0'); c += 4;
	}
	m = 10 * (c[0] - '0') + (c[1] - '0'); c += 2;
	d = 10 * (c[0] - '0') + (c[1] - '0');
	if (t.tm_year < y) {
		cert->authFailFlags |= PS_CERT_AUTH_FAIL_DATE_FLAG;
	} else if (t.tm_year == y) {
		if (t.tm_mon < m) {
			cert->authFailFlags |= PS_CERT_AUTH_FAIL_DATE_FLAG;
		} else if (t.tm_mon == m && t.tm_mday < d) {
			cert->authFailFlags |= PS_CERT_AUTH_FAIL_DATE_FLAG;
		}
	}

	/* Validate the 'not after' date */
	if ((c = cert->notAfter) == NULL) {
		return PS_FAILURE;
	}
	if (strlen(c) < 8) {
		return PS_FAILURE;
	}
	/* UTCTIME, defined in 1982 has just a 2 digit year */
	if (cert->notAfterTimeType == ASN_UTCTIME) {
		y =  2000 + 10 * (c[0] - '0') + (c[1] - '0'); c += 2;
	} else {
		y = 1000 * (c[0] - '0') + 100 * (c[1] - '0') +
		10 * (c[2] - '0') + (c[3] - '0'); c += 4;
	}
	m = 10 * (c[0] - '0') + (c[1] - '0'); c += 2;
	d = 10 * (c[0] - '0') + (c[1] - '0');
	if (t.tm_year > y) {
		cert->authFailFlags |= PS_CERT_AUTH_FAIL_DATE_FLAG;
	} else if (t.tm_year == y) {
		if (t.tm_mon > m) {
			cert->authFailFlags |= PS_CERT_AUTH_FAIL_DATE_FLAG;
		} else if (t.tm_mon == m && t.tm_mday > d) {
			cert->authFailFlags |= PS_CERT_AUTH_FAIL_DATE_FLAG;
		}
	}
	return 0;
#else
/* Warn if we are skipping the date validation checks. */
#ifdef WIN32
#pragma message("CERTIFICATE DATE VALIDITY NOT SUPPORTED ON THIS PLATFORM.")
#else
//#warning "CERTIFICATE DATE VALIDITY NOT SUPPORTED ON THIS PLATFORM."
#endif
	//cert->authFailFlags |= PS_CERT_AUTH_FAIL_DATE_FLAG;
	return 0;
#endif /* POSIX */
}

/******************************************************************************/
/*
	Implementation specific date parser.  Does not actually verify the date
*/
static int32 getTimeValidity(psPool_t *pool, unsigned char **pp, uint32 len,
				int32 *notBeforeTimeType, int32 *notAfterTimeType,
				char **notBefore, char **notAfter)
{
	unsigned char   *p = *pp, *end;
	uint32          seqLen, timeLen;

	end = p + len;
	if (len < 1 || *(p++) != (ASN_SEQUENCE | ASN_CONSTRUCTED) ||
			getAsnLength(&p, len - 1, &seqLen) < 0 ||
				(uint32)(end - p) < seqLen) {
		psTraceCrypto("getTimeValidity failed on inital parse\n");
		return PS_PARSE_FAIL;
	}
/*
	Have notBefore and notAfter times in UTCTime or GeneralizedTime formats
*/
	if ((end - p) < 1 || ((*p != ASN_UTCTIME) && (*p != ASN_GENERALIZEDTIME))) {
		psTraceCrypto("Malformed validity\n");
		return PS_PARSE_FAIL;
	}
	*notBeforeTimeType = *p;
	p++;
/*
	Allocate them as null terminated strings
*/
	if (getAsnLength(&p, seqLen, &timeLen) < 0 || (uint32)(end - p) < timeLen) {
		psTraceCrypto("Malformed validity 2\n");
		return PS_PARSE_FAIL;
	}
	*notBefore = psMalloc(pool, timeLen + 1);
	if (*notBefore == NULL) {
		psError("Memory allocation error in getTimeValidity for notBefore\n");
		return PS_MEM_FAIL;
	}
	memcpy(*notBefore, p, timeLen);
	(*notBefore)[timeLen] = '\0';
	p = p + timeLen;
	if ((end - p) < 1 || ((*p != ASN_UTCTIME) && (*p != ASN_GENERALIZEDTIME))) {
		psTraceCrypto("Malformed validity 3\n");
		return PS_PARSE_FAIL;
	}
	*notAfterTimeType = *p;
	p++;
	if (getAsnLength(&p, seqLen - timeLen, &timeLen) < 0 ||
			(uint32)(end - p) < timeLen) {
		psTraceCrypto("Malformed validity 4\n");
		return PS_PARSE_FAIL;
	}
	*notAfter = psMalloc(pool, timeLen + 1);
	if (*notAfter == NULL) {
		psError("Memory allocation error in getTimeValidity for notAfter\n");
        return PS_MEM_FAIL;
	}
	memcpy(*notAfter, p, timeLen);
	(*notAfter)[timeLen] = '\0';
	p = p + timeLen;

	*pp = p;
	return PS_SUCCESS;
}

/******************************************************************************/
/*
    Could be optional.  If the tag doesn't contain the value from the left
    of the IMPLICIT keyword we don't have a match and we don't incr the pointer.
*/
static int32 getImplicitBitString(psPool_t *pool, unsigned char **pp,
				uint32 len,	int32 impVal, unsigned char **bitString,
				uint32 *bitLen)
{
	unsigned char   *p = *pp;
	int32           ignore_bits;

	if (len < 1) {
		psTraceCrypto("Initial parse error in getImplicitBitString\n");
		return PS_PARSE_FAIL;
	}
/*
	We don't treat this case as an error, because of the optional nature.
*/
	if (*p != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | impVal)) {
		return PS_SUCCESS;
	}

	p++;
	if (getAsnLength(&p, len, bitLen) < 0) {
		psTraceCrypto("Malformed implicitBitString\n");
		return PS_PARSE_FAIL;
	}
	ignore_bits = *p++;
	psAssert(ignore_bits == 0);

	*bitString = psMalloc(pool, *bitLen);
	if (*bitString == NULL) {
		psError("Memory allocation error in getImplicitBitString\n");
		return PS_MEM_FAIL;
	}
	memcpy(*bitString, p, *bitLen);
	*pp = p + *bitLen;
	return PS_SUCCESS;
}


/******************************************************************************/
/*
	Implementations of this specification MUST be prepared to receive
	the following standard attribute types in issuer names:
	country, organization, organizational-unit, distinguished name qualifier,
	state or province name, and common name 
*/
int32 psX509GetDNAttributes(psPool_t *pool, unsigned char **pp, uint32 len, 
				x509DNattributes_t *attribs, int32 flags)
{
	psDigestContext_t	hash;
	unsigned char		*p = *pp;
	unsigned char		*dnEnd, *dnStart, *moreInSetPtr;
	int32				id, stringType, checkHiddenNull, moreInSet;
	uint32				llen, setlen, arcLen;
	char				*stringOut;

	dnStart = p;
	if (getAsnSequence(&p, len, &llen) < 0) {
		return PS_PARSE_FAIL;
	}
	dnEnd = p + llen;

/*
	The possibility of a CERTIFICATE_REQUEST message.  Set aside full DN
*/
	if (flags & CERT_STORE_DN_BUFFER) {
		attribs->dnencLen = (uint32)(dnEnd - dnStart);
		attribs->dnenc = psMalloc(pool, attribs->dnencLen);
		if (attribs->dnenc == NULL) {
			psError("Memory allocation error in getDNAttributes\n");
			return PS_MEM_FAIL;
		}
		memcpy(attribs->dnenc, dnStart, attribs->dnencLen);
	}
	psSha1Init(&hash);
	moreInSet = 0;
	while (p < dnEnd) {
		if (getAsnSet(&p, (uint32)(dnEnd - p), &setlen) < 0) {
			psTraceCrypto("Malformed DN attributes\n");
			return PS_PARSE_FAIL;
		}
		/*	Hash up the DN.  Nice for validation later */
		psSha1Update(&hash, p, setlen);
		
		/* 99.99% of certs have one attribute per SET but did come across
			one that nested a couple at this level so let's watch out for 
			that with the "moreInSet" logic */
MORE_IN_SET:
		moreInSetPtr = p;
		if (getAsnSequence(&p, (uint32)(dnEnd - p), &llen) < 0) {
			psTraceCrypto("Malformed DN attributes 2\n");
			return PS_PARSE_FAIL;
		}
		if (moreInSet > 0) {
			moreInSet -= llen + (int32)(p - moreInSetPtr);
		} else {
			if (setlen != llen + (int32)(p - moreInSetPtr)) {
				moreInSet = setlen - (int32)(p - moreInSetPtr) - llen;
			}
		}
		if (dnEnd <= p || (*(p++) != ASN_OID) ||
				getAsnLength(&p, (uint32)(dnEnd - p), &arcLen) < 0 || 
				(uint32)(dnEnd - p) < arcLen) {
			psTraceCrypto("Malformed DN attributes 3\n");
			return PS_PARSE_FAIL;
		}
/*
		id-at   OBJECT IDENTIFIER       ::=     {joint-iso-ccitt(2) ds(5) 4}
		id-at-commonName		OBJECT IDENTIFIER		::=		{id-at 3}
		id-at-countryName		OBJECT IDENTIFIER		::=		{id-at 6}
		id-at-localityName		OBJECT IDENTIFIER		::=		{id-at 7}
		id-at-stateOrProvinceName		OBJECT IDENTIFIER	::=	{id-at 8}
		id-at-organizationName			OBJECT IDENTIFIER	::=	{id-at 10}
		id-at-organizationalUnitName	OBJECT IDENTIFIER	::=	{id-at 11}
*/
		*pp = p;
/*
		Currently we are skipping OIDs not of type {joint-iso-ccitt(2) ds(5) 4}
		However, we could be dealing with an OID we MUST support per RFC.
		domainComponent is one such example.
*/
		if (dnEnd - p < 2) {
			psTraceCrypto("Malformed DN attributes 4\n");
			return PS_LIMIT_FAIL;
		}
		/* check id-at */
		if ((*p++ != 85) || (*p++ != 4) ) {
			/* OIDs we are not parsing */
			p = *pp;
/*
			Move past the OID and string type, get data size, and skip it.
			NOTE: Have had problems parsing older certs in this area.
*/
			if ((uint32)(dnEnd - p) < arcLen + 1) {
				psTraceCrypto("Malformed DN attributes 5\n");
				return PS_LIMIT_FAIL;
			}
			p += arcLen + 1;
			if (getAsnLength(&p, (uint32)(dnEnd - p), &llen) < 0 || 
					(uint32)(dnEnd - p) < llen) {
				psTraceCrypto("Malformed DN attributes 6\n");
				return PS_PARSE_FAIL;
			}
			p = p + llen;
			continue;
		}
/*
		Next are the id of the attribute type and the ASN string type
*/
		if (arcLen != 3 || dnEnd - p < 2) {
			psTraceCrypto("Malformed DN attributes 7\n");
			return PS_LIMIT_FAIL;
		}
		id = (int32)*p++;
/*
		Done with OID parsing
*/
		stringType = (int32)*p++;

		if (getAsnLength(&p, (uint32)(dnEnd - p), &llen) < 0 ||
				(uint32)(dnEnd - p) < llen) {
			psTraceCrypto("Malformed DN attributes 8\n");
			return PS_LIMIT_FAIL;
		}
/*
		For the known 8-bit character string types, we flag that we want
		to test for a hidden null in the middle of the string to address the
		issue of www.goodguy.com\0badguy.com.  For BMPSTRING, the user will
		have to validate against the xLen member for such abuses.
*/
		checkHiddenNull = PS_FALSE;
		switch (stringType) {
			case ASN_PRINTABLESTRING:
			case ASN_UTF8STRING:
			case ASN_IA5STRING:
				checkHiddenNull = PS_TRUE;
			case ASN_T61STRING:
			case ASN_BMPSTRING:
				stringOut = psMalloc(pool, llen + 2);
				if (stringOut == NULL) {
					psError("Memory allocation error in getDNAttributes\n");
					return PS_MEM_FAIL; 
				}
				memcpy(stringOut, p, llen);
/*
				Terminate with 2 null chars to support standard string
				manipulations with any potential unicode types.
*/
				stringOut[llen] = '\0';
				stringOut[llen + 1] = '\0';

				if (checkHiddenNull) {
					if ((uint32)strlen(stringOut) != llen) {
						psFree(stringOut);
						psTraceCrypto("Malformed DN attributes 9\n");
						return PS_PARSE_FAIL;
					}
				}
		
				p = p + llen;
				llen += 2; /* Add the two null bytes for length assignments */
				break;
			default:
				psTraceIntCrypto("Unsupported DN attrib type %d\n", stringType);
				return PS_UNSUPPORTED_FAIL;
		}

		switch (id) {
			case ATTRIB_COUNTRY_NAME:
				if (attribs->country) {
					psFree(attribs->country);
				}
				attribs->country = stringOut;
				attribs->countryType = (short)stringType;
				attribs->countryLen = (short)llen;
				break;
			case ATTRIB_STATE_PROVINCE:
				if (attribs->state) {
					psFree(attribs->state);
				}
				attribs->state = stringOut;
				attribs->stateType = (short)stringType;
				attribs->stateLen = (short)llen;
				break;
			case ATTRIB_LOCALITY:
				if (attribs->locality) {
					psFree(attribs->locality);
				}
				attribs->locality = stringOut;
				attribs->localityType = (short)stringType;
				attribs->localityLen = (short)llen;
				break;
			case ATTRIB_ORGANIZATION:
				if (attribs->organization) {
					psFree(attribs->organization);
				}
				attribs->organization = stringOut;
				attribs->organizationType = (short)stringType;
				attribs->organizationLen = (short)llen;
				break;
			case ATTRIB_ORG_UNIT:
				if (attribs->orgUnit) {
					psFree(attribs->orgUnit);
				}
				attribs->orgUnit = stringOut;
				attribs->orgUnitType = (short)stringType;
				attribs->orgUnitLen = (short)llen;
				break;
			case ATTRIB_COMMON_NAME:
				if (attribs->commonName) {
					psFree(attribs->commonName);
				}
				attribs->commonName = stringOut;
				attribs->commonNameType = (short)stringType;
				attribs->commonNameLen = (short)llen;
				break;
/*
			Not a MUST support
*/
			default:
				psFree(stringOut);
				stringOut = NULL;
				break;
		}
		if (moreInSet) {
			goto MORE_IN_SET;
		}
	}
	psSha1Final(&hash, (unsigned char*)attribs->hash);
	*pp = p;
	return PS_SUCCESS;
}

/******************************************************************************/
/*
	Free helper
*/
void psX509FreeDNStruct(x509DNattributes_t *dn)
{
	if (dn->country)		psFree(dn->country);
	if (dn->state)			psFree(dn->state);
	if (dn->locality)		psFree(dn->locality);
	if (dn->organization)	psFree(dn->organization);
	if (dn->orgUnit)		psFree(dn->orgUnit);
	if (dn->commonName)		psFree(dn->commonName);
	if (dn->dnenc)			psFree(dn->dnenc);
}


/******************************************************************************/
/*
	Fundamental routine to test whether the supplied issuerCert issued
	the supplied subjectCert.  There are currently two tests that are
	performed here:
		1. A strict SHA1 hash comparison of the Distinguished Name details
		2. A test of the public key cryptographic cert signature 

	subjectCert may be a chain.  Cert chains must always be passed with
	the child-most as the first in the list (the 'next' structure member
	points to the parent).  The authentication of the entire chain
	will be tested before the issuerCert is used to authenticate the
	parent-most certificate
	
	issuerCert will always be a treated as a single certificate even if it
	is a chain
	
	If there is no issuerCert the parent-most subejct cert will always
	be tested as a self-signed CA certificate.
	
	So there are three uses:
	1. Test a cert was issued by another (single subjectCert, single issuerCert)
	1. Test a self signed cert (single cert to subjectCert, no issuerCert)
	2. Test a CA terminated chain (cert chain to subjectCert, no issuerCert)

	This function exits with a failure code on the first authentication
	that doesn't succeed.  The 'authStatus' members may be examined for more
	information of where the authentication failed.

	The 'authStatus' member of the issuerCert will be set to PS_FALSE 
	since it will not be authenticated. 

	The 'authStatus' members of the subjectCert structures will always
	be reset to PS_FALSE when this routine is called and set to PS_TRUE 
	when authenticated.  Any error during the authentication will set the 
	current subject cert 'authStatus' member to PS_CERT_AUTH_FAIL and the
	function will return with an error code. 

	Return codes:
		PS_SUCCESS			- yes 

		PS_CERT_AUTH_FAIL	- nope. these certs are not a match
		PS_UNSUPPORTED_FAIL	- unrecognized cert format
		PS_ARG_FAIL			- local, psRsaDecryptPub 
		PS_LIMIT_FAIL		- psRsaDecryptPub 
		PS_FAILURE			- internal psRsaDecryptPub failure

	There is nothing for the caller to free at the completion of this
	routine.
*/
int32 psX509AuthenticateCert(psPool_t *pool, psX509Cert_t *subjectCert,
						psX509Cert_t *issuerCert,  psX509Cert_t	**foundIssuer)
{
	psX509Cert_t	*ic, *sc;
	int32			sigType, rc;
	uint32			sigLen;
	void			*rsaData;
#ifdef USE_ECC
	int32			sigStat;
#endif /* USE_ECC */	
#ifdef USE_RSA	
	unsigned char	sigOut[10 + MAX_HASH_SIZE + 9];	/* Max size */
	unsigned char	*tempSig;
#endif /* USE_RSA */	
	psPool_t	*pkiPool = NULL;
#ifdef USE_CRL
	x509revoked_t	*curr, *next;
#endif

	rc = 0;
	sigLen = 0;
	if (subjectCert == NULL) {
		psTraceCrypto("No subject cert given to psX509AuthenticateCert\n");
		return PS_ARG_FAIL;
	}

/*
	Determine what we've been passed
*/
	if (issuerCert == NULL) {
		/* reset auth flags in subjectCert chain and find first sc and ic */
		sc = subjectCert;
		while (sc) {
			sc->authStatus = PS_FALSE;
			sc = sc->next;
		}
		/* Now see if this is a chain or just a single cert */
		sc = subjectCert;
		if (sc->next == NULL) {
			ic = sc; /* A single subject cert for self-signed test */
		} else {
			ic = sc->next;
		}
	} else {
		issuerCert->authStatus = PS_FALSE;
		ic = issuerCert; /* Easy case of single subject and single issuer */
		sc = subjectCert;
	}

/*
	Error on first problem seen and set the subject status to FAIL
*/
	while (ic) {
/*
		Certificate authority constraint only available in version 3 certs.
		Only parsing version 3 certs by default though.
*/
		if ((ic->version > 1) && (ic->extensions.bc.cA <= 0)) {
			psTraceCrypto("Issuer does not have basicConstraint CA permissions\n");
			sc->authStatus = PS_CERT_AUTH_FAIL_BC;
			return PS_CERT_AUTH_FAIL_BC;
		}
		
/*
		Use sha1 hash of issuer fields computed at parse time to compare
*/
		if (memcmp(sc->issuer.hash, ic->subject.hash, SHA1_HASH_SIZE) != 0) {
			if (sc == ic) {
				psTraceCrypto("Info: not a self-signed certificate\n");
			} else {
				psTraceCrypto("Issuer DN attributes do not match subject\n");
			}
			sc->authStatus = PS_CERT_AUTH_FAIL_DN;
			return PS_CERT_AUTH_FAIL_DN;
		}
		
#ifdef USE_CRL
		/* Does this issuer have a list of revoked serial numbers that needs
			to be checked? */
		if (ic->revoked) {
			curr = ic->revoked;
			while (curr != NULL) {
				next = curr->next;
				if (curr->serialLen == sc->serialNumberLen) {
					if (memcmp(curr->serial, sc->serialNumber, curr->serialLen)
							== 0) {
						sc->authStatus = PS_CERT_AUTH_FAIL_REVOKED;
						return -1;
					}
				}
				curr = next;
			}
			
		}
#endif

/*
		Signature confirmation
		The sigLen is the ASN.1 size in bytes for encoding the hash.
		The magic 10 is comprised of the SEQUENCE and ALGORITHM ID overhead.
		The magic 9, 8, or 5 is the OID length of the corresponding algorithm.
*/
		sigType = PS_UNSUPPORTED_FAIL;
#ifdef USE_RSA
#ifdef ENABLE_MD5_SIGNED_CERTS
		if (sc->sigAlgorithm ==  OID_MD5_RSA_SIG ||
				sc->sigAlgorithm == OID_MD2_RSA_SIG) {
			sigType = RSA_TYPE_SIG;
			sigLen = 10 + MD5_HASH_SIZE + 8;
		} 
#endif
		if (sc->sigAlgorithm == OID_SHA1_RSA_SIG) {
			sigLen = 10 + SHA1_HASH_SIZE + 5;
			sigType = RSA_TYPE_SIG;
		}
#ifdef USE_SHA256		
		if (sc->sigAlgorithm == OID_SHA256_RSA_SIG) {
			sigLen = 10 + SHA256_HASH_SIZE + 9;
			sigType = RSA_TYPE_SIG;
		}
#endif /* USE_SHA256 */
#ifdef USE_SHA384
		if (sc->sigAlgorithm == OID_SHA384_RSA_SIG) {
			sigLen = 10 + SHA384_HASH_SIZE + 9;
			sigType = RSA_TYPE_SIG;
		}
#endif /* USE_SHA384 */
#ifdef USE_SHA512		
		if (sc->sigAlgorithm == OID_SHA512_RSA_SIG) {
			sigLen = 10 + SHA512_HASH_SIZE + 9;
			sigType = RSA_TYPE_SIG;
		}
#endif /* USE_SHA512 */
#endif /* USE_RSA */
#ifdef USE_ECC
		if (sc->sigAlgorithm == OID_SHA1_ECDSA_SIG) {
			sigLen = SHA1_HASH_SIZE;
			sigType = DSA_TYPE_SIG;
		}
#ifdef USE_SHA256		
		if (sc->sigAlgorithm == OID_SHA256_ECDSA_SIG) {
			sigLen = SHA256_HASH_SIZE;
			sigType = DSA_TYPE_SIG;
		}
#endif /* USE_SHA256 */	
#ifdef USE_SHA384		
		if (sc->sigAlgorithm == OID_SHA384_ECDSA_SIG) {
			sigLen = SHA384_HASH_SIZE;
			sigType = DSA_TYPE_SIG;
		}
#endif /* USE_SHA384 */	
#ifdef USE_SHA512		
		if (sc->sigAlgorithm == OID_SHA512_ECDSA_SIG) {
			sigLen = SHA512_HASH_SIZE;
			sigType = DSA_TYPE_SIG;
		}
#endif /* USE_SHA512 */	
#endif /* USE_ECC */
		if (sigType == PS_UNSUPPORTED_FAIL) {
			sc->authStatus = PS_CERT_AUTH_FAIL_SIG;
			psTraceIntCrypto("Unsupported certificate signature algorithm %d\n",
				subjectCert->sigAlgorithm);
			return sigType;
		}
	
#ifdef USE_RSA
		if (sigType == RSA_TYPE_SIG) {
			psAssert(sigLen <= sizeof(sigOut));
/*
			psRsaDecryptPub destroys the 'in' parameter so let it be a tmp
*/
			tempSig = psMalloc(pool, sc->signatureLen);
			if (tempSig == NULL) {
				psError("Memory allocation error: psX509AuthenticateCert\n");
				return PS_MEM_FAIL;
			}
			memcpy(tempSig, sc->signature, sc->signatureLen);
			rsaData = NULL;
			
			if ((rc = psRsaDecryptPub(pkiPool,
					(psRsaKey_t*)&(ic->publicKey.key->rsa),
					tempSig, sc->signatureLen, sigOut, sigLen, rsaData)) < 0) {
				psTraceCrypto("Unable to RSA decrypt certificate signature\n");
				sc->authStatus = PS_CERT_AUTH_FAIL_SIG;
				psFree(tempSig);
				return rc;					
			}
			psFree(tempSig);
			rc = x509ConfirmSignature(sc->sigHash, sigOut, sigLen);
		}
#endif /* USE_RSA */
#ifdef USE_ECC
		if (sigType == DSA_TYPE_SIG) {
			rsaData = NULL;
			if ((rc = psEcDsaValidateSignature(pkiPool,
					&ic->publicKey.key->ecc,
					sc->signature, sc->signatureLen,
					sc->sigHash, sigLen, &sigStat, rsaData)) != 0) {
				psTraceCrypto("Error validating ECDSA certificate signature\n");
				sc->authStatus = PS_CERT_AUTH_FAIL_SIG;
				return rc;
			}
			if (sigStat == -1) {
				/* No errors, but signature didn't pass */
				psTraceCrypto("ECDSA certificate signature failed\n");
				rc = -1;
			}
		}
#endif /* USE_ECC */

/*
		Test what happen in the signature test?
*/
		if (rc < PS_SUCCESS) {
			sc->authStatus = PS_CERT_AUTH_FAIL_SIG;
			return rc;
		}

		/* X.509 extension tests.  Problems below here will be collected
			in flags and given to the user */

		/* If date was out of range in parse, flag it here */
		if (sc->authFailFlags & PS_CERT_AUTH_FAIL_DATE_FLAG) {
			sc->authStatus = PS_CERT_AUTH_FAIL_EXTENSION;
		}

		/* Verify subject key and auth key if either is non-zero */
		if (sc->extensions.ak.keyLen > 0 || ic->extensions.sk.len > 0) {
			if (ic->extensions.sk.len != sc->extensions.ak.keyLen) {
				psTraceCrypto("Subject/Issuer key id mismatch\n");
				sc->authStatus = PS_CERT_AUTH_FAIL_AUTHKEY;
			} else {
				if (memcmp(ic->extensions.sk.id, sc->extensions.ak.keyId,
						ic->extensions.sk.len) != 0) {
					psTraceCrypto("Subject/Issuer key id data mismatch\n");
					sc->authStatus = PS_CERT_AUTH_FAIL_AUTHKEY;
				}
			}
		}

		/* Ensure keyCertSign of KeyUsage. The second byte of the BIT STRING
			will always contain the relevant information. */
		if ( ! (ic->extensions.keyUsageFlags & KEY_USAGE_KEY_CERT_SIGN)) {
			psTraceCrypto("Issuer does not allow keyCertSign in keyUsage\n");
			sc->authFailFlags |= PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG;
			sc->authStatus = PS_CERT_AUTH_FAIL_EXTENSION;
		}
/*
		Fall through to here only if passed all non-failure checks.
*/
		if (sc->authStatus == PS_FALSE) { /* Hasn't been touched */
			sc->authStatus = PS_CERT_AUTH_PASS;
		}
/*
		Loop control for finding next ic and sc.
*/
		if (ic == sc) {
			*foundIssuer = ic;
			ic = NULL; /* Single self-signed test completed */
		} else if (ic == issuerCert) {
			*foundIssuer = ic;
			ic = NULL; /* If issuerCert was used, that is always final test */
		} else {
			sc = ic;
			ic = sc->next;
			if (ic == NULL) { /* Reached end of chain */
				*foundIssuer = ic;
				ic = sc; /* Self-signed test on final subectCert chain */
			}
		}
		
	}
	return PS_SUCCESS;
}

#ifdef USE_RSA
/******************************************************************************/
/*
	Do the signature validation for a subject certificate against a
	known CA certificate
*/
static int32 x509ConfirmSignature(unsigned char *sigHash, unsigned char *sigOut,
							uint32 sigLen)
{
	unsigned char	*end, *p = sigOut;
	unsigned char	hash[MAX_HASH_SIZE];
	int32			oi, plen;
	uint32			len;

	end = p + sigLen;
/*
	DigestInfo ::= SEQUENCE {
		digestAlgorithm DigestAlgorithmIdentifier,
		digest Digest }

	DigestAlgorithmIdentifier ::= AlgorithmIdentifier

	Digest ::= OCTET STRING
*/
	if (getAsnSequence(&p, (uint32)(end - p), &len) < 0) {
		psTraceCrypto("Initial parse error in x509ConfirmSignature\n");
		return PS_PARSE_FAIL;
	}

/*
	Could be MD5 or SHA1
 */
	if (getAsnAlgorithmIdentifier(&p, (uint32)(end - p), &oi, &plen) < 0) {
		psTraceCrypto("Algorithm ID parse error in x509ConfirmSignature\n");
		return PS_PARSE_FAIL;
	}
	psAssert(plen == 0);
	if ((*p++ != ASN_OCTET_STRING) ||
			getAsnLength(&p, (uint32)(end - p), &len) < 0 ||
				(uint32)(end - p) <  len) {
		psTraceCrypto("getAsnLength parse error in x509ConfirmSignature\n");
		return PS_PARSE_FAIL;
	}
	memcpy(hash, p, len);
	if (oi == OID_SHA1_ALG) {
		if (len != SHA1_HASH_SIZE) {
			psTraceCrypto("SHA1_HASH_SIZE error in x509ConfirmSignature\n");
			return PS_LIMIT_FAIL;
		}
#ifdef ENABLE_MD5_SIGNED_CERTS
	} else if (oi == OID_MD5_ALG || oi == OID_MD2_ALG) {
		if (len != MD5_HASH_SIZE) {
			psTraceCrypto("MD5_HASH_SIZE error in x509ConfirmSignature\n");
			return PS_LIMIT_FAIL;
		}
#endif
#ifdef USE_SHA256
	} else if (oi == OID_SHA256_ALG) {
		if (len != SHA256_HASH_SIZE) {
			psTraceCrypto("SHA256_HASH_SIZE error in x509ConfirmSignature\n");
			return PS_LIMIT_FAIL;
		}
#endif		
#ifdef USE_SHA512
	} else if (oi == OID_SHA512_ALG) {
		if (len != SHA512_HASH_SIZE) {
			psTraceCrypto("SHA512_HASH_SIZE error in x509ConfirmSignature\n");
			return PS_LIMIT_FAIL;
		}
#endif	
	} else {
		psTraceCrypto("Unsupported alg ID error in x509ConfirmSignature\n");
		return PS_UNSUPPORTED_FAIL;
	}
/*
	hash should match sigHash
*/
	if (memcmp(hash, sigHash, len) != 0) {
		psTraceCrypto("Signature failure in x509ConfirmSignature\n");
		return PS_SIGNATURE_MISMATCH;
	}
	return PS_SUCCESS;
}
#endif /* USE_RSA */

/******************************************************************************/
#ifdef USE_CRL
static void x509FreeRevoked(x509revoked_t **revoked)
{
	x509revoked_t		*next, *curr = *revoked;
	
	while (curr) {
		next = curr->next;
		psFree(curr->serial);
		psFree(curr);
		curr = next;
	}
	*revoked = NULL;
}

/*
	Parse a CRL and confirm was issued by supplied CA.
	
	Only interested in the revoked serial numbers which are stored in the
	CA structure if all checks out.  Used during cert validation as part of
	the default tests
*/
int32 psX509ParseCrl(psPool_t *pool, psX509Cert_t *CA, int append,
						unsigned char *crlBin, int32 crlBinLen)
{
	unsigned char		*end, *start, *revStart, *sigStart, *sigEnd,*p = crlBin;
	int32				oi, plen, sigLen, version, rc;
	unsigned char		sigHash[SHA512_HASH_SIZE], sigOut[SHA512_HASH_SIZE];
	x509revoked_t		*curr, *next;
	x509DNattributes_t	issuer;
	x509v3extensions_t	ext;
	psDigestContext_t	hashCtx;
	psPool_t			*pkiPool = MATRIX_NO_POOL;
	uint32				glen, ilen, timelen;

	end = p + crlBinLen;
	/*
		CertificateList  ::=  SEQUENCE  {
			tbsCertList          TBSCertList,
			signatureAlgorithm   AlgorithmIdentifier,
			signatureValue       BIT STRING  }

		TBSCertList  ::=  SEQUENCE  {
			version                 Version OPTIONAL,
                                     -- if present, shall be v2
			signature               AlgorithmIdentifier,
			issuer                  Name,
			thisUpdate              Time,
			nextUpdate              Time OPTIONAL,
			revokedCertificates     SEQUENCE OF SEQUENCE  {
             userCertificate         CertificateSerialNumber,
             revocationDate          Time,
             crlEntryExtensions      Extensions OPTIONAL
                                           -- if present, shall be v2
                                  }  OPTIONAL,
			crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
                                           -- if present, shall be v2
		}
	*/
	if (getAsnSequence(&p, (uint32)(end - p), &glen) < 0) {
		psTraceCrypto("Initial parse error in psX509ParseCrl\n");
		return PS_PARSE_FAIL;
	}
	
	sigStart = p;
	if (getAsnSequence(&p, (uint32)(end - p), &glen) < 0) {
		psTraceCrypto("Initial parse error in psX509ParseCrl\n");
		return PS_PARSE_FAIL;
	}
	if (*p == ASN_INTEGER) {
		version = 0;
		if (getAsnInteger(&p, (uint32)(end - p), &version) < 0 || version != 1){
			psTraceIntCrypto("Version parse error in psX509ParseCrl %d\n",
				version);
			return PS_PARSE_FAIL;
		}
	}
	/* signature */
	if (getAsnAlgorithmIdentifier(&p, (int32)(end - p), &oi, &plen) < 0) {
		psTraceCrypto("Couldn't parse crl sig algorithm identifier\n");
		return PS_PARSE_FAIL;
	}
		
	/*
		Name            ::=   CHOICE { -- only one possibility for now --
                                 rdnSequence  RDNSequence }

		RDNSequence     ::=   SEQUENCE OF RelativeDistinguishedName

		DistinguishedName       ::=   RDNSequence

		RelativeDistinguishedName  ::=
                    SET SIZE (1 .. MAX) OF AttributeTypeAndValue
	*/
	memset(&issuer, 0x0, sizeof(x509DNattributes_t));
	if ((rc = psX509GetDNAttributes(pool, &p, (uint32)(end - p),
			&issuer, 0)) < 0) {
		psTraceCrypto("Couldn't parse crl issuer DN attributes\n");
		return rc;
	}
	/* Ensure crlSign flag of KeyUsage for the given CA. */
	if ( ! (CA->extensions.keyUsageFlags & KEY_USAGE_CRL_SIGN)) {
		psTraceCrypto("Issuer does not allow crlSign in keyUsage\n");
		CA->authFailFlags |= PS_CERT_AUTH_FAIL_KEY_USAGE_FLAG;
		CA->authStatus = PS_CERT_AUTH_FAIL_EXTENSION;
		psX509FreeDNStruct(&issuer);
		return PS_CERT_AUTH_FAIL_EXTENSION;
	}
	if (memcmp(issuer.hash, CA->subject.hash, SHA1_HASH_SIZE) != 0) {
		psTraceCrypto("CRL NOT ISSUED BY THIS CA\n");
		psX509FreeDNStruct(&issuer);
		return PS_CERT_AUTH_FAIL_DN;
	}
	psX509FreeDNStruct(&issuer);
	
	/* thisUpdate TIME */
	if ((end - p) < 1 || ((*p != ASN_UTCTIME) && (*p != ASN_GENERALIZEDTIME))) {
		psTraceCrypto("Malformed thisUpdate CRL\n");
		return PS_PARSE_FAIL;
	}
	p++;
	if (getAsnLength(&p, (uint32)(end - p), &timelen) < 0 ||
			(uint32)(end - p) < timelen) {
		psTraceCrypto("Malformed thisUpdate CRL\n");
		return PS_PARSE_FAIL;
	}	
	p += timelen;	/* Skip it */
	/* nextUpdateTIME - Optional */
	if ((end - p) < 1 || ((*p == ASN_UTCTIME) || (*p == ASN_GENERALIZEDTIME))) {
		p++;
		if (getAsnLength(&p, (uint32)(end - p), &timelen) < 0 ||
				(uint32)(end - p) < timelen) {
			psTraceCrypto("Malformed nextUpdateTIME CRL\n");
			return PS_PARSE_FAIL;
		}	
		p += timelen;	/* Skip it */
	}
	/* 
		revokedCertificates     SEQUENCE OF SEQUENCE  {
             userCertificate         CertificateSerialNumber,
             revocationDate          Time,
             crlEntryExtensions      Extensions OPTIONAL
                                           -- if present, shall be v2
                                  }  OPTIONAL,
	*/
	if (getAsnSequence(&p, (uint32)(end - p), &glen) < 0) {
		psTraceCrypto("Initial revokedCertificates error in psX509ParseCrl\n");
		return PS_PARSE_FAIL;
	}
	
	if (CA->revoked) {
		/* Append or refresh */
		if (append == 0) { 
			/* refresh */
			x509FreeRevoked(&CA->revoked);
			CA->revoked = curr = psMalloc(pool, sizeof(x509revoked_t));
			if (curr == NULL) {
				return PS_MEM_FAIL;
			}
		} else {
			/* append.  not looking for duplicates */
			curr = psMalloc(pool, sizeof(x509revoked_t));
			if (curr == NULL) {
				return PS_MEM_FAIL;
			}
			next = CA->revoked;
			while (next->next != NULL) {
				next = next->next;
			}
			next->next = curr;
		}
	} else {
		CA->revoked = curr = psMalloc(pool, sizeof(x509revoked_t));
		if (curr == NULL) {
			return PS_MEM_FAIL;
		}
	}
	memset(curr, 0x0, sizeof(x509revoked_t));
	
	
	
	while (glen > 0) {
		revStart = p;
		if (getAsnSequence(&p, (uint32)(end - p), &ilen) < 0) {
			psTraceCrypto("Deep revokedCertificates error in psX509ParseCrl\n");
			return PS_PARSE_FAIL;
		}
		start = p;
		if ((rc = getSerialNum(pool, &p, (uint32)(end - p), &curr->serial,
				&curr->serialLen)) < 0) {
			psTraceCrypto("ASN serial number parse error\n");
			return rc;
		}
		/* skipping time and extensions */
		p += ilen - (uint32)(p - start);
		if (glen < (uint32)(p - revStart)) {
			psTraceCrypto("Deeper revokedCertificates err in psX509ParseCrl\n");
			return PS_PARSE_FAIL;
		}
		glen -= (uint32)(p - revStart);
		
		// psTraceBytes("revoked", curr->serial, curr->serialLen);
		if (glen > 0) {
			if ((next = psMalloc(pool, sizeof(x509revoked_t))) == NULL) {
				x509FreeRevoked(&CA->revoked);
				return PS_MEM_FAIL;
			}
			memset(next, 0x0, sizeof(x509revoked_t));
			curr->next = next;
			curr = next;
		}
	}
	memset(&ext, 0x0, sizeof(x509v3extensions_t));
	if (getExplicitExtensions(pool, &p, (uint32)(end - p), 0, &ext, 0) < 0) {
		psTraceCrypto("Extension parse error in psX509ParseCrl\n");
		x509FreeRevoked(&CA->revoked);
		return PS_PARSE_FAIL;
	}
	x509FreeExtensions(&ext);
	sigEnd = p;
	
	if (getAsnAlgorithmIdentifier(&p, (int32)(end - p), &oi, &plen) < 0) {
		x509FreeRevoked(&CA->revoked);
		psTraceCrypto("Couldn't parse crl sig algorithm identifier\n");
		return PS_PARSE_FAIL;
	}
	
	if ((rc = psX509GetSignature(pool, &p, (uint32)(end - p), &revStart, &ilen))
			< 0) {
		x509FreeRevoked(&CA->revoked);		
		psTraceCrypto("Couldn't parse signature\n");
		return rc;
	}
	
	if (oi == OID_SHA1_RSA_SIG) {
		sigLen = SHA1_HASH_SIZE;
		psSha1Init(&hashCtx);
		psSha1Update(&hashCtx, sigStart, (uint32)(sigEnd - sigStart));
		psSha1Final(&hashCtx, sigHash);
#ifdef ENABLE_MD5_SIGNED_CERTS
	} else if (oi == OID_MD5_RSA_SIG) {
		sigLen = MD5_HASH_SIZE;
		psMd5Init(&hashCtx);
		psMd5Update(&hashCtx, sigStart, (uint32)(sigEnd - sigStart));
		psMd5Final(&hashCtx, sigHash);
#endif
#ifdef USE_SHA256		 
	} else if (oi == OID_SHA256_RSA_SIG) {
		sigLen = SHA256_HASH_SIZE;
		psSha256Init(&hashCtx);
		psSha256Update(&hashCtx, sigStart, (uint32)(sigEnd - sigStart));
		psSha256Final(&hashCtx, sigHash);
#endif /* USE_SHA256 */	
	} else {
		psTraceCrypto("Need more signatuare alg support for CRL\n");
		x509FreeRevoked(&CA->revoked);	
		return PS_UNSUPPORTED_FAIL;
	}
	


	if ((rc = pubRsaDecryptSignedElement(pkiPool, &(CA->publicKey),
			revStart, ilen, sigOut, sigLen, NULL)) < 0) {
		x509FreeRevoked(&CA->revoked);
		psTraceCrypto("Unable to RSA decrypt CRL signature\n");
		return rc;					
	}
	
			
	if (memcmp(sigHash, sigOut, sigLen) != 0) {
		x509FreeRevoked(&CA->revoked);	
		psTraceCrypto("Unable to verify CRL signature\n");
		return PS_CERT_AUTH_FAIL_SIG;					
	}
	
	return PS_SUCCESS;
}
#endif /* USE_CRL */
#endif /* USE_CERT_PARSE */

#endif /* USE_X509 */
/******************************************************************************/


