/*
 *	x509.h
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

#ifndef _h_PS_X509
#define _h_PS_X509

/******************************************************************************/
#ifdef USE_X509
/******************************************************************************/

/* ClientCertificateType */
enum {
	RSA_SIGN = 1,
	DSS_SIGN,
	RSA_FIXED_DH,
	DSS_FIXED_DH,
	ECDSA_SIGN = 64,
	RSA_FIXED_ECDH,
	ECDSA_FIXED_ECDH
};

/* Parsing flags */
#define	CERT_STORE_UNPARSED_BUFFER	0x1
#define	CERT_STORE_DN_BUFFER		0x2

#ifdef USE_CERT_PARSE

/* Per specification, any critical extension in an X.509 cert should cause
	the connection to fail. SECURITY - Uncomment at your own risk */
/* #define ALLOW_UNKNOWN_CRITICAL_EXTENSIONS */

/*
	DN attributes are used outside the X509 area for cert requests,
	which have been included in the RSA portions of the code
*/
typedef struct {
	char	*country;
	char	*state;
	char	*locality;
	char	*organization;
	char	*orgUnit;
	char	*commonName;
	char	hash[SHA1_HASH_SIZE];	
	char	*dnenc; /* CERT_STORE_DN_BUFFER */
	u32	dnencLen;
	short	countryType;
	short	countryLen;
	short	stateType;
	short	stateLen;
	short	localityType;
	short	localityLen;
	short	organizationType;
	short	organizationLen;
	short	orgUnitType;
	short	orgUnitLen;
	short	commonNameType;
	short	commonNameLen;
} x509DNattributes_t;

typedef struct {
	s32	cA;
	s32	pathLenConstraint;
} x509extBasicConstraints_t;

typedef struct psGeneralNameEntry {
	enum {
		GN_OTHER = 0,	// OtherName
        GN_EMAIL,		// IA5String
        GN_DNS,			// IA5String
        GN_X400,		// ORAddress
        GN_DIR,			// Name
        GN_EDI,			// EDIPartyName
        GN_URI,			// IA5String
        GN_IP,			// OCTET STRING
        GN_REGID		// OBJECT IDENTIFIER
	}								id;
	unsigned char					name[16];
	unsigned char					oid[32]; /* SubjectAltName OtherName */
	u32							oidLen;
	unsigned char					*data;
	u32							dataLen;
	struct psGeneralNameEntry		*next;
} x509GeneralName_t;

typedef struct {
	u32			len;
	unsigned char	*id;
} x509extSubjectKeyId_t;

typedef struct {
	u32				keyLen;
	unsigned char		*keyId;
	x509DNattributes_t	attribs;
	u32				serialNumLen;
	unsigned char		*serialNum;
} x509extAuthKeyId_t;

#ifdef USE_FULL_CERT_PARSE
typedef struct {
	x509GeneralName_t	*permitted;
	x509GeneralName_t	*excluded;
} x509nameConstraints_t;
#endif /* USE_FULL_CERT_PARSE */

/* x509 extension types. Flag logic only works through enum of 31 */
enum {
	EXT_BASIC_CONSTRAINTS = 1,
	EXT_KEY_USAGE,
	EXT_SUBJ_KEY_ID,
	EXT_AUTH_KEY_ID,
	EXT_ALT_SUBJECT_NAME,
	EXT_CRL_DIST_PTS,
	EXT_AUTH_INFO_ACC,
	EXT_NAME_CONSTRAINTS,
	EXT_EXTND_KEY_USAGE
};

/* Make the flag value, given the enum above */
#define EXT_CRIT_FLAG(A) (unsigned int)(1 << (A))

/* Flags for known keyUsage (first byte) */
#define KEY_USAGE_DIGITAL_SIGNATURE		0x0080
#define KEY_USAGE_NON_REPUDIATION		0x0040
#define KEY_USAGE_KEY_ENCIPHERMENT		0x0020
#define KEY_USAGE_DATA_ENCIPHERMENT		0x0010
#define KEY_USAGE_KEY_AGREEMENT			0x0008
#define KEY_USAGE_KEY_CERT_SIGN			0x0004
#define KEY_USAGE_CRL_SIGN				0x0002
#define KEY_USAGE_ENCIPHER_ONLY			0x0001
/* Flags for known keyUsage (second, optional byte) */
#define KEY_USAGE_DECIPHER_ONLY			0x8000

/* Flags for known extendedKeyUsage */
#define EXT_KEY_USAGE_TLS_SERVER_AUTH	(1 << 1)
#define EXT_KEY_USAGE_TLS_CLIENT_AUTH	(1 << 2)
#define EXT_KEY_USAGE_CODE_SIGNING		(1 << 3)
#define EXT_KEY_USAGE_EMAIL_PROTECTION	(1 << 4)
#define EXT_KEY_USAGE_TIME_STAMPING		(1 << 8)
#define EXT_KEY_USAGE_OCSP_SIGNING		(1 << 9)

/* Holds the known extensions we support */
typedef struct {
	x509extBasicConstraints_t	bc;
	x509GeneralName_t			*san;
	u32						critFlags;		/* EXT_CRIT_FLAG(EXT_KEY_USE) */
	u32						keyUsageFlags;	/* KEY_USAGE_ */
	u32						ekuFlags;		/* EXT_KEY_USAGE_ */
	x509extSubjectKeyId_t		sk;
	x509extAuthKeyId_t			ak;
#ifdef USE_FULL_CERT_PARSE
	x509nameConstraints_t		nameConstraints;
#endif /* USE_FULL_CERT_PARSE */
#ifdef USE_CRL
	x509GeneralName_t			*crlDist;
#endif
} x509v3extensions_t;

#endif /* USE_CERT_PARSE */

#ifdef USE_CRL
typedef struct x509revoked {
	unsigned char		*serial;
	u32				serialLen;
	struct x509revoked	*next;
} x509revoked_t;
#endif

typedef struct psCert {
#ifdef USE_CERT_PARSE
	s32				version;
	unsigned char		*serialNumber;
	u32				serialNumberLen;
	x509DNattributes_t	issuer;
	x509DNattributes_t	subject;
	s32				notBeforeTimeType;
	s32				notAfterTimeType;
	char				*notBefore;
	char				*notAfter;
	psPubKey_t			publicKey;
	s32				pubKeyAlgorithm; /* public key algorithm OID */
	s32				certAlgorithm; /* signature algorithm OID */
	s32				sigAlgorithm; /* signature algorithm OID */
	unsigned char		*signature;
	u32				signatureLen;
	unsigned char		*uniqueIssuerId;
	u32				uniqueIssuerIdLen;
	unsigned char		*uniqueSubjectId;
	u32				uniqueSubjectIdLen;
	x509v3extensions_t	extensions;
	s32				authStatus; /* See psX509AuthenticateCert doc */
	u32				authFailFlags; /* Flags for extension check failures */
#ifdef USE_CRL
	x509revoked_t		*revoked;
#endif	
	unsigned char		sigHash[MAX_HASH_SIZE];
#endif /* USE_CERT_PARSE */	
	unsigned char		*unparsedBin; /* see psX509ParseCertFile */ 
	u32				binLen;
	struct psCert		*next;
} psX509Cert_t;


#ifdef USE_CERT_PARSE					
extern s32 psX509GetSignature(psPool_t *pool, unsigned char **pp, u32 len,
					unsigned char **sig, u32 *sigLen);
extern s32 psX509GetDNAttributes(psPool_t *pool, unsigned char **pp,
				u32 len, x509DNattributes_t *attribs, s32 flags);
extern void psX509FreeDNStruct(x509DNattributes_t *dn);
extern s32 getSerialNum(psPool_t *pool, unsigned char **pp, u32 len,
                        unsigned char **sn, u32 *snLen);
extern s32 getExplicitExtensions(psPool_t *pool, unsigned char **pp,
					u32 inlen, s32 expVal,	x509v3extensions_t *extensions,
					s32 known);
extern void x509FreeExtensions(x509v3extensions_t *extensions);
extern int psX509ValidateGeneralName(char *n);
#endif /* USE_CERT_PARSE */

#endif /* USE_X509 */
/******************************************************************************/

#endif /* _h_PS_X509 */

