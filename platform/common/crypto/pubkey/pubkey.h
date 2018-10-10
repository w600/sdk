/*
 *	pubkey.h
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

#ifndef _h_PS_PUBKEY
#define _h_PS_PUBKEY

#define PUBKEY_TYPE		0x01
#define PRIVKEY_TYPE	0x02

/* Public Key types for psPubKey_t */
#define PS_RSA	1
#define	PS_ECC	2
#define PS_DH	3

/* Sig types */
#define	RSA_TYPE_SIG			5
#define	DSA_TYPE_SIG			6

/*
	Pub key speed or size optimization handling
*/
#if defined(PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED) &&	defined(PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM)
#error "May only enable either PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED or PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM"
#endif

#if !defined(PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED) && !defined(PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM)
#define PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM
#endif

#ifdef PS_PUBKEY_OPTIMIZE_FOR_SMALLER_RAM
#define PS_EXPTMOD_WINSIZE		3
#endif

#ifdef PS_PUBKEY_OPTIMIZE_FOR_FASTER_SPEED
#define PS_EXPTMOD_WINSIZE		5
#endif

/******************************************************************************/
#ifdef USE_RSA
/******************************************************************************/
/*
    Primary RSA Key struct.  Define here for crypto
*/
typedef struct {
    pstm_int    e, d, N, qP, dP, dQ, p, q;
    u32      size;   /* Size of the key in bytes */
    s32       optimized; /* 1 for optimized */
} psRsaKey_t;


#endif /* USE_RSA */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_ECC
/******************************************************************************/
#define ECC_MAXSIZE	132 /* max private key size */

typedef struct {
	s32 size; /* The size of the curve in octets */
	s32 curveId; /* IANA named curve id for TLS use */
	s32 OIDsum; /* Matrix OID */
#ifdef USE_PKCS11_ECC
	CK_BYTE oid[10]; /* OID bytes */
	int		oidLen; /* OID bytes */
#else
	s32 isOptimized; /* 1 if this is an optimized curve with field parameter
							A=-3, zero otherwise. */
#endif
	char *name;  /* name of curve */
	char *prime; /* prime defining the field the curve is in (encoded in hex) */
	char *A; /* The fields A param (hex) */
	char *B; /* The fields B param (hex) */
	char *order; /* The order of the curve (hex) */
	char *Gx; /* The x co-ordinate of the base point on the curve (hex) */
	char *Gy; /* The y co-ordinate of the base point on the curve (hex) */
} psEccSet_t;
	
/*	A point on a ECC curve, stored in Jacbobian format such that 
	 (x,y,z) => (x/z^2, y/z^3, 1) when interpretted as affine
 */
typedef struct {
	pstm_int x; /* The x co-ordinate */
	pstm_int y; /* The y co-ordinate */
	pstm_int z;  /* The z co-ordinate */
} psEccPoint_t;

#ifdef USE_NATIVE_ECC
typedef struct {
	s32				type;	/* Type of key, PK_PRIVATE or PK_PUBLIC */
	psEccSet_t			*dp;	/* pointer to domain parameters; */
	psEccPoint_t		pubkey;	/* The public key */
	pstm_int			k;		/* The private key */
} psEccKey_t;

#endif
#ifdef USE_PKCS11_ECC
typedef struct {
	unsigned char		*value;
	s32				valueLen;	
} pkcs11EcKey_t;

typedef struct {
	s32				type;	/* Type of key, PK_PRIVATE or PK_PUBLIC */
	psEccSet_t			*dp;	/* pointer to domain parameters; */
	pkcs11EcKey_t		pubkey;
	pkcs11EcKey_t		k;  /* private key */
#ifdef USE_UNIFIED_PKCS11
	CK_SESSION_HANDLE	sess; /* keys stay internal to module */
	CK_OBJECT_HANDLE	obj;
	s32				external; /* Did we create the object? */
#endif
} psEccKey_t;
#endif

extern void	psGetEccCurveIdList(char *curveList, u32 *len);
extern s32 getEcPubKey(psPool_t *pool, unsigned char **pp, s32 len, 
				psEccKey_t *pubKey);

extern s32 getEccParamById(s32 curveId, psEccSet_t **set);
extern s32 getEccParamByName(char *curveName, psEccSet_t **set);
extern s32 getEccParamByOid(s32 oid, psEccSet_t **set);

#endif /* USE_ECC */
/******************************************************************************/

/******************************************************************************/
#ifdef USE_DH
/******************************************************************************/
typedef struct {
	s32	type;
    u32	size;
    pstm_int	priv, pub;	
} psDhKey_t;

typedef struct {
	u32	size;
	pstm_int	p, g;
} psDhParams_t;

#endif /* USE_DH */
/******************************************************************************/

/******************************************************************************/
/*
	Univeral public key type

	The pubKey name comes from the generic public-key crypto terminology and
	does not mean these key are restricted to the public side only. These
	may be private keys.
*/
/******************************************************************************/

typedef union {
#ifdef USE_RSA
    psRsaKey_t	rsa;
#else
	short		notEmpty; /* Prevents from being empty */
#endif /* USE_RSA */
#ifdef USE_ECC
    psEccKey_t	ecc;
#endif /* USE_ECC */
} pubKeyUnion_t;

typedef struct {
	pubKeyUnion_t	*key;
	u32			keysize; /* in bytes */
	s32			type; /* PS_RSA, PS_ECC, PS_DH */ 
} psPubKey_t;


/******************************************************************************/
/*
	Internal helpers
*/
extern s32 pkcs1Pad(unsigned char *in, u32 inlen, unsigned char *out,
				u32 outlen, s32 cryptType);
extern s32 pkcs1Unpad(unsigned char *in, u32 inlen, unsigned char *out,
				u32 outlen, s32 decryptType);

#ifdef USE_RSA				
extern void psRsaFreeKey(psRsaKey_t *key);
#endif /* USE_RSA */
/******************************************************************************/
#endif /* _h_PS_PUBKEY */

