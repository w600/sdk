/*
 *	ecc.c
 *	Release $Name: MATRIXSSL-3-6-1-OPEN $
 *
 *	Implements ECC over Z/pZ for curve y^2 = x^3 + ax + b
 *
 *	All curves taken from NIST recommendation paper of July 1999
 *	Available at http://csrc.nist.gov/cryptval/dss.htm
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
#include <ctype.h> /* toupper */

/******************************************************************************/
#ifdef USE_ECC
#ifdef USE_NATIVE_ECC
/******************************************************************************/

/* Enable the individual curves */
#define USE_SECP192R1
#define USE_SECP224R1
#define USE_SECP256R1
#define USE_SECP384R1
#define USE_SECP521R1

//#define USE_BRAIN224R1
#define USE_BRAIN256R1
#define USE_BRAIN384R1
#define USE_BRAIN512R1



#define ECC_BUF_SIZE 256

#define ECC_PUBLIC		0x01
#define ECC_PRIVATE		0x02

static psEccPoint_t *eccNewPoint(psPool_t *pool, short size);
static int32 eccMulmod(psPool_t *pool, void *k, psEccPoint_t *G,
                psEccPoint_t *R, pstm_int *modulus, int32 map, pstm_int *A);
static int32 eccProjectiveAddPoint(psPool_t *pool, psEccPoint_t *P,
                psEccPoint_t *Q, psEccPoint_t *R, pstm_int *modulus, pstm_digit *mp, pstm_int *A);
static int32 eccProjectiveDblPoint(psPool_t *pool, psEccPoint_t *P,
                psEccPoint_t *R, pstm_int *modulus, pstm_digit *mp, pstm_int *A);
static int32 eccMap(psPool_t *pool, psEccPoint_t *P, pstm_int *modulus,
                pstm_digit *mp);
static void eccFreePoint(psEccPoint_t *p);

static int32 pstm_read_radix(psPool_t *pool, pstm_int *a,
				char *str, int32 strlen, int32 radix);				
static int32 get_digit_count(void *a);
static unsigned long get_digit(void *a, int32 n);

/* 
	This holds the key settings.  
	***MUST*** be organized by size from smallest to largest.

	TFM DOC: implementation is meant solely for NIST and SECG GF (p) curves.
	
	The recommended elliptic curve domain parameters over p have been given
	nicknames to enable them to be easily identified. The nicknames were
	chosen as follows. Each name begins with sec to denote ‘Standards for
	Efficient Cryptography’, followed by a p to denote parameters over p,
	followed by a number denoting the length in bits of the field size p,
	followed by a k to denote parameters associated with a Koblitz curve or an
	r to denote verifiably random parameters, followed by a sequence number.
	
	
	typedef struct {
		int32 size; // The size of the curve in octets
		int32 curveId; // IANA named curve id for TLS use
		int32 OIDsum; //Matrix OID
		int32 optimized // -3 A characteristic
		char *name;  // name of curve
		char *prime; // prime defining the field the curve is in (hex)
		char *A; // The fields A param (hex)
		char *B; // The fields B param (hex)
		char *order; // The order of the curve (hex)
		char *Gx; // The x co-ordinate of the base point on the curve (hex)
		char *Gy; // The y co-ordinate of the base point on the curve (hex)
	} psEccSet_t;
*/
static psEccSet_t eccSets[] = {
#ifdef USE_SECP192R1
	{
		24, /* size in octets */
		19, /* IANA named curve ID */
		520,  /* 42.134.72.206.61.3.1.1 */
        1,  /* isOptimized */
        "ECC-192", /* secp192r1 */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", /* prime */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", /* A = -3 */ 
        "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", /* B */
        "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", /* order */
        "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", /* Gx */
        "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", /* Gy */
	},
#endif	

#ifdef USE_SECP224R1
	{
        28,
		21,
		209, /* 43.129.4.0.33 */
        1,  /* isOptimized */
        "ECC-224", /* secp224r1 */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
        "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
        "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
        "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
	},
#endif	

#ifdef USE_SECP256R1
	{
        32,
		23,
		526, /* 42.134.72.206.61.3.1.7 */
        1,  /* isOptimized */
        "ECC-256", /* secp256r1 */
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
		"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
	},
#endif
	
#ifdef USE_SECP384R1	
	{
        48,
		24,
		210, /* 43.129.4.0.34 */
        1,  /* isOptimized */
        "ECC-384", /* secp384r1 */
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
	},
#endif
	
#ifdef USE_SECP521R1	
	{
        66,
		25,
		211, /* 43.129.4.0.35 */
        1,  /* isOptimized */
        "ECC-521", /* secp521r1 */
        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
		"1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
        "51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
        "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
        "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
        "11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
	},
#endif

#ifdef USE_BRAIN224R1
	{
        28, /* size in octets */
        55, /* MADE THIS UP FOR NOW - official curve ID if ever assigned */
        102,  /* 1.3.36.3.3.2.8.1.1.5 */ /* XXX Patrick : How to compute the OIDsum ? */
        0,  /* isOptimized */
        "BP-224", /* brainpoolP256r1 */
        "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",
        "68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43",
        "2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B",
        "D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F",
        "0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D",
        "58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD"
 	},
#endif

#ifdef USE_BRAIN256R1
	{
        32, /* size in octets */
        26,
        104,  /* 1.3.36.3.3.2.8.1.1.7 */
        0,  /* isOptimized */
        "BP-256", /* brainpoolP256r1 */
        "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
        "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
        "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
        "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
        "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
        "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
	},
#endif

#ifdef USE_BRAIN384R1
	{
        48, /* size in octets */
        27,
        108,  /* 1.3.36.3.3.2.8.1.1.11 */
        0,  /* isOptimized */
        "BP-384", /* brainpoolP384r1 */
        "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
        "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
        "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
        "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
        "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
        "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
	},
#endif

#ifdef USE_BRAIN512R1
	{
        64, /* size in octets */
        28,
        110,  /* 1.3.36.3.3.2.8.1.1.13 */
        0,  /* isOptimized */
        "BP-512", /* brainpoolP512r1 */
        "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
        "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
        "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
        "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",
        "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
        "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
	},
#endif

		{
            0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL
	}
};

/*****************************************************************************/
/*
	Called from the cert parse.  The initial bytes in this stream are
	technically the EcpkParameters from the ECDSA pub key OBJECT IDENTIFIER
	that name the curve.  The asnGetAlgorithmIdentifier call right before
	this just stripped out the OID
*/
int32 getEcPubKey(psPool_t *pool, unsigned char **pp, int32 len, 
				psEccKey_t *pubKey)
{
	psEccSet_t		*eccSet;
	unsigned char	*p = *pp, *end;
	int32			oid, ignore_bits;
	uint32			arcLen;

	end = p + len;
	if (*(p++) != ASN_OID || getAsnLength(&p, (int32)(end - p), &arcLen) < 0){
		psTraceCrypto("Only namedCurve types are supported in EC certs\n");
		return -1;
	}
	
	if (end - p < 2) {
		return -1;
	}
/*
	NamedCurve OIDs
 
	ansi-x9-62 OBJECT IDENTIFER ::= {
		iso(1) member-body(2) us(840) 10045
	}
 
	secp192r1 OBJECT IDENTIFIER ::= { ansi-x9-62 curves(3) prime(1) 1 }
		2a8648ce3d030101 -> sum = 520
		
	secp256r1 OBJECT IDENTIFIER ::= { ansi-x9-62 curves(3) prime(1) 7 }
		2a8648ce3d030107 -> sum = 526
*/

//	if ((*p != 0x2a) && (*(p + 1) != 0x86)) {
/*
		 Expecting DSA here if not RSA, but OID doesn't always match
*/
//		psTraceCrypto("Unrecognized namedCurve OID\n");
//		return -1;
//	}
	oid = 0;
	while (arcLen-- > 0) {
		oid += (int32)*p++;
	}
/*
	Match the sum against our list of curves to make sure we got it
*/
	if (getEccParamByOid(oid, &eccSet) < 0) {
		psTraceCrypto("Cert named curve not found in eccSet list\n");
		return -1;
	}
	
	if (len < 1 || (*(p++) != ASN_BIT_STRING) ||
			getAsnLength(&p, len - 1, &arcLen) < 0) {
		return -1;
	}
	ignore_bits = *p++;
	if (ignore_bits != 0) {
		psTraceCrypto("Unexpected ECC pubkey format\n");
	}
	arcLen--;
	
	if (psEccX963ImportKey(pool, p, arcLen, pubKey) < 0) {
		psTraceCrypto("Unable to parse ECC pubkey from cert\n");
		return -1;
	}
	pubKey->dp = eccSet;
	p += arcLen;
							
	*pp = p;
	return 0;
}



int32 psEccMakeKeyEx(psPool_t *pool, psEccKey_t **keyPtr, psEccSet_t *dp,
		void *pkiData)
{
	int32			err, keysize, slen;
	psEccPoint_t	*base;
	psEccKey_t		*key;
	pstm_int		prime, *A = NULL;
	unsigned char	*buf;

	if (dp == NULL) {
		psTraceCrypto("Only named curves supported in psEccMakeKeyEx\n");
		return PS_UNSUPPORTED_FAIL;
	}
	
	key = psMalloc(pool, sizeof(psEccKey_t));
	if (key == NULL) {
		psError("Memory allocation error in psEccMakeKeyEx\n");
		return PS_MEM_FAIL;
	}
	memset(key, 0, sizeof(psEccKey_t));
	key->dp  = dp;
	keysize  = dp->size;
	slen = keysize * 2;

	/* allocate ram */
	base = NULL;
	buf  = psMalloc(pool, ECC_MAXSIZE);
	if (buf == NULL) {
		psError("Memory allocation error in psEccMakeKeyEx\n");
		err = PS_MEM_FAIL;
		goto ERR_KEY;
	}

	/* make up random string */
	if (psGetPrng(NULL, buf, keysize) != keysize) {
		err = PS_PLATFORM_FAIL;
		goto ERR_BUF;
	}

    if (key->dp->isOptimized == 0)
    {
        if ((A = psMalloc(pool, sizeof(pstm_int))) == NULL) {
            err = PS_MEM_FAIL;
            goto ERR_BUF;
        }

        if (pstm_init_for_read_unsigned_bin(pool, A, keysize) < 0) {
            err = PS_MEM_FAIL;
            psFree(A);
            goto ERR_BUF;
        }
        
        if ((err = pstm_read_radix(pool, A, (char *)key->dp->A, slen, 16))
            != PS_SUCCESS) {
            goto ERR_A;
        }
    }

	if (pstm_init_for_read_unsigned_bin(pool, &prime, keysize) < 0) {
		err = PS_MEM_FAIL;
		goto ERR_A;
	}
	
	base = eccNewPoint(pool, prime.alloc);
	if (base == NULL) {
		err = PS_MEM_FAIL;
		goto ERR_PRIME;
	}

	/* read in the specs for this key */
	if ((err = pstm_read_radix(pool, &prime, (char *)key->dp->prime, slen, 16))
			!= PS_SUCCESS) {
		goto ERR_BASE;
	}
	if ((err = pstm_read_radix(pool, &base->x, (char *)key->dp->Gx, slen, 16))
			!= PS_SUCCESS){
		goto ERR_BASE;
	}
	if ((err = pstm_read_radix(pool, &base->y, (char *)key->dp->Gy, slen, 16))
			!= PS_SUCCESS){
		goto ERR_BASE;
	}
	pstm_set(&base->z, 1);
	
	if (pstm_init_for_read_unsigned_bin(pool, &key->k, keysize) < 0) {
		err = PS_MEM_FAIL;
		goto ERR_BASE;
	}
	if ((err = pstm_read_unsigned_bin(&key->k, (unsigned char *)buf, keysize))
			!= PS_SUCCESS) {
		goto ERR_BASE;
	}


	/* make the public key */
	if (pstm_init_size(pool, &key->pubkey.x, (key->k.used * 2) + 1) < 0) {
		err = PS_MEM_FAIL;
		goto ERR_BASE;
	}
	if (pstm_init_size(pool, &key->pubkey.y, (key->k.used * 2) + 1) < 0) {
		err = PS_MEM_FAIL;
		goto ERR_BASE;
	}
	if (pstm_init_size(pool, &key->pubkey.z, (key->k.used * 2) + 1) < 0) {
		err = PS_MEM_FAIL;
		goto ERR_BASE;
	}
	if ((err = eccMulmod(pool, &key->k, base, &key->pubkey, &prime, 1, A)) !=
			PS_SUCCESS) {
		goto ERR_BASE;
	}

	key->type = PRIVKEY_TYPE;

	/* frees for success */
	eccFreePoint(base);
	pstm_clear(&prime);
    if (A) {
        pstm_clear(A);
        psFree(A);
    }
	psFree(buf);
	*keyPtr = key;
	return PS_SUCCESS;
	
ERR_BASE:	
	eccFreePoint(base);
ERR_PRIME:
	pstm_clear(&prime);
ERR_A:
    if (A) {
        pstm_clear(A);
        psFree(A);
    }
ERR_BUF:
	psFree(buf);
ERR_KEY:
	psEccFreeKey(&key);
	return err;
}

#ifdef MATRIX_USE_FILE_SYSTEM
#ifdef USE_PRIVATE_KEY_PARSING
/******************************************************************************/
/*
	ECPrivateKey{CURVES:IOSet} ::= SEQUENCE { 
		version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1), 
		privateKey OCTET STRING, 
		parameters [0] Parameters{{IOSet}} OPTIONAL, 
		publicKey [1] BIT STRING OPTIONAL 
	} 
 
*/
int32 psEcdsaParsePrivFile(psPool_t *pool, char *fileName, char *password,
			psPubKey_t **outkey)
{
	unsigned char	*DERout;
	int32			rc;
	uint32			DERlen;
	psPubKey_t		*keyPtr;

	*outkey = NULL;

	if ((rc = pkcs1DecodePrivFile(pool, fileName, password, &DERout, &DERlen))
			< PS_SUCCESS) {
		return rc;
	}

	if ((rc = psEcdsaParsePrivKey(pool, DERout, DERlen, &keyPtr, NULL)) < 0) {
#ifdef USE_PKCS8
		/* This logic works for processing PKCS#8 files becuase the above file
			and bin decodes will always leave the unprocessed buffer intact and
			the password protection is done in the internal ASN.1 encoding */
		if ((rc = pkcs8ParsePrivBin(pool, DERout, DERlen, password,
				&keyPtr)) < 0) {
			psFree(DERout);
			return rc;
		}
#else
		psFree(DERout);
		return rc;
#endif
	}
	
	psFree(DERout);
	*outkey = keyPtr;
	return PS_SUCCESS;
}
#endif /* USE_PRIVATE_KEY_PARSING */
#endif /* MATRIX_USE_FILE_SYSTEM */

int32 psEcdsaParsePrivKey(psPool_t *pool, unsigned char *keyBuf,
				int32 keyBufLen, psPubKey_t **pubkey, psEccSet_t *curve)
{
	psEccKey_t		*key;
	psEccSet_t		*eccSet;
	unsigned char	*buf, *end;
	int32			oid, ignore_bits;
	uint32			len;
	
	buf = keyBuf;
	end = buf + keyBufLen;
	
	
	if (getAsnSequence(&buf, (int32)(end - buf), &len) < 0) {
		psTraceCrypto("ECDSA subject signature parse failure 1\n");
		return PS_FAILURE;
	}
	if (getAsnInteger(&buf, (int32)(end - buf), (int32*)&len) < 0) {
		psTraceCrypto("Expecting private key flag\n");
		return PS_FAILURE;
	}
	if (len != 1) {
		psTraceCrypto("Expecting private key flag\n");
		return PS_FAILURE;
	}
		
/*
	Initial curve check
*/
	if ((*buf++ != ASN_OCTET_STRING) ||
			getAsnLength(&buf, (int32)(end - buf), &len) < 0 ||
			(end - buf) <  (int32)len) {
		psTraceCrypto("Expecting private key octet string\n");
		return PS_FAILURE;
	}	
/*
	Format is looking fine.  Get the key structure ready
*/	
	*pubkey = psNewPubKey(pool);
	if (*pubkey == NULL) {
		psError("Memory allocation error in pkcs1ParsePrivBin\n");
		return PS_MEM_FAIL;
	}
	(*pubkey)->type = PS_ECC;
	key = &((*pubkey)->key->ecc);

	memset(key, 0x0, sizeof(psEccKey_t));
	if (pstm_init_for_read_unsigned_bin(pool, &key->k, len) != PS_SUCCESS) {
		psFreePubKey(*pubkey);
		*pubkey = NULL;
		return PS_FAILURE;
	}
/*
	 Key material
*/
	if (pstm_read_unsigned_bin(&key->k, (unsigned char*)buf, len) != PS_SUCCESS) {
		psTraceCrypto("Unable to read private key octet string\n");
		psFreePubKey(*pubkey);
		*pubkey = NULL;
		return PS_FAILURE;
	}
	buf += len;
	
	if (*buf == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0)) {
/*
		optional parameters are present
*/
		buf++;
		if (getAsnLength(&buf, (int32)(end - buf), &len) < 0 ||
				(end - buf) <  (int32)len) {
			psTraceCrypto("Bad private key format\n");
			psFreePubKey(*pubkey);
			return PS_FAILURE;
		}
		if (*(buf++) != ASN_OID ||
				getAsnLength(&buf, (int32)(end - buf), &len) < 0){
			psTraceCrypto("Only namedCurves are supported in EC keys\n");
			psFreePubKey(*pubkey); *pubkey = NULL;
			return PS_FAILURE;
		}
		oid = 0;
		while (len-- > 0) {
			oid += (int32)*buf++;
		}
		if (getEccParamByOid(oid, &eccSet) < 0) {
			psTraceCrypto("Cert named curve not found in eccSet list\n");
			psFreePubKey(*pubkey); *pubkey = NULL;
			return PS_FAILURE;
		}
		if (curve != NULL) {
			if (curve != eccSet) {
				psTraceCrypto("PrivKey named curve doesn't match desired\n");
			}
		}
		key->dp = eccSet;
		
	} else if (curve != NULL) {
		key->dp = curve;
	} else {
		psTraceCrypto("No curve paramaters found in EC private key\n");
		psFreePubKey(*pubkey); *pubkey = NULL;
		return PS_FAILURE;
	}
	
	if (*buf == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 1)) {
/*
		optional public key is present
*/	
		buf++;
		if (getAsnLength(&buf, (int32)(end - buf), &len) < 0 ||
				(end - buf) <  (int32)len) {
			psTraceCrypto("Bad private key format\n");
			psFreePubKey(*pubkey); *pubkey = NULL;
			return -1;
		}
		if (*(buf++) != ASN_BIT_STRING ||
				getAsnLength(&buf, (int32)(end - buf), &len) < 0) {
			psFreePubKey(*pubkey); *pubkey = NULL;	
			return -1;
		}
		ignore_bits = *buf++;
		if (ignore_bits != 0) {
			psTraceCrypto("Unexpected ECC pubkey format\n");
		}
		len--;
		
		if (psEccX963ImportKey(pool, buf, len, key) < 0) {
			psTraceCrypto("Unable to parse ECC pubkey from cert\n");
			psFreePubKey(*pubkey); *pubkey = NULL;
			return -1;
		}
		buf += len;
		key->type = PRIVKEY_TYPE;
	}
/*
	Mainly just a shortcut size to help with message lengths later
*/
	(*pubkey)->keysize = key->dp->size * 2;
/*
	Should be at the end
*/
	if (end != buf) {
		psTraceCrypto("Didn't reach end of private key parse\n");
	}

	return PS_SUCCESS;
}

int32 getEccParamById(int32 curveId, psEccSet_t **set)
{
	int32 i = 0;
	
	*set = NULL;
	while (eccSets[i].size > 0) {
		if (curveId == eccSets[i].curveId) {
			*set = (psEccSet_t*)&eccSets[i];
			return 0;
		}
		i++;
	}
	return -1;
}

int32 getEccParamByOid(int32 oid, psEccSet_t **set)
{
	int32 i = 0;
	
	*set = NULL;
	while (eccSets[i].size > 0) {
		if (oid == eccSets[i].OIDsum) {
			*set = (psEccSet_t*)&eccSets[i];
			return 0;
		}
		i++;
	}
	return -1;
}

int32 getEccParamByName(char *curveName, psEccSet_t **set)
{
	int32 i = 0;
	
	*set = NULL;
	while (eccSets[i].size > 0) {
		if (strcmp(curveName, eccSets[i].name) == 0) {
			*set = (psEccSet_t*)&eccSets[i];
			return 0;
		}
		i++;
	}
	return -1;
}

/*
	Return a list of supported curves
*/
void psGetEccCurveIdList(char *curveList, uint32 *len)
{
	uint32	listLen = 0;
	int32	i = 0;
	
	while (eccSets[i].size > 0) {
		if (listLen < (*len - 2)) {
			curveList[listLen++] = (eccSets[i].curveId & 0xFF00) >> 8; 
			curveList[listLen++] = eccSets[i].curveId & 0xFF;
		}
		i++;
	}
	*len = listLen;
}


/******************************************************************************/
/*
	Perform a point multiplication 
	@param k    The scalar to multiply by
	@param G    The base point
	@param R    [out] Destination for kG
	@param modulus  The modulus of the field the ECC curve is in
	@param map      Boolean whether to map back to affine or not (1==map)
	@return PS_SUCCESS on success
*/
/* size of sliding window, don't change this! */
#define ECC_MULMOD_WINSIZE 4

static int32 eccMulmod(psPool_t *pool, void *k, psEccPoint_t *G,
                       psEccPoint_t *R, pstm_int *modulus, int32 map, pstm_int *A)
{
	psEccPoint_t	*tG, *M[8];
	int32			i, j, err;
	pstm_int		mu;
	pstm_digit		mp;
	unsigned long	buf;
	int32			first, bitbuf, bitcpy, bitcnt, mode, digidx;

	/* init montgomery reduction */
	if ((err = pstm_montgomery_setup(modulus, &mp)) != PS_SUCCESS) {
		return err;
	}
	if ((err = pstm_init_size(pool, &mu, modulus->alloc)) != PS_SUCCESS) {
		return err;
	}
	if ((err = pstm_montgomery_calc_normalization(&mu, modulus)) != PS_SUCCESS) {
		pstm_clear(&mu);
		return err;
	}
  
	/* alloc ram for window temps */
	for (i = 0; i < 8; i++) {
		M[i] = eccNewPoint(pool, (G->x.used * 2) + 1);
		if (M[i] == NULL) {
			for (j = 0; j < i; j++) {
				eccFreePoint(M[j]);
			}
			pstm_clear(&mu);
			return PS_MEM_FAIL;
		}
	}

	/* make a copy of G incase R==G */
	tG = eccNewPoint(pool, G->x.alloc);
	if (tG == NULL) {
		err = PS_MEM_FAIL;
		goto done;
	}

	/* tG = G  and convert to montgomery */
	if (pstm_cmp_d(&mu, 1) == PSTM_EQ) {
		if ((err = pstm_copy(&G->x, &tG->x)) != PS_SUCCESS) { goto done; }
		if ((err = pstm_copy(&G->y, &tG->y)) != PS_SUCCESS) { goto done; }
		if ((err = pstm_copy(&G->z, &tG->z)) != PS_SUCCESS) { goto done; }
	} else {      
		if ((err = pstm_mulmod(pool, &G->x, &mu, modulus, &tG->x)) != PS_SUCCESS) {
			goto done;
		}
		if ((err = pstm_mulmod(pool, &G->y, &mu, modulus, &tG->y)) != PS_SUCCESS) {
			goto done;
		}
		if ((err = pstm_mulmod(pool, &G->z, &mu, modulus, &tG->z)) != PS_SUCCESS) {
			goto done;
		}
	}
	pstm_clear(&mu);
   
	/* calc the M tab, which holds kG for k==8..15 */
	/* M[0] == 8G */
	if ((err = eccProjectiveDblPoint(pool, tG, M[0], modulus, &mp, A)) != PS_SUCCESS)
	{
		goto done;
	}
	if ((err = eccProjectiveDblPoint(pool, M[0], M[0], modulus, &mp, A)) !=
			PS_SUCCESS) {
		goto done;
	}
	if ((err = eccProjectiveDblPoint(pool, M[0], M[0], modulus, &mp, A)) !=
			PS_SUCCESS) {
		goto done;
	}

	/* now find (8+k)G for k=1..7 */
	for (j = 9; j < 16; j++) {
		if ((err = eccProjectiveAddPoint(pool, M[j-9], tG, M[j-8], modulus,
                                         &mp, A)) != PS_SUCCESS) {
			goto done;
		}
	}

	/* setup sliding window */
	mode   = 0;
	bitcnt = 1;
	buf    = 0;
	digidx = get_digit_count(k) - 1;
	bitcpy = bitbuf = 0;
	first  = 1;

	/* perform ops */
	for (;;) {
		/* grab next digit as required */
		if (--bitcnt == 0) {
			if (digidx == -1) {
				break;
			}
			buf = get_digit(k, digidx);
			bitcnt = DIGIT_BIT;
			--digidx;
		}

		/* grab the next msb from the ltiplicand */
		i = (buf >> (DIGIT_BIT - 1)) & 1;
		buf <<= 1;

		/* skip leading zero bits */
		if (mode == 0 && i == 0) {
			continue;
		}

		/* if the bit is zero and mode == 1 then we double */
		if (mode == 1 && i == 0) {
			if ((err = eccProjectiveDblPoint(pool, R, R, modulus, &mp, A)) !=
					PS_SUCCESS) {
				goto done;
			}
			continue;
		}

		/* else we add it to the window */
		bitbuf |= (i << (ECC_MULMOD_WINSIZE - ++bitcpy));
		mode = 2;

		if (bitcpy == ECC_MULMOD_WINSIZE) {
			/* if this is the first window we do a simple copy */
			if (first == 1) {
				/* R = kG [k = first window] */
				if ((err = pstm_copy(&M[bitbuf-8]->x, &R->x)) != PS_SUCCESS) {
					goto done;
				}
				if ((err = pstm_copy(&M[bitbuf-8]->y, &R->y)) != PS_SUCCESS) {
					goto done;
				}
				if ((err = pstm_copy(&M[bitbuf-8]->z, &R->z)) != PS_SUCCESS) {
					goto done;
				}
				first = 0;
			} else {
				/* normal window */
				/* ok window is filled so double as required and add  */
				/* double first */
				for (j = 0; j < ECC_MULMOD_WINSIZE; j++) {
					if ((err = eccProjectiveDblPoint(pool, R, R, modulus, &mp, A))
							!= PS_SUCCESS) {
						goto done;
					}
				}

				/* then add, bitbuf will be 8..15 [8..2^WINSIZE] guaranteed */
				if ((err = eccProjectiveAddPoint(pool, R, M[bitbuf-8], R,
                                                 modulus, &mp, A)) != PS_SUCCESS) {
					goto done;
				}
			}
			/* empty window and reset */
			bitcpy = bitbuf = 0;
			mode = 1;
		}
	}

	/* if bits remain then double/add */
	if (mode == 2 && bitcpy > 0) {
		/* double then add */
		for (j = 0; j < bitcpy; j++) {
			/* only double if we have had at least one add first */
			if (first == 0) {
				if ((err = eccProjectiveDblPoint(pool, R, R, modulus, &mp, A)) !=
						PS_SUCCESS) {
					goto done;
				}
			}

			bitbuf <<= 1;
			if ((bitbuf & (1 << ECC_MULMOD_WINSIZE)) != 0) {
				if (first == 1){
					/* first add, so copy */
					if ((err = pstm_copy(&tG->x, &R->x)) != PS_SUCCESS) {
						goto done;
					}
					if ((err = pstm_copy(&tG->y, &R->y)) != PS_SUCCESS) {
						goto done;
					}
					if ((err = pstm_copy(&tG->z, &R->z)) != PS_SUCCESS) {
						goto done;
					}
					first = 0;
				} else {
					/* then add */
					if ((err = eccProjectiveAddPoint(pool, R, tG, R, modulus,
                                                     &mp, A)) !=	PS_SUCCESS) {
						goto done;
					}
				}
			}
		}
	}

	/* map R back from projective space */
	if (map) {
		err = eccMap(pool, R, modulus, &mp);
	} else {
		err = PS_SUCCESS;
	}
done:

	pstm_clear(&mu);
	eccFreePoint(tG);
	for (i = 0; i < 8; i++) {
		eccFreePoint(M[i]);
	}
	return err;
}


int32 psEccX963ImportKey(psPool_t *pool, const unsigned char *in,
							uint32 inlen, psEccKey_t *key)
{
	int32 err;
		
	/* must be odd */
	if ((inlen & 1) == 0) {
		return PS_ARG_FAIL;
	}
	
	/* init key */
	if (pstm_init_for_read_unsigned_bin(pool, &key->pubkey.x, (inlen-1)>>1) < 0)
	{
		return PS_MEM_FAIL;
	}
	if (pstm_init_for_read_unsigned_bin(pool, &key->pubkey.y, (inlen-1)>>1) < 0)
	{
		pstm_clear(&key->pubkey.x);
		return PS_MEM_FAIL;
	}
	if (pstm_init_size(pool, &key->pubkey.z, 1) < 0) {
		pstm_clear(&key->pubkey.x);
		pstm_clear(&key->pubkey.y);
		return PS_MEM_FAIL;
	}
	
	/* check for 3, 4, 6 or 7 
		4 is the standard Octet-String id.  3 has been seen in Bit-String use
			but should parse just the same.
		6 and 7 are for compressed point formats?
			can't see compression support here though */
	if (in[0] != 3 && in[0] != 4 && in[0] != 6 && in[0] != 7) {
		err = PS_UNSUPPORTED_FAIL;
		goto error;
	}
	
	/* read data */
	if ((err = pstm_read_unsigned_bin(&key->pubkey.x, (unsigned char *)in+1,
			(inlen-1)>>1)) != PS_SUCCESS) {
		goto error;
	}
	
	if ((err = pstm_read_unsigned_bin(&key->pubkey.y,
			(unsigned char *)in+1+((inlen-1)>>1), (inlen-1)>>1)) != PS_SUCCESS) {
		goto error;
	}
	pstm_set(&key->pubkey.z, 1);
	
	key->type = ECC_PUBLIC;
	
	/* we're done */
	return PS_SUCCESS;
error:
	pstm_clear_multi(&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, NULL,
					NULL, NULL, NULL, NULL);
	return err;
}

/** ECC X9.63 (Sec. 4.3.6) uncompressed export
 @param key     Key to export
 @param out     [out] destination of export
 @param outlen  [in/out]  Length of destination and final output size
 Return PS_SUCCESS on success
 */
int32 psEccX963ExportKey(psPool_t *pool, psEccKey_t *key, unsigned char *out,
						 uint32 *outlen)
{
	unsigned char buf[ECC_BUF_SIZE];
	unsigned long numlen;
	int32			res;
	
	numlen = key->dp->size;
	
	if (*outlen < (1 + 2*numlen)) {
		*outlen = 1 + 2*numlen;
		return PS_LIMIT_FAIL;
	}
	
	/* store byte 0x04 - Octet-String */
	out[0] = 0x04;
	
	/* pad and store x */
	memset(buf, 0, sizeof(buf));
	if ((res = pstm_to_unsigned_bin(pool, &key->pubkey.x, buf +
			(numlen - pstm_unsigned_bin_size(&key->pubkey.x)))) != PSTM_OKAY) {
		return res;
	}
	memcpy(out+1, buf, numlen);
	
	/* pad and store y */
	memset(buf, 0, sizeof(buf));
	if ((res = pstm_to_unsigned_bin(pool, &key->pubkey.y, buf +
			(numlen - pstm_unsigned_bin_size(&key->pubkey.y)))) != PSTM_OKAY) {
		return res;
	}
	memcpy(out+1+numlen, buf, numlen);
	
	*outlen = 1 + 2*numlen;
	return PS_SUCCESS;
}


/**
 Create an ECC shared secret between two keys
 @param private_key      The private ECC key
 @param public_key       The public key
 @param out              [out] Destination of the shared secret (Conforms to EC-DH from ANSI X9.63)
 @param outlen           [in/out] The max size and resulting size of the shared secret
 @return PS_SUCCESS if successful
 */
int32 psEccGenSharedSecret(psPool_t *pool, psEccKey_t *private_key,
			psEccKey_t *public_key, unsigned char *out, uint32 *outlen,
			void *eccData)
{
	unsigned long	x;
	psEccPoint_t	*result;
	pstm_int		prime, *A = NULL;
	int32			err;
	
	/* type valid? */
	if (private_key->type != PRIVKEY_TYPE) {
		return PS_ARG_FAIL;
	}

	/* make new point */
	result = eccNewPoint(pool, (private_key->k.used * 2) + 1);
	if (result == NULL) {
		return PS_MEM_FAIL;
	}

    if (private_key->dp->isOptimized == 0)
    {
        if ((A = psMalloc(pool, sizeof(pstm_int))) == NULL) {
            eccFreePoint(result);
            return PS_MEM_FAIL;
        }

        if (pstm_init_for_read_unsigned_bin(pool, A, private_key->dp->size) < 0) {
            psFree(A);
            eccFreePoint(result);
            return PS_MEM_FAIL;
        }
        
        if ((err = pstm_read_radix(pool, A, (char *)private_key->dp->A,
                                   private_key->dp->size * 2, 16))
            != PS_SUCCESS) {
            pstm_clear(A);
            psFree(A);
            eccFreePoint(result);
            return err;
        }
    }
   
	if ((err = pstm_init_for_read_unsigned_bin(pool, &prime,
			private_key->dp->size))	!= PS_SUCCESS) {
        if (A) {
            pstm_clear(A);
            psFree(A);
        }
		eccFreePoint(result);
		return err;
	}
	
	if ((err = pstm_read_radix(pool, &prime, (char *)private_key->dp->prime,
			private_key->dp->size * 2, 16)) != PS_SUCCESS){
		goto done;
	}
	if ((err = eccMulmod(pool, &private_key->k, &public_key->pubkey, result,
                         &prime, 1, A)) != PS_SUCCESS) {
		goto done;
	}
	
	x = (unsigned long)pstm_unsigned_bin_size(&prime);
	if (*outlen < x) {
		*outlen = x;
		err = PS_LIMIT_FAIL;
		goto done;
	}
	memset(out, 0, x);
	if ((err = pstm_to_unsigned_bin(pool, &result->x,
			out + (x - pstm_unsigned_bin_size(&result->x)))) != PS_SUCCESS) {
		goto done;
	}
	
	err = PS_SUCCESS;
	*outlen = x;
done:
    if (A) {
        pstm_clear(A);
        psFree(A);
    }
	pstm_clear(&prime);
	eccFreePoint(result);
	return err;
}


/******************************************************************************/
/*
	Add two ECC points
	@param P        The point to add
	@param Q        The point to add
	@param R        [out] The destination of the double
	@param modulus  The modulus of the field the ECC curve is in
	@param mp       The "b" value from montgomery_setup()
	@return PS_SUCCESS on success
*/
static int32 eccProjectiveAddPoint(psPool_t *pool, psEccPoint_t *P,
             psEccPoint_t *Q, psEccPoint_t *R, pstm_int *modulus, pstm_digit *mp, pstm_int *A)
{
	pstm_int	t1, t2, x, y, z;
	pstm_digit	*paD;
	int32		err;
	uint32		paDlen;

	paD = NULL;
	if (pstm_init_size(pool, &t1, P->x.alloc) < 0) {
		return PS_MEM_FAIL;
	}
	err = PS_MEM_FAIL;
	if (pstm_init_size(pool, &t2, P->x.alloc) < 0) {
		goto ERR_T1;
	}
	if (pstm_init_size(pool, &x, P->x.alloc) < 0) {
		goto ERR_T2;
	}
	if (pstm_init_size(pool, &y, P->y.alloc) < 0) {
		goto ERR_X;
	}
	if (pstm_init_size(pool, &z, P->z.alloc) < 0) {
		goto ERR_Y;
	}
   
	/* should we dbl instead? */
	if ((err = pstm_sub(modulus, &Q->y, &t1)) != PS_SUCCESS) { goto done; }

	if ((pstm_cmp(&P->x, &Q->x) == PSTM_EQ) && 
			(&Q->z != NULL && pstm_cmp(&P->z, &Q->z) == PSTM_EQ) &&
			(pstm_cmp(&P->y, &Q->y) == PSTM_EQ ||
			pstm_cmp(&P->y, &t1) == PSTM_EQ)) {
		pstm_clear_multi(&t1, &t2, &x, &y, &z, NULL, NULL, NULL);
		return eccProjectiveDblPoint(pool, P, R, modulus, mp, A);
	}

	if ((err = pstm_copy(&P->x, &x)) != PS_SUCCESS) { goto done; }
	if ((err = pstm_copy(&P->y, &y)) != PS_SUCCESS) { goto done; }
	if ((err = pstm_copy(&P->z, &z)) != PS_SUCCESS) { goto done; }

/*
	Pre-allocated digit.  Used for mul, sqr, AND reduce
	TODO: haven't fully explored max paDlen
*/
	paDlen = (modulus->used*2+1) * sizeof(pstm_digit);
	if ((paD = psMalloc(pool, paDlen)) == NULL) {
		err = PS_MEM_FAIL;
		goto done;
	}

	/* if Z is one then these are no-operations */
	if (&Q->z != NULL) {
		/* T1 = Z' * Z' */
		if ((err = pstm_sqr_comba(pool, &Q->z, &t1, paD, paDlen))
				!= PS_SUCCESS) {
			goto done;
		}
		if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
				!= PS_SUCCESS) {
			goto done;
		}
		/* X = X * T1 */
		if ((err = pstm_mul_comba(pool, &t1, &x, &x, paD, paDlen))
				!= PS_SUCCESS) {
			goto done;
		}
		if ((err = pstm_montgomery_reduce(pool, &x, modulus, *mp, paD, paDlen))
				!= PS_SUCCESS) {
			goto done;
		}
		/* T1 = Z' * T1 */
		if ((err = pstm_mul_comba(pool, &Q->z, &t1, &t1, paD, paDlen))
				!= PS_SUCCESS) {
			goto done;
		}
		if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
				!= PS_SUCCESS) {
			goto done;
		}
		/* Y = Y * T1 */
		if ((err = pstm_mul_comba(pool, &t1, &y, &y, paD, paDlen))
				!= PS_SUCCESS) {
			goto done;
		}
		if ((err = pstm_montgomery_reduce(pool, &y, modulus, *mp, paD, paDlen))
				!= PS_SUCCESS) {
			goto done;
		}
	}

	/* T1 = Z*Z */
	if ((err = pstm_sqr_comba(pool, &z, &t1, paD, paDlen)) != PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	/* T2 = X' * T1 */
	if ((err = pstm_mul_comba(pool, &Q->x, &t1, &t2, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &t2, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	/* T1 = Z * T1 */
	if ((err = pstm_mul_comba(pool, &z, &t1, &t1, paD, paDlen)) != PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	/* T1 = Y' * T1 */
	if ((err = pstm_mul_comba(pool, &Q->y, &t1, &t1, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}

	/* Y = Y - T1 */
	if ((err = pstm_sub(&y, &t1, &y)) != PS_SUCCESS) { goto done; }
	if (pstm_cmp_d(&y, 0) == PSTM_LT) {
		if ((err = pstm_add(&y, modulus, &y)) != PS_SUCCESS) { goto done; }
	}
	/* T1 = 2T1 */
	if ((err = pstm_add(&t1, &t1, &t1)) != PS_SUCCESS) { goto done; }
	if (pstm_cmp(&t1, modulus) != PSTM_LT) {
		if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS) { goto done; }
	}
	/* T1 = Y + T1 */
	if ((err = pstm_add(&t1, &y, &t1)) != PS_SUCCESS) { goto done; }
	if (pstm_cmp(&t1, modulus) != PSTM_LT) {
		if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS) { goto done; }
	}
	/* X = X - T2 */
	if ((err = pstm_sub(&x, &t2, &x)) != PS_SUCCESS) { goto done; }
	if (pstm_cmp_d(&x, 0) == PSTM_LT) {
		if ((err = pstm_add(&x, modulus, &x)) != PS_SUCCESS) { goto done; }
	}
	/* T2 = 2T2 */
	if ((err = pstm_add(&t2, &t2, &t2)) != PS_SUCCESS) { goto done; }
	if (pstm_cmp(&t2, modulus) != PSTM_LT) {
		if ((err = pstm_sub(&t2, modulus, &t2)) != PS_SUCCESS) { goto done; }
	}
	/* T2 = X + T2 */
	if ((err = pstm_add(&t2, &x, &t2)) != PS_SUCCESS) { goto done; }
	if (pstm_cmp(&t2, modulus) != PSTM_LT) {
		if ((err = pstm_sub(&t2, modulus, &t2)) != PS_SUCCESS) { goto done; }
	}

	/* if Z' != 1 */
	if (&Q->z != NULL) {
		/* Z = Z * Z' */
		if ((err = pstm_mul_comba(pool, &z, &Q->z, &z, paD, paDlen))
				!= PS_SUCCESS) {
			goto done;
		}
		if ((err = pstm_montgomery_reduce(pool, &z, modulus, *mp, paD, paDlen))
				!= PS_SUCCESS) {
			goto done;
		}
	}

	/* Z = Z * X */
	if ((err = pstm_mul_comba(pool, &z, &x, &z, paD, paDlen)) != PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &z, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}

	/* T1 = T1 * X  */
	if ((err = pstm_mul_comba(pool, &t1, &x, &t1, paD, paDlen)) != PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	/* X = X * X */
	if ((err = pstm_sqr_comba(pool, &x, &x, paD, paDlen)) != PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &x, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	/* T2 = T2 * x */
	if ((err = pstm_mul_comba(pool, &t2, &x, &t2, paD, paDlen)) != PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &t2, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	/* T1 = T1 * X  */
	if ((err = pstm_mul_comba(pool, &t1, &x, &t1, paD, paDlen)) != PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
 
	/* X = Y*Y */
	if ((err = pstm_sqr_comba(pool, &y, &x, paD, paDlen)) != PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &x, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	/* X = X - T2 */
	if ((err = pstm_sub(&x, &t2, &x)) != PS_SUCCESS) { goto done; }
	if (pstm_cmp_d(&x, 0) == PSTM_LT) {
		if ((err = pstm_add(&x, modulus, &x)) != PS_SUCCESS) { goto done; }
	}

	/* T2 = T2 - X */
	if ((err = pstm_sub(&t2, &x, &t2)) != PS_SUCCESS) { goto done; }
	if (pstm_cmp_d(&t2, 0) == PSTM_LT) {
		if ((err = pstm_add(&t2, modulus, &t2)) != PS_SUCCESS) { goto done; }
	} 
	/* T2 = T2 - X */
	if ((err = pstm_sub(&t2, &x, &t2)) != PS_SUCCESS) { goto done; }
	if (pstm_cmp_d(&t2, 0) == PSTM_LT) {
		if ((err = pstm_add(&t2, modulus, &t2)) != PS_SUCCESS) { goto done; }
	}
	/* T2 = T2 * Y */
	if ((err = pstm_mul_comba(pool, &t2, &y, &t2, paD, paDlen)) != PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &t2, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	/* Y = T2 - T1 */
	if ((err = pstm_sub(&t2, &t1, &y)) != PS_SUCCESS) { goto done; }
	if (pstm_cmp_d(&y, 0) == PSTM_LT) {
		if ((err = pstm_add(&y, modulus, &y)) != PS_SUCCESS) { goto done; }
	}
	/* Y = Y/2 */
	if (pstm_isodd(&y)) {
		if ((err = pstm_add(&y, modulus, &y)) != PS_SUCCESS) { goto done; }
	}
	if ((err = pstm_div_2(&y, &y)) != PS_SUCCESS) { goto done; }

	if ((err = pstm_copy(&x, &R->x)) != PS_SUCCESS) { goto done; }
	if ((err = pstm_copy(&y, &R->y)) != PS_SUCCESS) { goto done; }
	if ((err = pstm_copy(&z, &R->z)) != PS_SUCCESS) { goto done; }

	err = PS_SUCCESS;
	
done:
	pstm_clear(&z);		
ERR_Y:
	pstm_clear(&y);	
ERR_X:
	pstm_clear(&x);
ERR_T2:
	pstm_clear(&t2);
ERR_T1:
	pstm_clear(&t1);
	if (paD) psFree(paD);
	return err;
}


/******************************************************************************/
/*
	Double an ECC point
	@param P   The point to double
	@param R   [out] The destination of the double
	@param modulus  The modulus of the field the ECC curve is in
	@param mp       The "b" value from montgomery_setup()
	@param A        The "A" of the field the ECC curve is in
	@return PS_SUCCESS on success
*/
static int32 eccProjectiveDblPoint(psPool_t *pool, psEccPoint_t *P,
             psEccPoint_t *R, pstm_int *modulus, pstm_digit *mp, pstm_int *A)
{
	pstm_int	t1, t2;
	pstm_digit *paD;
	uint32		paDlen;
	int32		err, initSize;


	if (P != R) {
		if (pstm_copy(&P->x, &R->x) < 0) { return PS_MEM_FAIL; }
		if (pstm_copy(&P->y, &R->y) < 0) { return PS_MEM_FAIL; }
		if (pstm_copy(&P->z, &R->z) < 0) { return PS_MEM_FAIL; }
	}
	
	initSize = R->x.used;
	if (R->y.used > initSize) { initSize = R->y.used; }
	if (R->z.used > initSize) { initSize = R->z.used; }
	
	if (pstm_init_size(pool, &t1, (initSize * 2) + 1) < 0) {
		return PS_MEM_FAIL;
	}
	if (pstm_init_size(pool, &t2, (initSize * 2) + 1) < 0) {
		pstm_clear(&t1);
		return PS_MEM_FAIL;
	}
	
/*
	Pre-allocated digit.  Used for mul, sqr, AND reduce
	TODO: haven't fully explored max possible paDlen
*/
	paDlen = (modulus->used*2+1) * sizeof(pstm_digit);
	if ((paD = psMalloc(pool, paDlen)) == NULL) {
		err = PS_MEM_FAIL;
		goto done;
	}
	
	/* t1 = Z * Z */
	if ((err = pstm_sqr_comba(pool, &R->z, &t1, paD, paDlen)) != PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &t1, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	/* Z = Y * Z */
	if ((err = pstm_mul_comba(pool, &R->z, &R->y, &R->z, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &R->z, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	/* Z = 2Z */
	if ((err = pstm_add(&R->z, &R->z, &R->z)) != PS_SUCCESS) { goto done; }
	if (pstm_cmp(&R->z, modulus) != PSTM_LT) {
		if ((err = pstm_sub(&R->z, modulus, &R->z)) != PS_SUCCESS) {
			goto done;
		}
	}

    // compute into T1  M=3(X+Z^2)(X-Z^2) 
    if (A == NULL)
    {
        /* T2 = X - T1 */
        if ((err = pstm_sub(&R->x, &t1, &t2)) != PS_SUCCESS) { goto done; }
        if (pstm_cmp_d(&t2, 0) == PSTM_LT) {
            if ((err = pstm_add(&t2, modulus, &t2)) != PS_SUCCESS) { goto done; }
        }
        /* T1 = X + T1 */
        if ((err = pstm_add(&t1, &R->x, &t1)) != PS_SUCCESS) { goto done; }
        if (pstm_cmp(&t1, modulus) != PSTM_LT) {
            if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS) { goto done; }
        }
        /* T2 = T1 * T2 */
        if ((err = pstm_mul_comba(pool, &t1, &t2, &t2, paD, paDlen)) != PS_SUCCESS){
            goto done;
        }
        if ((err = pstm_montgomery_reduce(pool, &t2, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
            goto done;
        }
        /* T1 = 2T2 */
        if ((err = pstm_add(&t2, &t2, &t1)) != PS_SUCCESS) { goto done; }
        if (pstm_cmp(&t1, modulus) != PSTM_LT) {
            if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS) { goto done; }
        }
        /* T1 = T1 + T2 */
        if ((err = pstm_add(&t1, &t2, &t1)) != PS_SUCCESS) { goto done; }
        if (pstm_cmp(&t1, modulus) != PSTM_LT) {
            if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS) { goto done; }
        } 
    }
    else
    // compute into T1  M=3X^2 + A Z^4
    {
        pstm_int t3, t4;

        if (pstm_init_size(pool, &t3, (initSize * 2) + 1) < 0) {
            return PS_MEM_FAIL;
        }
        if (pstm_init_size(pool, &t4, (initSize * 2) + 1) < 0) {
            pstm_clear(&t3);
            return PS_MEM_FAIL;
        }

        /* T3 = X * X */
        if ((err = pstm_sqr_comba(pool, &R->x, &t3, paD, paDlen)) != PS_SUCCESS) {
            goto done;
        }
        if ((err = pstm_montgomery_reduce(pool, &t3, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
            goto done;
        }

        /* T4 = 2T3 */
        if ((err = pstm_add(&t3, &t3, &t4)) != PS_SUCCESS) { goto done; }
        if (pstm_cmp(&t4, modulus) != PSTM_LT) {
            if ((err = pstm_sub(&t4, modulus, &t4)) != PS_SUCCESS) { goto done; }
        }

        /* T3 = T3 + T4 */
        if ((err = pstm_add(&t3, &t4, &t3)) != PS_SUCCESS) { goto done; }
        if (pstm_cmp(&t3, modulus) != PSTM_LT) {
            if ((err = pstm_sub(&t3, modulus, &t3)) != PS_SUCCESS) { goto done; }
        } 

        /* T4 = T1 * T1 */
        if ((err = pstm_sqr_comba(pool, &t1, &t4, paD, paDlen)) != PS_SUCCESS) {
            goto done;
        }
        if ((err = pstm_mod(pool, &t4, modulus, &t4)) != PS_SUCCESS) { goto done; }

        /* T4 = T4 * A */
        if ((err = pstm_mul_comba(pool, &t4, A, &t4, paD, paDlen)) != PS_SUCCESS){
            goto done;
        }

        if ((err = pstm_montgomery_reduce(pool, &t4, modulus, *mp, paD, paDlen))
       		!= PS_SUCCESS) {
            goto done;
        }

        /* T1 = T3 + T4 */
         if ((err = pstm_add(&t3, &t4, &t1)) != PS_SUCCESS) { goto done; }
        if (pstm_cmp(&t1, modulus) != PSTM_LT) {
            if ((err = pstm_sub(&t1, modulus, &t1)) != PS_SUCCESS) { goto done; }
        } 

        pstm_clear_multi(&t3, &t4, NULL, NULL, NULL, NULL, NULL, NULL);
    }

	/* Y = 2Y */
	if ((err = pstm_add(&R->y, &R->y, &R->y)) != PS_SUCCESS) { goto done; }
	if (pstm_cmp(&R->y, modulus) != PSTM_LT) {
		if ((err = pstm_sub(&R->y, modulus, &R->y)) != PS_SUCCESS) { goto done;}
	}
	/* Y = Y * Y */
	if ((err = pstm_sqr_comba(pool, &R->y, &R->y, paD, paDlen)) != PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &R->y, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	/* T2 = Y * Y */
	if ((err = pstm_sqr_comba(pool, &R->y, &t2, paD, paDlen)) != PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &t2, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	/* T2 = T2/2 */
	if (pstm_isodd(&t2)) {
		if ((err = pstm_add(&t2, modulus, &t2)) != PS_SUCCESS) { goto done; }
	}
	if ((err = pstm_div_2(&t2, &t2)) != PS_SUCCESS) { goto done; }
	/* Y = Y * X */
	if ((err = pstm_mul_comba(pool, &R->y, &R->x, &R->y, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &R->y, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}

	/* X  = T1 * T1 */
	if ((err = pstm_sqr_comba(pool, &t1, &R->x, paD, paDlen)) != PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &R->x, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	/* X = X - Y */
	if ((err = pstm_sub(&R->x, &R->y, &R->x)) != PS_SUCCESS) { goto done; }
	if (pstm_cmp_d(&R->x, 0) == PSTM_LT) {
		if ((err = pstm_add(&R->x, modulus, &R->x)) != PS_SUCCESS) { goto done;}
	}
	/* X = X - Y */
	if ((err = pstm_sub(&R->x, &R->y, &R->x)) != PS_SUCCESS) { goto done; }
	if (pstm_cmp_d(&R->x, 0) == PSTM_LT) {
		if ((err = pstm_add(&R->x, modulus, &R->x)) != PS_SUCCESS) { goto done;}
	}

	/* Y = Y - X */     
	if ((err = pstm_sub(&R->y, &R->x, &R->y)) != PS_SUCCESS) { goto done; }
	if (pstm_cmp_d(&R->y, 0) == PSTM_LT) {
		if ((err = pstm_add(&R->y, modulus, &R->y)) != PS_SUCCESS) { goto done;}
	}
	/* Y = Y * T1 */
	if ((err = pstm_mul_comba(pool, &R->y, &t1, &R->y, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &R->y, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	/* Y = Y - T2 */
	if ((err = pstm_sub(&R->y, &t2, &R->y)) != PS_SUCCESS) { goto done; }
	if (pstm_cmp_d(&R->y, 0) == PSTM_LT) {
		if ((err = pstm_add(&R->y, modulus, &R->y)) != PS_SUCCESS) { goto done;}
	}
 
	err = PS_SUCCESS;
done:
	pstm_clear_multi(&t1, &t2, NULL, NULL, NULL, NULL, NULL, NULL);
	if (paD) psFree(paD);
	return err;
}

static int32 get_digit_count(void *a)
{
	pstm_int *A;
	A = a;
	return A->used;
}

static unsigned long get_digit(void *a, int32 n)
{
	pstm_int *A;
	A = a;
	return (n >= A->used || n < 0) ? 0 : A->dp[n];
}

/**
  Free an ECC key from memory
  @param key   The key you wish to free
*/
void psEccFreeKey(psEccKey_t **key)
{
	psEccKey_t *lkey = *key;
	
	if (lkey == NULL) {
		return;
	}
	pstm_clear_multi(&lkey->pubkey.x, &lkey->pubkey.y, &lkey->pubkey.z,
		&lkey->k, NULL, NULL, NULL, NULL);
	psFree(lkey);
	*key = NULL;
}

/******************************************************************************/
/*
	Allocate a new ECC point
	@return A newly allocated point or NULL on error 
*/
static psEccPoint_t *eccNewPoint(psPool_t *pool, short size)
{
	psEccPoint_t	*p = NULL;
   
	p = psMalloc(pool, sizeof(*p));
	if (p == NULL) {
		return NULL;
	}
	if (size == 0) {
		if (pstm_init(pool, &p->x) != PSTM_OKAY) {
			return NULL;
		}
		if (pstm_init(pool, &p->y) != PSTM_OKAY) {
			pstm_clear(&p->x);
			return NULL;
		}
		if (pstm_init(pool, &p->z) != PSTM_OKAY) {
			pstm_clear(&p->x);
			pstm_clear(&p->y);
			return NULL;
		}
	} else {
		if (pstm_init_size(pool, &p->x, size) != PSTM_OKAY) {
			return NULL;
		}
		if (pstm_init_size(pool, &p->y, size) != PSTM_OKAY) {
			pstm_clear(&p->x);
			return NULL;
		}
		if (pstm_init_size(pool, &p->z, size) != PSTM_OKAY) {
			pstm_clear(&p->x);
			pstm_clear(&p->y);
			return NULL;
		}
	}
	
	return p;
}

/** Free an ECC point from memory
  @param p   The point to free
*/
static void eccFreePoint(psEccPoint_t *p)
{
	/* prevents free'ing null arguments */
	if (p != NULL) {
		pstm_clear(&p->x); 
		pstm_clear(&p->y);
		pstm_clear(&p->z);
		psFree(p);
	}
}

/**
 Map a projective jacbobian point back to affine space
 @param P        [in/out] The point to map
 @param modulus  The modulus of the field the ECC curve is in
 @param mp       The "b" value from montgomery_setup()
 @return PS_SUCCESS on success
 */
static int32 eccMap(psPool_t *pool, psEccPoint_t *P, pstm_int *modulus,
					pstm_digit *mp)
{
	pstm_int	t1, t2;
	pstm_digit	*paD;
	int32		err;
	uint32		paDlen;
	
	if (pstm_init_size(pool, &t1, P->x.alloc) < 0) {
		return PS_MEM_FAIL;
	}
	if (pstm_init_size(pool, &t2, P->x.alloc) < 0) {
		pstm_clear(&t1);
		return PS_MEM_FAIL;
	}
	
/*
	Pre-allocated digit.  Used for mul, sqr, AND reduce
*/
	paDlen = (modulus->used*2+1) * sizeof(pstm_digit);
	if ((paD = psMalloc(pool, paDlen)) == NULL) {
		err = PS_MEM_FAIL;
		goto done;
	}
	
	/* first map z back to normal */
	if ((err = pstm_montgomery_reduce(pool, &P->z, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	
	/* get 1/z */
	if ((err = pstm_invmod(pool, &P->z, modulus, &t1)) != PS_SUCCESS) {
		goto done;
	}
	
	/* get 1/z^2 and 1/z^3 */
	if ((err = pstm_sqr_comba(pool, &t1, &t2, paD, paDlen)) != PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_mod(pool, &t2, modulus, &t2)) != PS_SUCCESS) { goto done; }
	if ((err = pstm_mul_comba(pool, &t1, &t2, &t1, paD, paDlen)) != PS_SUCCESS){
		goto done;
	}
	if ((err = pstm_mod(pool, &t1, modulus, &t1)) != PS_SUCCESS) { goto done; }
	
	/* multiply against x/y */
	if ((err = pstm_mul_comba(pool, &P->x, &t2, &P->x, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &P->x, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_mul_comba(pool, &P->y, &t1, &P->y, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	if ((err = pstm_montgomery_reduce(pool, &P->y, modulus, *mp, paD, paDlen))
			!= PS_SUCCESS) {
		goto done;
	}
	pstm_set(&P->z, 1);	
	err = PS_SUCCESS;
done:
	pstm_clear_multi(&t1, &t2, NULL, NULL, NULL, NULL, NULL, NULL);
	if (paD) psFree(paD);
	return err;
}

/******************************************************************************/
/*
	Verify an ECC signature

	Return code 0 if successful
	stat:  1 if valid, -1 if invalid
 */
int32 psEcDsaValidateSignature(psPool_t *pool, psEccKey_t *myPubKey,
			unsigned char *signature, int32 sigLen,	unsigned char *hash,
			int32 hashLen, int32 *stat, void *pkiData)
{
	psEccKey_t		*key;
	psEccPoint_t	*mG, *mQ;
	pstm_digit		mp;
	pstm_int		v, w, u1, u2, e, p, m, r, s;
	unsigned char	*buf, *end;
	int32			err, radlen;
	uint32			len;
	pstm_int        *A = NULL;

	/* default to invalid signature */
	*stat = -1; 

	key = myPubKey;
	
	buf = signature;
	end = buf + sigLen;
	
	if ((err = getAsnSequence(&buf, (int32)(end - buf), &len)) < 0) {
		psTraceCrypto("ECDSA subject signature parse failure 1\n");
		return err;
	}
	if ((err = getAsnBig(pool, &buf, (int32)(end - buf), &r)) < 0) {
		psTraceCrypto("ECDSA subject signature parse failure 2\n");
		return err;
	}
	if ((err = getAsnBig(pool, &buf, (int32)(end - buf), &s)) < 0) {
		psTraceCrypto("ECDSA subject signature parse failure 3\n");
		pstm_clear(&r);
		return err;
	}


	/* allocate ints */
	radlen = key->dp->size * 2;
	if (pstm_init_for_read_unsigned_bin(pool, &p, key->dp->size) < 0) {
		pstm_clear(&s);
		pstm_clear(&r);
		return PS_MEM_FAIL;
	}
	err = PS_MEM_FAIL;
	if (pstm_init_for_read_unsigned_bin(pool, &m, key->dp->size) < 0) {
		goto LBL_P;
	}
	if (pstm_init_size(pool, &v, key->pubkey.x.alloc) < 0) {
		goto LBL_M;
	}
	if (pstm_init_size(pool, &w, s.alloc) < 0) {
		goto LBL_V;
	}
	/* Shouldn't have signed more data than the key length.  Truncate if so */
	if (hashLen > myPubKey->dp->size) {
		hashLen = myPubKey->dp->size;
	}
	if (pstm_init_for_read_unsigned_bin(pool, &e, hashLen) < 0) {
		goto LBL_W;
	}
	if (pstm_init_size(pool, &u1, e.alloc + w.alloc) < 0) {
		goto LBL_E;
	}
	if (pstm_init_size(pool, &u2, r.alloc + w.alloc) < 0) {
		goto LBL_U1;
	}
		
	/* allocate points */
	if ((mG = eccNewPoint(pool, key->pubkey.x.alloc * 2)) == NULL) {
		goto LBL_U2;
	}
	if ((mQ = eccNewPoint(pool, key->pubkey.x.alloc * 2)) == NULL) {
		goto LBL_MG;
	}
	
	/* get the order */
	if ((err = pstm_read_radix(pool, &p, (char *)key->dp->order, radlen, 16))
			!= PS_SUCCESS) {
		goto error;
	}
	
	/* get the modulus */
	if ((err = pstm_read_radix(pool, &m, (char *)key->dp->prime, radlen, 16))
			!= PS_SUCCESS) {
		goto error;
	}
	
	/* check for zero */
	if (pstm_iszero(&r) || pstm_iszero(&s) || pstm_cmp(&r, &p) != PSTM_LT ||
			pstm_cmp(&s, &p) != PSTM_LT) {
		err = PS_PARSE_FAIL;
		goto error;
	}
	
	/* read hash */
	if ((err = pstm_read_unsigned_bin(&e, hash, hashLen)) != PS_SUCCESS) {
		goto error;
	}
	
	/*  w  = s^-1 mod n */
	if ((err = pstm_invmod(pool, &s, &p, &w)) != PS_SUCCESS) {
		goto error;
	}
	
	/* u1 = ew */
	if ((err = pstm_mulmod(pool, &e, &w, &p, &u1)) != PS_SUCCESS) {
		goto error;
	}
	
	/* u2 = rw */
	if ((err = pstm_mulmod(pool, &r, &w, &p, &u2)) != PS_SUCCESS) {
		goto error;
	}
	
	/* find mG and mQ */
	if ((err = pstm_read_radix(pool, &mG->x, (char *)key->dp->Gx, radlen, 16))
			!= PS_SUCCESS) {
		goto error;
	}
	if ((err = pstm_read_radix(pool, &mG->y, (char *)key->dp->Gy, radlen, 16))
			!= PS_SUCCESS) {
		goto error;
	}
	pstm_set(&mG->z, 1);
	
	if ((err = pstm_copy(&key->pubkey.x, &mQ->x)) != PS_SUCCESS) {
		goto error;
	}
	if ((err = pstm_copy(&key->pubkey.y, &mQ->y)) != PS_SUCCESS) {
		goto error;
	}
	if ((err = pstm_copy(&key->pubkey.z, &mQ->z)) != PS_SUCCESS) {
		goto error;
	}
	
    if (key->dp->isOptimized == 0)
    {
        if ((A = psMalloc(pool, sizeof(pstm_int))) == NULL) {
            goto error;
        }

        if (pstm_init_for_read_unsigned_bin(pool, A, key->dp->size) < 0) {
            goto error;
        }
        
        if ((err = pstm_read_radix(pool, A, (char *)key->dp->A,
                                   key->dp->size * 2, 16))
            != PS_SUCCESS) {
            goto error;
        }
    }

	/* compute u1*mG + u2*mQ = mG */
	if ((err = eccMulmod(pool, &u1, mG, mG, &m, 0, A)) != PS_SUCCESS) {
		goto error;
	}
	if ((err = eccMulmod(pool, &u2, mQ, mQ, &m, 0, A)) != PS_SUCCESS) {
		goto error;
	}
		
	/* find the montgomery mp */
	if ((err = pstm_montgomery_setup(&m, &mp)) != PS_SUCCESS) {
		goto error;
	}
		
	/* add them */
	if ((err = eccProjectiveAddPoint(pool, mQ, mG, mG, &m, &mp, A)) != PS_SUCCESS) {
		goto error;
	}
		
	/* reduce */
	if ((err = eccMap(pool, mG, &m, &mp)) != PS_SUCCESS) {
		goto error;
	}
		
	/* v = X_x1 mod n */
	if ((err = pstm_mod(pool, &mG->x, &p, &v)) != PS_SUCCESS) {
		goto error;
	}
	
	/* does v == r */
	if (pstm_cmp(&v, &r) == PSTM_EQ) {
		*stat = 1;
	}
	
	/* clear up and return */
	err = PS_SUCCESS;
	
error:
    if (A) {
        pstm_clear(A);
        psFree(A);
    }

	eccFreePoint(mQ);
LBL_MG:
	eccFreePoint(mG);
LBL_U2:
	pstm_clear(&u2);	
LBL_U1:
	pstm_clear(&u1);
LBL_E:
	pstm_clear(&e);	
LBL_W:
	pstm_clear(&w);
LBL_V:
	pstm_clear(&v);
LBL_M:
	pstm_clear(&m);
LBL_P:
	pstm_clear(&p);
	pstm_clear(&s);
	pstm_clear(&r);
	return err;
}

/**
 Sign a message digest
 @param in        The message digest to sign
 @param inlen     The length of the digest
 @param out       [out] The destination for the signature
 @param outlen    [in/out] The max size and resulting size of the signature
 @param prng      An active PRNG state
 @param wprng     The index of the PRNG you wish to use
 @param key       A private ECC key
 @return PS_SUCCESS if successful
 */
int32 psEccSignHash(psPool_t *pool, unsigned char *in, int32 inlen, 
				  unsigned char *c, int32 outlen, psEccKey_t *privKey,
				  int32 *bytesWritten, int32 includeSize, void *eccData)
{
	psEccKey_t		*pubKey;
	pstm_int		r, s;
	pstm_int		e, p;
	int32			radlen;
	int32			err, sigLen, rLen, sLen;
	
	err = 0;
	/* is this a private key? */
	if (privKey->type != PRIVKEY_TYPE) {
		return PS_ARG_FAIL;
	}

	/* Can't sign more data than the key length.  Truncate if so */
	if (inlen > privKey->dp->size) {
		inlen = privKey->dp->size;
	}
	err = PS_MEM_FAIL;

	radlen = privKey->dp->size * 2;
	if (pstm_init_for_read_unsigned_bin(pool, &p, privKey->dp->size) < 0) {
		return PS_MEM_FAIL;
	}
	if (pstm_init_for_read_unsigned_bin(pool, &e, inlen) < 0) {
		goto LBL_P;
	}
	if (pstm_init_size(pool, &r, p.alloc) < 0) {
		goto LBL_E;
	}
	if (pstm_init_size(pool, &s, p.alloc) < 0) {
		goto LBL_R;
	}
	
	if ((err = pstm_read_radix(pool, &p, (char *)privKey->dp->order, radlen,
			16)) != PS_SUCCESS) {
		goto errnokey;
	}
	if ((err = pstm_read_unsigned_bin(&e, in, inlen)) != PS_SUCCESS) {
		goto errnokey;
	}
	
	/* make up a key and export the public copy */

	for(;;) {
		if ((err = psEccMakeKeyEx(pool, &pubKey, privKey->dp, NULL))
				!= PS_SUCCESS) {
			goto errnokey;
		}
		
		/* find r = x1 mod n */
		if ((err = pstm_mod(pool, &pubKey->pubkey.x, &p, &r)) != PS_SUCCESS) {
			goto error;
		}
		
		if (pstm_iszero(&r) == PS_TRUE) {
			psEccFreeKey(&pubKey);
		} else { 
			/* find s = (e + xr)/k */
			if ((err = pstm_invmod(pool, &pubKey->k, &p, &pubKey->k)) !=
					PS_SUCCESS) {
				goto error; /* k = 1/k */
			}
			if ((err = pstm_mulmod(pool, &privKey->k, &r, &p, &s))
					!= PS_SUCCESS) {
				goto error; /* s = xr */
			}	
			if ((err = pstm_add(&e, &s, &s)) != PS_SUCCESS) {
				goto error;  /* s = e +  xr */
			}
			if ((err = pstm_mod(pool, &s, &p, &s)) != PS_SUCCESS) {
				goto error; /* s = e +  xr */
			}
			if ((err = pstm_mulmod(pool, &s, &pubKey->k, &p, &s))
					!= PS_SUCCESS) {
				goto error; /* s = (e + xr)/k */
			}
			psEccFreeKey(&pubKey);
			
			rLen = pstm_unsigned_bin_size(&r);
			sLen = pstm_unsigned_bin_size(&s);
			
			if (rLen == privKey->dp->size && sLen == privKey->dp->size) {
				if (pstm_iszero(&s) == PS_FALSE) {
					break;
				}
			}
		}
	}
	sigLen = 6 + rLen + sLen; 
	
	/* Handle lengths longer than 128.. but still only handling up to 256 */
	if (sigLen - 3 >= 128) {
		sigLen++;
	}
	
	/* TLS uses a two byte length specifier.  Others sometimes do not */
	if (includeSize) {
		if (sigLen + 2 > outlen) {
			err = -1;
			goto errnokey;
		}
	
		*c = sigLen >> 8 & 0xFF; c++;
		*c = sigLen & 0xFF; c++;
	} else {
		if (sigLen > outlen) {
			err = -1;
			goto errnokey;
		}
	}

	*c = ASN_CONSTRUCTED | ASN_SEQUENCE; c++;

	*bytesWritten = 0;
	if (sigLen - 3 >= 128) {
		*c = 0x81; c++; /* high bit to indicate 'long' and low for byte count */
		*c = (sigLen & 0xFF) - 3; c++;
		*bytesWritten = 1;
	} else {
		*c = (sigLen & 0xFF) - 2; c++;
	}
	*c = ASN_INTEGER; c++;
	*c = rLen & 0xFF; c++;
	if (includeSize) {
		*bytesWritten += 6;
	} else {
		*bytesWritten += 4;
	}
	
	if ((err = pstm_to_unsigned_bin(pool, &r, c)) != PSTM_OKAY) {
		goto errnokey;
	}
	c += rLen; 
	*bytesWritten += rLen;
	*c = ASN_INTEGER; c++;
	*c = sLen & 0xFF; c++;
	if ((err = pstm_to_unsigned_bin(pool, &s, c)) != PSTM_OKAY) {
		goto error;
	}
	c += sLen;
	*bytesWritten += sLen + 2;
	
	err = PS_SUCCESS;
	goto errnokey;
	
error:
	psEccFreeKey(&pubKey);
errnokey:
	pstm_clear(&s);
LBL_R:
	pstm_clear(&r);
LBL_E:
	pstm_clear(&e);
LBL_P:
	pstm_clear(&p);
	return err;   
}

/* c = a + b */
static int32 pstm_add_d(psPool_t *pool, pstm_int *a, pstm_digit b, pstm_int *c)
{
	pstm_int	tmp;
	int32		res;
	
	if (pstm_init_size(pool, &tmp, sizeof(pstm_digit)) != PSTM_OKAY) {
		return PS_MEM_FAIL;
	}
	pstm_set(&tmp, b);
	res = pstm_add(a,&tmp,c);
	pstm_clear(&tmp);
	return res;
}

/* chars used in radix conversions */
const char *pstm_s_rmap = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";


/* TODO: just copied over from tfm and renamed functions so far */
static int32 pstm_read_radix(psPool_t *pool, pstm_int *a,
				char *str, int32 strlen, int32 radix)
{
	int32	y, neg;
	char    ch;

	/* make sure the radix is ok */
	if (radix < 2 || radix > 64) {
		return PS_ARG_FAIL;
	}

	if (strlen == 0) {
		_psTrace("TODO:  FIX MY CALLER TO HAVE A STRLEN!!!!\n");
	}
	
	/* if the leading digit is a minus set the sign to negative. */
	if (*str == '-') {
		++str; strlen--;
		neg = PSTM_NEG;
	} else {
		neg = PSTM_ZPOS;
	}

	/* set the integer to the default of zero */
	pstm_zero(a);

	/* process each digit of the string */
	while (strlen > 0) {
    /* if the radix < 36 the conversion is case insensitive
     * this allows numbers like 1AB and 1ab to represent the same  value
     * [e.g. in hex]
     */
		ch = (char) ((radix < 36) ? toupper (*str) : *str);
		for (y = 0; y < 64; y++) {
			if (ch == pstm_s_rmap[y]) {
				break;
			}
		}

    /* if the char was found in the map
     * and is less than the given radix add it
     * to the number, otherwise exit the loop.
     */
		if (y < radix) {
			pstm_mul_d (a, (pstm_digit) radix, a);
			pstm_add_d (pool, a, (pstm_digit) y, a);
		} else {
			break;
		}
		++str; strlen--;
	}

	/* set the sign only if a != 0 */
	if (pstm_iszero(a) != PS_TRUE) {
		a->sign = (int16)neg;
	}
	return PS_SUCCESS;
}



#endif /* USE_NATIVE_ECC */
#endif /* USE_ECC */



