/*
 *	asn1.h
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

#ifndef _h_PS_ASN1
#define _h_PS_ASN1
#include "cryptoConfig.h"

/******************************************************************************/
/******************************************************************************/
/*
	8 bit bit masks for ASN.1 tag field
*/
#define ASN_PRIMITIVE			0x0
#define ASN_CONSTRUCTED			0x20

#define ASN_UNIVERSAL			0x0
#define ASN_APPLICATION			0x40
#define ASN_CONTEXT_SPECIFIC	0x80
#define ASN_PRIVATE				0xC0

/*
	ASN.1 primitive data types
*/
enum {
	ASN_BOOLEAN = 1,
	ASN_INTEGER,
	ASN_BIT_STRING,
	ASN_OCTET_STRING,
	ASN_NULL,
	ASN_OID,
	ASN_UTF8STRING = 12,
	ASN_SEQUENCE = 16,
	ASN_SET,
	ASN_PRINTABLESTRING = 19,
	ASN_T61STRING,
	ASN_IA5STRING = 22,
	ASN_UTCTIME,
	ASN_GENERALIZEDTIME,
	ASN_GENERAL_STRING = 27,
	ASN_BMPSTRING = 30
};

#define ASN_UNKNOWN_LEN	876

extern s32 getAsnLength(unsigned char **p, u32 size, u32 *valLen);
extern s32 getAsnBig(psPool_t *pool, unsigned char **pp, u32 len,
				pstm_int *big);
extern s32 getAsnSequence(unsigned char **pp, u32 len, u32 *seqlen);
extern s32 getAsnSet(unsigned char **pp, u32 len, u32 *setlen);
extern s32 getAsnInteger(unsigned char **pp, u32 len, s32 *val);

extern s32 getAsnAlgorithmIdentifier(unsigned char **pp, u32 len,
				s32 *oi, s32 *paramLen);
extern s32 getAsnOID(unsigned char **pp, u32 len, s32 *oi,
				s32 checkForParams, s32 *paramLen);
extern s32 getAsnConstructedOctetString(psPool_t *pool, unsigned char **pp,
				u32 len, unsigned char **outString, s32 *outStringLen);
#ifdef USE_RSA				
extern s32 getAsnRsaPubKey(psPool_t *pool, unsigned char **pp, u32 len, 
				psRsaKey_t *pubKey);
#endif /* USE_RSA */							
/******************************************************************************/

#endif /* _h_PS_ASN1 */

