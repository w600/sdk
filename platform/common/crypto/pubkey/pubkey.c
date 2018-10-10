/*
 *	pubkey.c
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
#if 0
/******************************************************************************/
/*
	Open (initialize) the Crypto module
	This function is in this file simply because there is no C file directly
	under the crypto directory
    The config param should always be passed as:
        PSCRYPTO_CONFIG
*/
static char g_config[32] = "N";

int32 psCryptoOpen(char *config)
{
	if (*g_config == 'Y') {
        return PS_SUCCESS; /* Function has been called previously */
    }
	strncpy(g_config, PSCRYPTO_CONFIG, sizeof(g_config) - 1);
	if (strncmp(g_config, config, sizeof(g_config) - 1) != 0) {
		psErrorStr( "Crypto config mismatch.\n" \
			"Library: " PSCRYPTO_CONFIG\
			"\nCurrent: %s\n", config);
		return -1;
	}
    if (psCoreOpen(PSCORE_CONFIG) < 0) {
        psError("pscore open failure\n");
        return PS_FAILURE;
    }
	return 0;
}

void psCryptoClose(void)
{
	psCoreClose();
}
#endif

/******************************************************************************/
/*
	Allocate a new psPubKey_t and memset empty 
*/
psPubKey_t * psNewPubKey(psPool_t *pool) {

	psPubKey_t *ret;

	ret = psMalloc(pool, sizeof(psPubKey_t));

	if (ret == NULL) {
		psError("Memory allocation error in psNewPubKey\n");
		return NULL;
	}
	memset(ret, 0x0, sizeof(psPubKey_t));
	ret->key = psMalloc(pool, sizeof(pubKeyUnion_t));
	if (ret->key == NULL) {
		psFree(ret);
		psError("Memory allocation error in psNewPubKey\n");
		return NULL;
	}
	memset(ret->key, 0x0, sizeof(pubKeyUnion_t));
	return ret;
}

/******************************************************************************/
/*
	
*/
void psFreePubKey(psPubKey_t *key)
{
	if (key == NULL) {
		return;
	}
	if (key->type == PS_RSA) {
#ifdef USE_RSA
		psRsaFreeKey((psRsaKey_t*)key->key);
#else
		psFree(key->key);
#endif		

#ifdef USE_ECC
	} else if (key->type == PS_ECC) {
#ifdef USE_NATIVE_ECC
		if (key->key->ecc.pubkey.x.dp) {
			pstm_clear(&(key->key->ecc.pubkey.x));
		}
		if (key->key->ecc.pubkey.y.dp) {
			pstm_clear(&(key->key->ecc.pubkey.y));
		}
		if (key->key->ecc.pubkey.z.dp) {
			pstm_clear(&(key->key->ecc.pubkey.z));
		}
		if (key->key->ecc.k.dp) {
			pstm_clear(&(key->key->ecc.k));
		}
		psFree(key->key);
#endif
#ifdef USE_PKCS11_ECC
		psEccKey_t	*ecc;
		ecc = &key->key->ecc;
		psEccFreeKey(&ecc);
#endif
#endif /* USE_ECC */	
	} else {
/*
		If type not found, assume an empty key type
*/
		psFree(key->key);
	}
	psFree(key);
}

/******************************************************************************/
