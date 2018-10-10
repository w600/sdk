/*
 *	psk.c
 *	Release $Name: MATRIXSSL-3-6-1-OPEN $
 *
 *	Pre-Shared Key cipher suite support
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

#ifdef USE_PSK_CIPHER_SUITE

/******************************************************************************/
/*
	Add a pre-shared key and ID to the static table in the first NULL spot
*/
int32 matrixSslLoadPsk(sslKeys_t *keys, unsigned char *key, uint32 keyLen,
				unsigned char *id, uint32 idLen)
{
	psPsk_t		*psk, *list;

	if (keys == NULL || key == NULL || id == NULL) {
		return PS_ARG_FAIL;
	}
	if (keyLen > SSL_PSK_MAX_KEY_SIZE) {
		psTraceIntInfo("Can't add PSK.  Key too large: %d\n", keyLen);
		return PS_ARG_FAIL;
	}

	if (idLen > SSL_PSK_MAX_ID_SIZE) {
		psTraceIntInfo("Can't add PSK.  Key ID too large: %d\n", idLen);
		return PS_ARG_FAIL;
	}

	if (keyLen < 1 || idLen < 1) {
		psTraceInfo("Can't add PSK. Both key and identity length must be >0\n");
		return PS_ARG_FAIL;
	}
	
	if ((psk = psMalloc(keys->pool, sizeof(psPsk_t))) == NULL) {
		return PS_MEM_FAIL;
	}
	memset(psk, 0, sizeof(psPsk_t));
	
	if ((psk->pskKey = psMalloc(keys->pool, keyLen)) == NULL) {
		psFree(psk);
		return PS_MEM_FAIL;
	}
	if ((psk->pskId = psMalloc(keys->pool, idLen)) == NULL) {
		psFree(psk->pskKey);
		psFree(psk);
		return PS_MEM_FAIL;
	}
	memcpy(psk->pskKey, key, keyLen);
	psk->pskLen = keyLen;
	
	memcpy(psk->pskId, id, idLen);
	psk->pskIdLen = idLen;
	
	if (keys->pskKeys == NULL) {
		keys->pskKeys = psk;
	} else {
		list = keys->pskKeys;
		while (list->next != NULL) {
			list = list->next;
		}
		list->next = psk;
	}
		
	return 0;
}


/******************************************************************************/
/*
	The ServerKeyExchange message passes an optional 'hint' to the client about
	which PSK it might want to use.  
*/
int32 matrixPskGetHint(ssl_t *ssl, char **hint, uint32 *hintLen)
{
/*
	RFC4279: In the absence of an application profile specification specifying
	otherwise, servers SHOULD NOT provide an identity hint and clients
	MUST ignore the identity hint field.  Applications that do use this
	field MUST specify its contents, how the value is chosen by the TLS
	server, and what the TLS client is expected to do with the value.

	NOTE: If you are adding support for a hint, make sure to also modify the
	SSL_PSK_MAX_HINT_SIZE define in matrixInternal.h so that messsageSize
	checks will work inside sslEncode.c
*/
	*hint = NULL;
	*hintLen = 0;
	return 0;
}

/******************************************************************************/
/*
	Get the id from the pre-shared key table based on given SSL session
	hint and hintLen are not currently used for the lookup
*/
int32 matrixSslPskGetKeyId(ssl_t *ssl, unsigned char **id, uint32 *idLen,
		char *hint, uint32 hintLen)
{
	psPsk_t	*psk;

	psk = ssl->keys->pskKeys;

	if (psk == NULL) {
		psTraceInfo("No pre-shared keys loaded\n");
		return PS_FAILURE;
	}
	
	*id = psk->pskId;
	*idLen = psk->pskIdLen;
	return PS_SUCCESS;
}

/******************************************************************************/
/*
	Get the key from the pre-shared list based on id
*/
int32 matrixSslPskGetKey(ssl_t *ssl, unsigned char *id, uint32 idLen,
		unsigned char **key, uint32 *keyLen)
{
	psPsk_t	*psk;

	*key = NULL;

	psk = ssl->keys->pskKeys;

	if (psk == NULL) {
		psTraceInfo("No pre-shared keys loaded\n");
		return PS_FAILURE;
	}
	
	if (idLen <= 0) {
		psTraceIntInfo("Bad PSK identity length: %d\n", idLen);
		return PS_ARG_FAIL;
	}

/*
	Make sure the length matches as well
*/
	while (psk) {
		if ((uint32)psk->pskIdLen == idLen) {
			if (memcmp(psk->pskId, id, idLen) == 0) {
				*key = psk->pskKey;
				*keyLen = psk->pskLen;
				return PS_SUCCESS;
			}
		}
		psk = psk->next;
	}

	psTraceInfo("Can't find PSK key from id\n");
	return PS_SUCCESS;
}
#endif /* USE_PSK_CIPHER_SUITE */

/******************************************************************************/
