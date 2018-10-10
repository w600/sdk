/*
 *	dh.c
 *	Release $Name: MATRIXSSL-3-6-1-OPEN $
 *
 *	Diffie-Hellman	
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

/******************************************************************************/
#ifdef USE_DH
/******************************************************************************/

#define DH_PUBLIC		0x01
#define DH_PRIVATE		0x02

/******************************************************************************/
/*
	Convert public DH key off wire to psDhKey_t struct
*/	
int32 psDhImportPubKey(psPool_t *pool, unsigned char *in, uint32 inlen,
						   psDhKey_t *key)
{
	int32	err;
	pstm_int	a;

	if ((err = pstm_init_for_read_unsigned_bin(pool, &a, inlen)) != PS_SUCCESS){
		return err;
	}
	if ((err = pstm_read_unsigned_bin(&a, in, inlen)) != PS_SUCCESS) {
		pstm_clear(&a);
		return err;
	}
	key->size = inlen;
	key->pub = a;
	key->type = DH_PUBLIC;
	return PS_SUCCESS;
}

/******************************************************************************/
/*
	Convert public psDhKey_t struct to binary for wire sends
*/
int32 psDhExportPubKey(psPool_t *pool, psDhKey_t *key, unsigned char **out)
{
	unsigned char	*tmp;
	uint32			x;

	tmp = *out;

	x = pstm_unsigned_bin_size(&key->pub);

	while (x < (unsigned long)key->size) {
		*tmp++ = 0x0;
		x++;
	}

	memset(tmp, 0x0, x);
	return pstm_to_unsigned_bin(pool, &key->pub, tmp);
}

/******************************************************************************/
/*
   Create the DH premaster secret.
   @param private_key	The private DH key in the pair
   @param public_key	The public DH key in the pair 
   @param out		[out] The destination of the shared data
   @param outlen	[in/out] The max size and resulting size of the shared data.
*/
int32 psDhGenSecret(psPool_t *pool, psDhKey_t *private_key,
					psDhKey_t *public_key, unsigned char *pBin, uint32 pLen,
					unsigned char *out, uint32 *outlen, void *data)
{
	pstm_int	tmp, p;
	uint32	x;
	int32	err;

	/* types valid? */
	if (private_key->type != DH_PRIVATE) {
		psTraceCrypto("Bad private key format for DH premaster\n");
		return PS_ARG_FAIL;
	}


	/* compute y^x mod p */
	if ((err = pstm_init(pool, &tmp)) != PS_SUCCESS) {
		return err;
	}
	if ((err = pstm_init_for_read_unsigned_bin(pool, &p, pLen)) != PS_SUCCESS) {
		return err;
	}

	if ((err = pstm_read_unsigned_bin(&p, pBin, pLen)) != PS_SUCCESS) {
		goto error;
	}
	if ((err = pstm_exptmod(pool, &public_key->pub, &private_key->priv, &p,
			&tmp)) != PS_SUCCESS) {
		goto error;
	}

	/* enough space for output? */
	x = (unsigned long)pstm_unsigned_bin_size(&tmp);
	if (*outlen < x) {
		psTraceCrypto("Overflow in DH premaster generation\n");
		err = PS_LIMIT_FAIL;
		goto error;
	}
/*
	It is possible to have a key size smaller than we expect
*/
	*outlen = x;

	if ((err = pstm_to_unsigned_bin(pool, &tmp, out)) != PS_SUCCESS) {
		goto error;
	}

	err = PS_SUCCESS;
error:
	pstm_clear(&p);
	pstm_clear(&tmp);
	return err;
}

/******************************************************************************/
/*
	Convert the pstm_int p and g params to binary for sending over the wire
*/
int32 psDhExportParameters(psPool_t *pool, psDhParams_t *key, uint32 *pLen,
						unsigned char **p, uint32 *gLen, unsigned char **g)
{
	int32	err = PS_SUCCESS;

	*pLen = pstm_unsigned_bin_size(&key->p);
	*gLen = pstm_unsigned_bin_size(&key->g);

	*p = psMalloc(pool, *pLen);
	if (*p == NULL) {
		psError("Memory allocation error in psDhExportParameters\n");
		return PS_MEM_FAIL;
	}
	*g = psMalloc(pool, *gLen);
	if (*g == NULL) {
		psError("Memory allocation error in psDhExportParameters\n");
		psFree(*p);
		return PS_MEM_FAIL;
	}
	
	if ((err = pstm_to_unsigned_bin(pool, &key->p, *p)) != PS_SUCCESS) {
		goto error;
	}
	if ((err = pstm_to_unsigned_bin(pool, &key->g, *g)) != PS_SUCCESS) {
		goto error;
	}

	goto done;
error:
	psFree(*p);
	psFree(*g);
done:
	return err;
}


/******************************************************************************/
/*
	Generate a DH key given the parameters
*/
int32 psDhKeyGen(psPool_t *pool, uint32 keysize, unsigned char *pBin,
				uint32 pLen, unsigned char *gBin, uint32 gLen, psDhKey_t *key,
				void *data)
{
	int32	err;
	pstm_int	p, g;
/*
	Convert the p and g into ints and make keys
*/
	if ((err = pstm_init_for_read_unsigned_bin(pool, &p, pLen)) != PS_SUCCESS) {
		return err;
	}
	if ((err = pstm_init_for_read_unsigned_bin(pool, &g, gLen)) != PS_SUCCESS) {
		pstm_clear(&p);
		return err;
	}

	if ((err = pstm_read_unsigned_bin(&p, pBin, pLen)) != PS_SUCCESS) {
		goto error;
	}
	if ((err = pstm_read_unsigned_bin(&g, gBin, gLen)) != PS_SUCCESS) {
		goto error;
	}

	err = psDhKeyGenInts(pool, keysize, &p, &g, key, data);

error:
	pstm_clear(&p);
	pstm_clear(&g);
	return err;
}


/******************************************************************************/
/*
	Does the actual key generation given p and g
*/
int32 psDhKeyGenInts(psPool_t *pool, uint32 keysize, pstm_int *p, pstm_int *g,
					  psDhKey_t *key, void *data)
{
	pstm_int		minusOne;
	unsigned char *buf = NULL;
	int32 err, i;

	if (key == NULL) {
		psTraceCrypto("NULL key passed to psDhMakeKey\n");
		return PS_ARG_FAIL;
	}
	memset(&minusOne, 0x0, sizeof(pstm_int));

	key->size = keysize;

	/* allocate buffer */
	buf = psMalloc(pool, keysize);
	if (buf == NULL) {
		psError("malloc error in psDhMakeKey\n");
		return PS_MEM_FAIL;
	}
	/* init parameters */
	if ((err = pstm_init_for_read_unsigned_bin(pool, &key->priv, keysize))
			!= PS_SUCCESS) {
		goto error;
	}
	if ((err = pstm_init_size(pool, &minusOne, p->used))
			!= PS_SUCCESS) {
		goto error;
	}
	pstm_sub_d(pool, p, 1, &minusOne);

   /* make up random string */
	for (i = 0; i < 1000; i++) {
		if ((err = psGetPrng(NULL, buf, keysize)) < 0) {
			goto error;
		}
		/* load the x value */
		if ((err = pstm_read_unsigned_bin(&key->priv, buf, keysize))
				!= PS_SUCCESS) {
			goto error;
		}
		/* Test key is between 2 and p - 1 */
		if (pstm_cmp_d(&key->priv, 2) == PSTM_LT) {
			continue;
		}
		if (pstm_cmp(&key->priv, &minusOne) == PSTM_GT) {
			continue;
		}
		break; /* found one */
		
	}
	if (i == 1000) {
		psTraceCrypto("DH private key could not be generated\n");
		err = PS_PLATFORM_FAIL;
		goto error;
	}
	pstm_clear(&minusOne);
	
	if ((err = pstm_init_size(pool, &key->pub, (key->priv.used * 2) + 1))
			!= PS_SUCCESS) {
		pstm_clear(&key->priv);
		goto error;
	}


	if ((err = pstm_exptmod(pool, g, &key->priv, p, &key->pub)) !=
			PS_SUCCESS) {
		goto error;
	}

	key->type = DH_PRIVATE;

	/* free up ram */
	err = PS_SUCCESS;
	goto done;

error:
	pstm_clear(&minusOne);
	pstm_clear(&key->priv);
	pstm_clear(&key->pub);
done:
	if (buf) psFree(buf);
	return err;
}

void psDhFreeKey(psDhKey_t *key)
{
	if (key->type == DH_PRIVATE) {
		pstm_clear(&key->priv);
	}
	pstm_clear(&key->pub);
}

#endif /* USE_DH */
/******************************************************************************/

