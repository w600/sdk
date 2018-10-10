/*
 *	sha224.c
 *	Release $Name: MATRIXSSL-3-6-1-OPEN $
 *
 *	SHA256 hash implementation
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

#ifdef USE_SHA224

/******************************************************************************/
/*
   Initialize the sha224 (sha256) hash state
*/
void psSha224Init(psDigestContext_t *md)
{
	psAssert(md != NULL);

	md->sha256.curlen = 0;
#ifdef HAVE_NATIVE_INT64
	md->sha256.length = 0;
#else
	md->sha256.lengthHi = 0;
	md->sha256.lengthLo = 0;
#endif /* HAVE_NATIVE_INT64 */
    md->sha256.state[0] = 0xc1059ed8UL;
    md->sha256.state[1] = 0x367cd507UL;
    md->sha256.state[2] = 0x3070dd17UL;
    md->sha256.state[3] = 0xf70e5939UL;
    md->sha256.state[4] = 0xffc00b31UL;
    md->sha256.state[5] = 0x68581511UL;
    md->sha256.state[6] = 0x64f98fa7UL;
    md->sha256.state[7] = 0xbefa4fa4UL;
}

void psSha224Update(psDigestContext_t *md, const unsigned char *buf, uint32 len)
{
	psSha256Update(md, buf, len);
}

int32 psSha224Final(psDigestContext_t *md, unsigned char *out)
{
	unsigned char buf[32];
    int32 err;

    psAssert(md  != NULL);
    psAssert(out != NULL);

    err = psSha256Final(md, buf);
    memcpy(out, buf, SHA224_HASH_SIZE);
#ifdef USE_BURN_STACK
	psBurnStack(sizeof(buf));
#endif 
    return err;
}

#endif /* USE_SHA224 */


