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

#ifdef USE_SHA384

void psSha384Init(psDigestContext_t *md)
{
    psAssert(md != NULL);

    md->sha512.curlen = 0;
    md->sha512.length = 0;
    md->sha512.state[0] = CONST64(0xcbbb9d5dc1059ed8);
    md->sha512.state[1] = CONST64(0x629a292a367cd507);
    md->sha512.state[2] = CONST64(0x9159015a3070dd17);
    md->sha512.state[3] = CONST64(0x152fecd8f70e5939);
    md->sha512.state[4] = CONST64(0x67332667ffc00b31);
    md->sha512.state[5] = CONST64(0x8eb44a8768581511);
    md->sha512.state[6] = CONST64(0xdb0c2e0d64f98fa7);
	md->sha512.state[7] = CONST64(0x47b5481dbefa4fa4);
}

void psSha384Update(psDigestContext_t *md, const unsigned char *buf, uint32 len)
{
	psSha512Update(md, buf, len);
}

int32 psSha384Final(psDigestContext_t *md, unsigned char *out)
{
	unsigned char buf[64];

	psAssert(md  != NULL);
	psAssert(out != NULL);

	if (md->sha512.curlen >= sizeof(md->sha512.buf)) {
		return PS_ARG_FAIL;
	}

	psSha512Final(md, buf);
	memcpy(out, buf, SHA384_HASH_SIZE);
#ifdef USE_BURN_STACK
	psBurnStack(sizeof(buf));
#endif
	return SHA384_HASH_SIZE;
}

#endif /* USE_SHA384 */

