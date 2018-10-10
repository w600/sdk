/*
 *	aesGCM.c
 *	Release $Name: MATRIXSSL-3-6-1-OPEN $
 *
 *	AES GCM block cipher implementation
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
#if defined(USE_AES_GCM) && !defined(USE_AES_GCM_EXTERNAL)
/******************************************************************************/
static void psGhashPad(psCipherContext_t *Context_p);
static void psGhashInit(psCipherContext_t *Context_p,
				unsigned char *GHASHKey_p);
static void psGhashUpdate(psCipherContext_t *ctx, unsigned char *data,
				int32 dataLen, int dataType);
static void psGhashFinal(psCipherContext_t *Context_p);


#define GHASH_DATATYPE_AAD			0
#define GHASH_DATATYPE_CIPHERTEXT	2

#define FL_GET_BE32(be)                           \
    (((uint32)((be).be_bytes[0]) << 24) |         \
     ((uint32)((be).be_bytes[1]) << 16) |         \
     ((uint32)((be).be_bytes[2]) <<  8) |         \
     (uint32)((be).be_bytes[3]))

typedef struct { unsigned char be_bytes[4]; } FL_UInt32_BE_UNA_t;

#define FLFBLOCKSIZE 128 /* Maximum block size of a hash function. */

/******************************************************************************/
/*
	Initialize an AES GCM context
*/
int32 psAesInitGCM(psCipherContext_t *ctx, unsigned char *key, int32 keylen)
{
	unsigned char	blockIn[16];

	memset(ctx, 0x0, sizeof(psCipherContext_t));	

	memset(blockIn, 0x0, 16);
	if (psAesInitKey(key, keylen, &ctx->aes.key) < 0) {
		return -1;
	}
	psAesEncryptBlock(blockIn, ctx->aes.gInit, &ctx->aes.key);	
    return PS_SUCCESS;
}

/******************************************************************************/
/*
	Specifiy the IV and additional data to an AES GCM context that was 
	created with psAesInitGCM
*/
int32 psAesReadyGCM(psCipherContext_t *ctx, unsigned char *IV,
					unsigned char *aad,	int32 aadLen)
{
	psGhashInit(ctx, ctx->aes.gInit);
	/* Save aside first counter for final use */
	memset(ctx->aes.IV, 0, 16);
	memcpy(ctx->aes.IV, IV, 12);
	ctx->aes.IV[15] = 1;

	/* Set up crypto counter starting at nonce || 2 */
	memset(ctx->aes.EncCtr, 0, 16);
	memcpy(ctx->aes.EncCtr, IV, 12);
	ctx->aes.EncCtr[15] = 2;

	psGhashUpdate(ctx, aad, aadLen, GHASH_DATATYPE_AAD);
	psGhashPad(ctx);
    ctx->aes.blocklen = 16;
	return 0;
}

/******************************************************************************/
/*
	Internal gcm crypt function that uses direction to determine what gets
	fed to the GHASH update 
*/
static int32 psAesEncryptGCMx(psCipherContext_t *ctx, unsigned char *pt,
			unsigned char *ct, int32 len, int direction)
{
	unsigned char	*ctStart;
	int32			outLen;
	int x;

	outLen = len;
	ctStart = ct;
	if (direction == 0) {
		psGhashUpdate(ctx, pt, len, GHASH_DATATYPE_CIPHERTEXT); 
	}
	while(len) {
		if (ctx->aes.OutputBufferCount == 0) {
			ctx->aes.OutputBufferCount = 16;
			psAesEncryptBlock(ctx->aes.EncCtr, ctx->aes.CtrBlock,
				&ctx->aes.key);

			//psTraceBytes("block encrypt", ctx->aes.CtrBlock, 16);
			/* CTR incr */
			for (x = ctx->aes.blocklen-1; x >= 0; x--) {
				ctx->aes.EncCtr[x] = (ctx->aes.EncCtr[x] +
					(unsigned char)1) & (unsigned char)255;
				if (ctx->aes.EncCtr[x] != (unsigned char)0) {
					break;
				}
			}
		}

		*(ct++) = *(pt++) ^ ctx->aes.CtrBlock[16 - ctx->aes.OutputBufferCount];
		len--;
		ctx->aes.OutputBufferCount--;
	}
	if (direction == 1) {
		psGhashUpdate(ctx, ctStart, outLen, GHASH_DATATYPE_CIPHERTEXT); 
	} 
	return PS_SUCCESS;
}

/******************************************************************************/
/*
	Public GCM encrypt function.  This will just perform the encryption.  The
	tag should be fetched with psAesGetGCMTag
*/
int32 psAesEncryptGCM(psCipherContext_t *ctx, unsigned char *pt,
			unsigned char *ct, int32 len)
{
	return psAesEncryptGCMx(ctx, pt, ct, len, 1);
}

/******************************************************************************/
/*
	After encryption this function is used to retreive the authentication tag
*/
int32 psAesGetGCMTag(psCipherContext_t *ctx, int32 TagBytes, unsigned char *tag)
{
	unsigned char	*pt, *ct;

	psGhashFinal(ctx);

	/* Encrypt authentication tag */
    ctx->aes.OutputBufferCount = 0;

	ct = tag;
	pt = (unsigned char*)ctx->aes.TagTemp;	
	while (TagBytes) {
		if (ctx->aes.OutputBufferCount == 0) {
			ctx->aes.OutputBufferCount = 16;
			/* Initial IV has been set aside in IV */
			psAesEncryptBlock(ctx->aes.IV, ctx->aes.CtrBlock,
				&ctx->aes.key);
			/* No need to increment since we know tag bytes will never be
				larger than 16 */
		}
		*(ct++) = *(pt++) ^ ctx->aes.CtrBlock[16 - ctx->aes.OutputBufferCount];
        TagBytes--;
        ctx->aes.OutputBufferCount--;
	
	}
	return PS_SUCCESS;	
}

/* Just does the GCM decrypt portion.  Doesn't expect the tag to be at the end
	of the ct.  User will invoke psAesGetGCMTag seperately */
int32 psAesDecryptGCMtagless(psCipherContext_t *ctx, unsigned char *ct,
			unsigned char *pt, int32 len)
{
	return psAesEncryptGCMx(ctx, ct, pt, len, 0);
}


/******************************************************************************/
/*
	Decrypt will invoke GetGMCTag so the comparison can be done.  ctLen
	will include the appended tag length and ptLen is just the encrypted
	portion
*/	
int32 psAesDecryptGCM(psCipherContext_t *ctx, unsigned char *ct, int32 ctLen,
			unsigned char *pt, int32 ptLen)
{
	int	tagLen;
	unsigned char	tag[16];

	//psTraceBytes("GCM decrypting ct of", ct, ctLen);
	tagLen = ctLen - ptLen;

	psAesEncryptGCMx(ctx, ct, pt, ptLen, 0);
	psAesGetGCMTag(ctx, tagLen, tag);

	if (memcmp(tag, ct + ptLen, tagLen) != 0) {
		psTraceCrypto("GCM didn't authenticate\n");
		return -1; // didn't authenticate 
	}
	return PS_SUCCESS;
}

/******************************************************************************/
/*
	Ghash code taken from FL
*/
static void FLA_GHASH_128_mul_base(uint32 *op, uint32 moduli)
{
  int carry_bit = op[3] & 0x1;

  op[3] = op[3] >> 1 | (op[2] & 0x1) << 31;
  op[2] = op[2] >> 1 | (op[1] & 0x1) << 31;
  op[1] = op[1] >> 1 | (op[0] & 0x1) << 31;
  op[0] = op[0] >> 1;

  if (carry_bit)
      op[0] ^= moduli;
}

/* Multiplication of X by Y, storing the result to X. */
static void FLA_GHASH_128_mul(uint32 *X, const uint32 *Y, uint32 moduli)
{
  uint32 t[4];
  int i;

  t[0] = X[0];
  t[1] = X[1];
  t[2] = X[2];
  t[3] = X[3];

  X[0]= X[1] = X[2] = X[3] = 0;

 for (i = 0; i < 128; i++)
    {
      if (Y[i / 32] & (1 << (31 - i % 32)))
        {
          X[0] ^= t[0];
          X[1] ^= t[1];
          X[2] ^= t[2];
          X[3] ^= t[3];
        }

      FLA_GHASH_128_mul_base(t, moduli);
    }
}


static int FLFIncreaseCountBits(psCipherContext_t * ctx, unsigned int CounterId,
				int32 NBits)
{
    int32 Lo, Hi;
    int32 Temp;

    Lo = NBits;
    Hi = 0;

    Temp = ctx->aes.ProcessedBitCount[CounterId];
    ctx->aes.ProcessedBitCount[CounterId] += Lo;

    if (Temp > (int32)ctx->aes.ProcessedBitCount[CounterId])
    {
        Hi += 1;
    }

    if (Hi)
    {
        Temp = ctx->aes.ProcessedBitCount[CounterId + 1];
        ctx->aes.ProcessedBitCount[CounterId + 1] += Hi;

        /* Returns true if carry out of highest bits. */
        return (Temp > (int32)ctx->aes.ProcessedBitCount[CounterId + 1]);
    }

    /* No update of high order bits => No carry. */
    return 0; /* false */
}

static int increaseCountBytes(psCipherContext_t *ctx, int32 NBytes,
				int CounterId)
{
    int carry;

    /* COVN: Test this code with > 2^31 bits. */

    /* Process NBytes (assuming NBytes < 0x10000000) */
    carry = FLFIncreaseCountBits(ctx, CounterId, (NBytes & 0x0FFFFFFF) << 3);

    NBytes &= 0x0FFFFFFF;

    /* For unusually large values of NBytes, process the remaining bytes
       to add 0x10000000 at time. This ensure the value of bytes,
       once converted to bits, does not overflow 32-bit value.

       PORTN: It is assumed NBytes <= 2**61. This is true on 32-bit APIs as
       FL_DataLen_t cannot represent such large value. */
    while(NBytes >= 0x10000000)
    {
        carry |= FLFIncreaseCountBits(ctx, CounterId, 0x10000000U * 8);
        NBytes -= 0x10000000;
    }

    return carry;
}

static void FLAGcmProcessBlock(uint32 *H, FL_UInt32_BE_UNA_t *Buf_p,
				uint32 *InOut)
{
    /* PORTN: Requires sizeof(FL_UInt32_BE_UNA_t) to be 4.
       Some platforms may add padding to FL_UInt32_BE_UNA_t if
       it is represented as a structure. */

    InOut[0] ^= FL_GET_BE32(Buf_p[0]);
    InOut[1] ^= FL_GET_BE32(Buf_p[1]);
    InOut[2] ^= FL_GET_BE32(Buf_p[2]);
    InOut[3] ^= FL_GET_BE32(Buf_p[3]);

  FLA_GHASH_128_mul(InOut, H, (1 << 31) + (1 << 30) + (1 << 29) + (1 << 24));
}

static void UpdateFunc(psCipherContext_t *ctx, const unsigned char *Buf_p,
                  int32 Size)
{
    while (Size >= 16)
    {
        FLAGcmProcessBlock((uint32*)ctx->aes.Hash_SubKey,
			(FL_UInt32_BE_UNA_t *) Buf_p, (uint32*)ctx->aes.TagTemp);
        Buf_p += 16;
        Size -= 16;
    }
}

static void flf_blocker(psCipherContext_t *Context_p, unsigned char *Data_p,
			int32 DataCount)
{
    while (DataCount > 0)
    {
        if (Context_p->aes.InputBufferCount == FLFBLOCKSIZE)
        {
            UpdateFunc(Context_p,
                       Context_p->aes.Input.Buffer,
                       Context_p->aes.InputBufferCount);
            Context_p->aes.InputBufferCount = 0;
        }
        if (Context_p->aes.InputBufferCount < FLFBLOCKSIZE)
        {
            uint32 BytesProcess = min((uint32)DataCount,
				FLFBLOCKSIZE - Context_p->aes.InputBufferCount);

            memcpy(Context_p->aes.Input.Buffer
				+ Context_p->aes.InputBufferCount, Data_p, BytesProcess);
            DataCount -= BytesProcess;
            Context_p->aes.InputBufferCount += BytesProcess;
            Data_p += BytesProcess;
        }
    }

}

static void psGhashInit(psCipherContext_t *Context_p, unsigned char *GHASHKey_p)
{
	uint32 *Key_p = (uint32*)Context_p->aes.Hash_SubKey;

    memset(&Context_p->aes.ProcessedBitCount, 0x0,
		sizeof(Context_p->aes.ProcessedBitCount));
    Context_p->aes.InputBufferCount = 0;
    Key_p[0] = FL_GET_BE32(*(FL_UInt32_BE_UNA_t *) GHASHKey_p);
    Key_p[1] = FL_GET_BE32(*(FL_UInt32_BE_UNA_t *) (GHASHKey_p + 4));
    Key_p[2] = FL_GET_BE32(*(FL_UInt32_BE_UNA_t *) (GHASHKey_p + 8));
    Key_p[3] = FL_GET_BE32(*(FL_UInt32_BE_UNA_t *) (GHASHKey_p + 12));
    memset(Context_p->aes.TagTemp, 0x0, 16);
}

static void psGhashUpdate(psCipherContext_t *ctx, unsigned char *data,
				int32 dataLen, int dataType)
{
	increaseCountBytes(ctx, dataLen, dataType);
	flf_blocker(ctx, data, dataLen);

}

static void psGhashPad(psCipherContext_t *Context_p)
{
    while ((Context_p->aes.InputBufferCount & 15) != 0)
    {
        unsigned char z = 0;
        flf_blocker(Context_p, &z, 1);
    }
}

static uint32 FLM_ReverseBytes32(uint32 Value)
{
    /* TODO: Testing for this function. */
    Value = (((Value & 0xff00ff00UL) >> 8) | ((Value & 0x00ff00ffUL) << 8));
    return ((Value >> 16) | (Value << 16));
}

static void FLF_ConvertToBE64(uint32 *Swap_p, uint32 num)
{
    /* PORTN: Byte order specific function. */
	uint32 tmp;
    while(num)
    {
        num--;
        tmp = FLM_ReverseBytes32(Swap_p[num * 2]);
        Swap_p[num * 2] = FLM_ReverseBytes32(Swap_p[num * 2 + 1]);
        Swap_p[num * 2 + 1] = tmp;
    }
}

static void FLF_ConvertToBE32(uint32 *Swap_p, uint32 num)
{
    /* PORTN: Byte order specific function. */
    while(num)
    {
        num--;
        Swap_p[num] = FLM_ReverseBytes32(Swap_p[num]);
    }
}

static void psGhashFinal(psCipherContext_t *Context_p)
{
	psGhashPad(Context_p);

    // PORTN: Intended to be byte order independent, but check.
    // COVN: Check GHASH with data > 2^32 bits.
    FLF_ConvertToBE64(&Context_p->aes.ProcessedBitCount[0], 2);

	UpdateFunc(Context_p, Context_p->aes.Input.Buffer,
		Context_p->aes.InputBufferCount);
	Context_p->aes.InputBufferCount = 0;

    UpdateFunc(Context_p,
		(const unsigned char *) &Context_p->aes.ProcessedBitCount[0], 16);
	
    /* Convert temporary Tag Value to final Tag Value. */
    FLF_ConvertToBE32(Context_p->aes.TagTemp, 4);
}

#endif /* USE_AES_GCM  && !USE_AES_GCM_EXTERNAL */
