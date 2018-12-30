#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wm_regs.h"
#include "wm_irq.h"
#include "wm_crypto_hard.h"
#include "wm_internal_flash.h"

//#define TEST_ALL_CRYPTO
#undef	DIGIT_BIT
#define DIGIT_BIT			28

#define SOFT_RESET_RC4    	25
#define SOFT_RESET_AES    	26
#define SOFT_RESET_DES    	27

#define RNG_SWITCH        	28
#define RNG_LOAD_SEED    	29
#define RNG_START         	30


volatile u8 crypto_complete = 0;
#if 0
typedef s32 psPool_t;
#include "libtommath.h"
#define pstm_set(a, b) mp_set((mp_int *)a, b)
#define pstm_init(pool, a) wpa_mp_init((mp_int *)a)
#define pstm_count_bits(a) mp_count_bits((mp_int *)a)
#define pstm_init_for_read_unsigned_bin(pool, a, len) mp_init_for_read_unsigned_bin((mp_int *)a, len)
#define pstm_read_unsigned_bin(a, b, c) mp_read_unsigned_bin((mp_int *)a, b, c)
#define pstm_copy(a, b) mp_copy((mp_int *)a, (mp_int *)b)
#define pstm_clear(a) mp_clear((mp_int *)a)
#define pstm_clamp(a) mp_clamp((mp_int *)a)
#define pstm_mulmod(pool, a, b, c, d) mp_mulmod((mp_int *)a, (mp_int *)b, (mp_int *)c, (mp_int *)d)			
#define pstm_exptmod(pool, G, X, P, Y) mp_exptmod((mp_int *)G, (mp_int *)X, (mp_int *)P, (mp_int *)Y)
#define pstm_reverse mp_reverse
#define pstm_cmp mp_cmp
#define pstm_to_unsigned_bin_nr(pool, a, b) mp_to_unsigned_bin_nr((mp_int *)a, (unsigned char *)b)
#endif


void RSA_IRQHandler(void)
{
	RSACON = 0x00;
	crypto_complete = 1;
}
void CRYPTION_IRQHandler(void)
{
	tls_reg_write32(HR_CRYPTO_SEC_STS, 0x10000);
	crypto_complete = 1;
}


static int16 pstm_get_bit (pstm_int * a, int16 idx)
{
	int16     r;
	int16 n = idx / DIGIT_BIT;
	int16 m = idx % DIGIT_BIT;

	if (a->used <= 0) {
		return 0;
	}
	
	r = (a->dp[n] >> m) & 0x01;
	return r;
}

u32 Reflect(u32 ref,u8 ch)
{	
	int i;
	u32 value = 0;
	for( i = 1; i < ( ch + 1 ); i++ )
	{
		if( ref & 1 )
			value |= 1 << ( ch - i );
		ref >>= 1;
	}
	return value;
}

/**
 * @brief          	This function is used to stop random produce.
 *
 * @param[in]      	None
 *
 * @retval         	0     		success
 * @retval         	other 	failed
 *
 * @note           	None
 */
int tls_crypto_random_stop(void)
{
	unsigned int sec_cfg, val;
	val = tls_reg_read32(HR_CRYPTO_SEC_CFG);
	sec_cfg = val & ~(1 << RNG_START);
	tls_reg_write32(HR_CRYPTO_SEC_CFG, sec_cfg);
	
	return ERR_CRY_OK;
}

/**
 * @brief          	This function initializes random digit seed and BIT number.
 *
 * @param[in]   	seed 		The random digit seed.
 * @param[in]   	rng_switch 	The random digit bit number.   (0: 16bit    1:32bit)				
 *
 * @retval  		0  			success 
 * @retval  		other   		failed  
 *
 * @note             	None
 */
int tls_crypto_random_init(u32 seed, CRYPTO_RNG_SWITCH rng_switch)
{
	unsigned int sec_cfg;
	tls_crypto_random_stop();
	tls_reg_write32(HR_CRYPTO_KEY0, seed);
	sec_cfg = (rng_switch << RNG_SWITCH) | (1 << RNG_LOAD_SEED) | (1 << RNG_START);
	tls_reg_write32(HR_CRYPTO_SEC_CFG, sec_cfg);
	return ERR_CRY_OK;
}

/**
 * @brief          	This function is used to get random digit content.
 *
 * @param[in]   	out 			Pointer to the output of random digit.
 * @param[in]   	len 			The random digit bit number will output.
 *
 * @retval  		0  			success 
 * @retval  		other   		failed  
 *
 * @note             	None
 */
int tls_crypto_random_bytes(unsigned char *out, u32 len)
{
	unsigned int val;
	uint32 inLen = len;
	int randomBytes = 2;
	val = tls_reg_read32(HR_CRYPTO_SEC_CFG);
	randomBytes = val & (1 << RNG_SWITCH) ? 4 : 2;
	while(inLen > 0)
	{
		val = tls_reg_read32(HR_CRYPTO_RNG_RESULT);
		if(inLen >= randomBytes)
		{
			memcpy(out, (char*)&val, randomBytes);
			out += randomBytes;
			inLen -= randomBytes;
		}
		else
		{
			memcpy(out, (char*)&val, inLen);
			inLen = 0;
		}
	}
	return ERR_CRY_OK;
}

/**
 * @brief          	This function initializes a RC4 encryption algorithm,  
 *				i.e. fills the psCipherContext_t structure pointed to by ctx with necessary data. 
 *
 * @param[in]   	ctx 		Pointer to the Cipher Context. 
 * @param[in]   	key 		Pointer to the key. 
 * @param[in]   	keylen 	the length of key. 
 *
 * @retval  		0  		success 
 * @retval  		other   	failed  

 *
 * @note             	The first parameter ctx must be a structure which is allocated externally. 
 *      			And all of Context parameters in the initializing methods should be allocated externally too.
 */
int tls_crypto_rc4_init(psCipherContext_t * ctx, const unsigned char *key, u32 keylen)
{
	if(keylen != 16)
		return ERR_FAILURE;
	memcpy(ctx->arc4.state, key, keylen);
	ctx->arc4.byteCount = keylen;
	
	return ERR_CRY_OK;
}


/**
 * @brief          	This function encrypts a variable length data stream according to RC4.
 *				The RC4 algorithm it generates a "keystream" which is simply XORed with the plaintext to produce the ciphertext stream. 
 *				Decryption is exactly the same as encryption. This function also decrypts a variable length data stream according to RC4.
 *
 * @param[in]   	ctx 		Pointer to the Cipher Context.
 * @param[in]   	in 		Pointer to the input plaintext data stream(or the encrypted text data stream) of variable length.
 * @param[in]   	out 		Pointer to the resulting ciphertext data stream. 
 * @param[in]		len 		Length of the plaintext data stream in octets.
 *
 * @retval  		0  		success 
 * @retval  		other   	failed  
 *
 * @note             	None
 */
int tls_crypto_rc4(psCipherContext_t * ctx, unsigned char *in, unsigned char *out, u32 len)
{
	unsigned int sec_cfg, val;
	unsigned char *key = ctx->arc4.state;
	u32 keylen = ctx->arc4.byteCount;
	memset((void *)HR_CRYPTO_KEY0, 0, 16);
	memcpy((void *)HR_CRYPTO_KEY0, key, keylen);
	tls_reg_write32(HR_CRYPTO_SRC_ADDR, (unsigned int)in);
	tls_reg_write32(HR_CRYPTO_DEST_ADDR, (unsigned int)out);
	val = tls_reg_read32(HR_CRYPTO_SEC_CFG);
	sec_cfg = (val & 0xF0000000) | (CRYPTO_METHOD_RC4 << 16) | (1 << SOFT_RESET_RC4) | (len & 0xFFFF);
	tls_reg_write32(HR_CRYPTO_SEC_CFG, sec_cfg);
	tls_reg_write32(HR_CRYPTO_SEC_CTRL, 0x1);//start crypto
	while (!crypto_complete)
	{

	}
	crypto_complete = 0;
	return ERR_CRY_OK;
}


/**
 * @brief          	This function initializes a AES encryption algorithm,  i.e. fills the psCipherContext_t structure pointed to by ctx with necessary data.
 *
 * @param[in]   	ctx 		Pointer to the Cipher Context. 
 * @param[in]   	IV 		Pointer to the Initialization Vector
 * @param[in]   	key 		Pointer to the key. 
 * @param[in]		keylen 	the length of key.
 * @param[in]   	cbc 		the encryption mode, AES supports ECB/CBC/CTR modes.
 *
 * @retval  		0  		success 
 * @retval  		other   	failed  
 *
 * @note             	None
 */
int tls_crypto_aes_init(psCipherContext_t * ctx, const unsigned char *IV, const unsigned char *key, u32 keylen, CRYPTO_MODE cbc)
{
	int x = 0;
	if (keylen != 16)
		return ERR_FAILURE;

	memcpy(ctx->aes.key.eK, key, keylen);
	ctx->aes.key.Nr = cbc;
	ctx->aes.blocklen = 16;
	for (x = 0; x < ctx->aes.blocklen; x++) {
		ctx->aes.IV[x] = IV[x];
	}
	return ERR_CRY_OK;
}
 
/**
 * @brief			This function encrypts or decrypts a variable length data stream according to AES.
 *
 * @param[in]		ctx 		Pointer to the Cipher Context. 
 * @param[in]		in 		Pointer to the input plaintext data stream(or the encrypted text data stream) of variable length.
 * @param[in]		out 		Pointer to the resulting ciphertext data stream.
 * @param[in]		len 		Length of the plaintext data stream in octets.
 * @param[in]		dec 		The cryption way which indicates encryption or decryption.
 *
 * @retval		0  		success 
 * @retval		other	failed	
 *
 * @note			None
 */
int tls_crypto_aes_encrypt_decrypt(psCipherContext_t * ctx, unsigned char *in, unsigned char *out, u32 len, CRYPTO_WAY dec)
{
	unsigned int sec_cfg, val;
	u32 keylen = 16;
	unsigned char *key = (unsigned char *)ctx->aes.key.eK;
	unsigned char *IV = ctx->aes.IV;
	CRYPTO_MODE cbc = (CRYPTO_MODE)(ctx->aes.key.Nr & 0xFF);
	memset((void *)HR_CRYPTO_KEY0, 0, 16);
	memcpy((void *)HR_CRYPTO_KEY0, key, keylen);
	memset((void *)HR_CRYPTO_IV0, 0, 8);
	memset((void *)HR_CRYPTO_IV1, 0, 8);
	memcpy((void *)HR_CRYPTO_IV0, IV, 8);
	memcpy((void *)HR_CRYPTO_IV1, IV+8, 8);
	
	tls_reg_write32(HR_CRYPTO_SRC_ADDR, (unsigned int)in);
	tls_reg_write32(HR_CRYPTO_DEST_ADDR, (unsigned int)out);
	val = tls_reg_read32(HR_CRYPTO_SEC_CFG);
	sec_cfg = (val & 0xF0000000) | (CRYPTO_METHOD_AES << 16) | (1 << SOFT_RESET_AES) |(dec << 20) | (cbc << 21) | (len & 0xFFFF); 
	tls_reg_write32(HR_CRYPTO_SEC_CFG, sec_cfg);
	tls_reg_write32(HR_CRYPTO_SEC_CTRL, 0x1);//start crypto
	while (!crypto_complete)
	{
	
	}
	crypto_complete = 0;
	return ERR_CRY_OK;
}

/**
 * @brief			This function initializes a 3DES encryption algorithm,  i.e. fills the psCipherContext_t structure pointed to by ctx with necessary data. 
 *
 * @param[in]		ctx 		Pointer to the Cipher Context. 
 * @param[in]		IV 		Pointer to the Initialization Vector
 * @param[in]		key 		Pointer to the key. 
 * @param[in]		keylen 	the length of key. 
 * @param[in]		cbc 		the encryption mode, 3DES supports ECB/CBC modes.
 *
 * @retval		0  		success 
 * @retval		other	failed	
 *
 * @note			None
 */
int tls_crypto_3des_init(psCipherContext_t * ctx, const unsigned char *IV, const unsigned char *key, u32 keylen, CRYPTO_MODE cbc)
{
	unsigned int x;
	if (keylen != DES3_KEY_LEN)
		return ERR_FAILURE;

	memcpy(ctx->des3.key.ek[0], key, keylen);
	ctx->des3.key.ek[1][0] =  cbc;
	ctx->des3.blocklen = DES3_IV_LEN;
	for (x = 0; x < ctx->des3.blocklen; x++) {
		ctx->des3.IV[x] = IV[x];
	}
	
	return ERR_CRY_OK;
}

/**
 * @brief			This function encrypts or decrypts a variable length data stream according to 3DES.
 *
 * @param[in]		ctx 		Pointer to the Cipher Context.
 * @param[in]		in 		Pointer to the input plaintext data stream(or the encrypted text data stream) of variable length.
 * @param[in]		out 		Pointer to the resulting ciphertext data stream.
 * @param[in]		len 		Length of the plaintext data stream in octets.
 * @param[in]		dec 		The cryption way which indicates encryption or decryption.
 *
 * @retval		0  		success 
 * @retval		other	failed	
 *
 * @note			None
 */
int tls_crypto_3des_encrypt_decrypt(psCipherContext_t * ctx, unsigned char *in, unsigned char *out, u32 len, CRYPTO_WAY dec)
{
	unsigned int sec_cfg, val;
	u32 keylen = DES3_KEY_LEN;
	unsigned char *key = (unsigned char *)(unsigned char *)ctx->des3.key.ek[0];
	unsigned char *IV = ctx->des3.IV;
	CRYPTO_MODE cbc = (CRYPTO_MODE)(ctx->des3.key.ek[1][0] & 0xFF);
	memset((void *)HR_CRYPTO_KEY0, 0, DES3_KEY_LEN);
	memcpy((void *)HR_CRYPTO_KEY0, key, keylen);
	memset((void *)HR_CRYPTO_IV0, 0, DES3_IV_LEN);
	memcpy((void *)HR_CRYPTO_IV0, IV, DES3_IV_LEN);
	tls_reg_write32(HR_CRYPTO_SRC_ADDR, (unsigned int)in);
	tls_reg_write32(HR_CRYPTO_DEST_ADDR, (unsigned int)out);
	val = tls_reg_read32(HR_CRYPTO_SEC_CFG);
	sec_cfg = (val & 0xF0000000) |(CRYPTO_METHOD_3DES << 16) | (1 << SOFT_RESET_DES) | (dec << 20) | (cbc << 21) | (len & 0xFFFF); 
	tls_reg_write32(HR_CRYPTO_SEC_CFG, sec_cfg);
	tls_reg_write32(HR_CRYPTO_SEC_CTRL, 0x1);//start crypto
	while (!crypto_complete)
	{

	}
	crypto_complete = 0;
	return ERR_CRY_OK;
}
  

/**
 * @brief			This function initializes a DES encryption algorithm,  i.e. fills the psCipherContext_t structure pointed to by ctx with necessary data. 
 *
 * @param[in]		ctx 		Pointer to the Cipher Context. 
 * @param[in]		IV 		Pointer to the Initialization Vector
 * @param[in]		key 		Pointer to the key. 
 * @param[in]		keylen 	the length of key. 
 * @param[in]		cbc 		the encryption mode, DES supports ECB/CBC modes.
 *
 * @retval		0  		success 
 * @retval		other	failed	
 *
 * @note			None
 */
int tls_crypto_des_init(psCipherContext_t * ctx, const unsigned char *IV, const unsigned char *key, u32 keylen, CRYPTO_MODE cbc)
{
	unsigned int x;
	if (keylen != DES_KEY_LEN)
		return ERR_FAILURE;
	memcpy(ctx->des3.key.ek[0], key, keylen);
	ctx->des3.key.ek[1][0] =  cbc;
	ctx->des3.blocklen = DES3_IV_LEN;
	for (x = 0; x < ctx->des3.blocklen; x++) {
		ctx->des3.IV[x] = IV[x];
	}
	return ERR_CRY_OK;
}


/**
 * @brief			This function encrypts or decrypts a variable length data stream according to DES.
 *
 * @param[in]		ctx 		Pointer to the Cipher Context. 
 * @param[in]		in 		Pointer to the input plaintext data stream(or the encrypted text data stream) of variable length.
 * @param[in]		out 		Pointer to the resulting ciphertext data stream.
 * @param[in]		len 		Length of the plaintext data stream in octets.
 * @param[in]		dec 		The cryption way which indicates encryption or decryption.
 *
 * @retval		0  		success 
 * @retval		other	failed	
 *
 * @note			None
 */
int tls_crypto_des_encrypt_decrypt(psCipherContext_t * ctx, unsigned char *in, unsigned char *out, u32 len, CRYPTO_WAY dec)
{
	unsigned int sec_cfg, val;
	u32 keylen = DES_KEY_LEN;
	unsigned char *key = (unsigned char *)ctx->des3.key.ek[0];
	unsigned char *IV = ctx->des3.IV;
	CRYPTO_MODE cbc = (CRYPTO_MODE)(ctx->des3.key.ek[1][0] & 0xFF);
	memset((void *)HR_CRYPTO_KEY0, 0, DES_KEY_LEN);
	memcpy((void *)HR_CRYPTO_KEY0, key, keylen);
	memset((void *)HR_CRYPTO_IV0, 0, DES3_IV_LEN);
	memcpy((void *)HR_CRYPTO_IV0, IV, DES3_IV_LEN);
	tls_reg_write32(HR_CRYPTO_SRC_ADDR, (unsigned int)in);
	tls_reg_write32(HR_CRYPTO_DEST_ADDR, (unsigned int)out);
	val = tls_reg_read32(HR_CRYPTO_SEC_CFG);
	sec_cfg = (val & 0xF0000000) | (CRYPTO_METHOD_DES << 16) | (1 << SOFT_RESET_DES) | (dec << 20) | (cbc << 21) | (len & 0xFFFF); 
	tls_reg_write32(HR_CRYPTO_SEC_CFG, sec_cfg);
	tls_reg_write32(HR_CRYPTO_SEC_CTRL, 0x1);//start crypto
	while (!crypto_complete)
	{

	}
	crypto_complete = 0;
	return ERR_CRY_OK;
}

 
/**
 * @brief			This function initializes a CRC algorithm,  i.e. fills the psCrcContext_t structure pointed to by ctx with necessary data. 
 *
 * @param[in]		ctx 		Pointer to the CRC Context. 
 * @param[in]		key 		The initialization key. 
 * @param[in]		crc_type 	The CRC type, supports CRC8/CRC16 MODBUS/CRC16 CCITT/CRC32
 * @param[in]		mode 	Set input or outpu reflect.
 * @param[in]		dec 		The cryption way which indicates encryption or decryption.
 *				see OUTPUT_REFLECT
 * 				see INPUT_REFLECT
 *
 * @retval		0		success 
 * @retval		other	failed	
 *
 * @note			None
 */
int tls_crypto_crc_init(psCrcContext_t * ctx, u32 key, CRYPTO_CRC_TYPE crc_type, u8 mode)
{
	ctx->state = key;
	ctx->type = crc_type;
	ctx->mode = mode;
	return ERR_CRY_OK;
}

/**
 * @brief			This function updates the CRC value with a variable length bytes.
 *				This function may be called as many times as necessary, so the message may be processed in blocks.
 *
 * @param[in]		ctx 		Pointer to the CRC Context. 
 * @param[in]		in 		Pointer to a variable length bytes
 * @param[in]		len 		The bytes 's length 
 *
 * @retval		0		success 
 * @retval		other	failed	
 *
 * @note			None
 */
int tls_crypto_crc_update(psCrcContext_t * ctx, unsigned char *in, u32 len)
{
	unsigned int sec_cfg, val;
	val = tls_reg_read32(HR_CRYPTO_SEC_CFG);
	sec_cfg =  (val & 0xF0000000) | (CRYPTO_METHOD_CRC << 16) | (ctx->type << 21) | (ctx->mode << 23) | (len & 0xFFFF); 
	tls_reg_write32(HR_CRYPTO_SEC_CFG, sec_cfg);
	if(ctx->mode & OUTPUT_REFLECT)
	{
		u8 ch_crc = 16;
		u32 state = 0;
		switch(ctx->type)
		{
			case CRYPTO_CRC_TYPE_8:
				ch_crc = 8;
				break;
			case CRYPTO_CRC_TYPE_16_MODBUS:
				ch_crc = 16;
				break;
			case CRYPTO_CRC_TYPE_16_CCITT:
				ch_crc = 16;
				break;
			case CRYPTO_CRC_TYPE_32:
				ch_crc = 32;
				break;
			default:
				break;
		}
		state = Reflect(ctx->state, ch_crc);
		tls_reg_write32(HR_CRYPTO_CRC_KEY, state);
	}
	else
		tls_reg_write32(HR_CRYPTO_CRC_KEY, ctx->state);
	
	tls_reg_write32(HR_CRYPTO_SRC_ADDR, (unsigned int)in);
	tls_reg_write32(HR_CRYPTO_SEC_CTRL, 0x1);//start crypto
	while (!crypto_complete)
	{

	}
	crypto_complete = 0;
	ctx->state = tls_reg_read32(HR_CRYPTO_CRC_RESULT); 
	return ERR_CRY_OK;
}


/**
 * @brief			This function ends a CRC operation and produces a CRC value.
 *
 * @param[in]		ctx 		Pointer to the CRC Context. 
 * @param[in]		crc_val 	Pointer to the CRC value.
 *
 * @retval		0		success 
 * @retval		other	failed	
 *
 * @note			None
 */
int tls_crypto_crc_final(psCrcContext_t * ctx, u32 *crc_val)
{
	*crc_val = ctx->state; 
	return ERR_CRY_OK;
}

static void hd_sha1_compress(psDigestContext_t *md)
{
	unsigned int sec_cfg, val;
	int i = 0;
	tls_reg_write32(HR_CRYPTO_SRC_ADDR, (unsigned int)md->sha1.buf);

	val = tls_reg_read32(HR_CRYPTO_SEC_CFG);
	sec_cfg = (val & 0xF0000000) | (CRYPTO_METHOD_SHA1 << 16) | (64 & 0xFFFF); // TODO
	tls_reg_write32(HR_CRYPTO_SEC_CFG, sec_cfg);
	tls_reg_write32(HR_CRYPTO_SHA1_DIGEST0, md->sha1.state[0]);
	tls_reg_write32(HR_CRYPTO_SHA1_DIGEST1, md->sha1.state[1]);
	tls_reg_write32(HR_CRYPTO_SHA1_DIGEST2, md->sha1.state[2]);
	tls_reg_write32(HR_CRYPTO_SHA1_DIGEST3, md->sha1.state[3]);
	tls_reg_write32(HR_CRYPTO_SHA1_DIGEST4, md->sha1.state[4]);
	tls_reg_write32(HR_CRYPTO_SEC_CTRL, 0x1);//start crypto
	while (!crypto_complete)
	{

	}
	crypto_complete = 0;
	for (i = 0; i < 5; i++) {
		val = tls_reg_read32(HR_CRYPTO_SHA1_DIGEST0 + (4*i));
		md->sha1.state[i] = val;
	}
}


/**
 * @brief			This function initializes Message-Diggest context for usage in SHA1 algorithm, starts a new SHA1 operation and writes a new Digest Context. 
 *
 * @param[in]		md 		Pointer to the SHA1 Digest Context. 
 *
 * @retval		0		success 
 * @retval		other	failed	
 *
 * @note			None
 */
void tls_crypto_sha1_init(psDigestContext_t * md)
{
	md->sha1.state[0] = 0x67452301UL;
	md->sha1.state[1] = 0xefcdab89UL;
	md->sha1.state[2] = 0x98badcfeUL;
	md->sha1.state[3] = 0x10325476UL;
	md->sha1.state[4] = 0xc3d2e1f0UL;
	md->sha1.curlen = 0;
#ifdef HAVE_NATIVE_INT64
	md->sha1.length = 0;
#else
	md->sha1.lengthHi = 0;
	md->sha1.lengthLo = 0;
#endif /* HAVE_NATIVE_INT64 */
}


/**
 * @brief			Process a message block using SHA1 algorithm.
 *				This function performs a SHA1 block update operation. It continues an SHA1 message-digest operation, 
 *				by processing InputLen-byte length message block pointed to by buf, and by updating the SHA1 context pointed to by md.
 *				This function may be called as many times as necessary, so the message may be processed in blocks.
 *
 * @param[in]		md		Pointer to the SHA1 Digest Context. 
 * @param[in]  	buf 		InputLen-byte length message block
 * @param[in]  	len 		The buf 's length 
 *
 * @returnl		None	
 *
 * @note			None
 */
void tls_crypto_sha1_update(psDigestContext_t * md, const unsigned char *buf, u32 len)
{
	u32 n;
	while (len > 0) {
		n = min(len, (64 - md->sha1.curlen));
		memcpy(md->sha1.buf + md->sha1.curlen, buf, (size_t)n);
		md->sha1.curlen		+= n;
		buf					+= n;
		len					-= n;

		/* is 64 bytes full? */
		if (md->sha1.curlen == 64) {
			hd_sha1_compress(md);
#ifdef HAVE_NATIVE_INT64
			md->sha1.length += 512;
#else
			n = (md->sha1.lengthLo + 512) & 0xFFFFFFFFL;
			if (n < md->sha1.lengthLo) {
				md->sha1.lengthHi++;
			}
			md->sha1.lengthLo = n;
#endif /* HAVE_NATIVE_INT64 */
			md->sha1.curlen = 0;
		}
	}
}

 
/**
 * @brief			This function ends a SHA1 operation and produces a Message-Digest.
 *				This function finalizes SHA1 algorithm, i.e. ends an SHA1 Message-Digest operation, 
 *				writing the Message-Digest in the 20-byte buffer pointed to by hash in according to the information stored in context. 
 *
 * @param[in]		md		Pointer to the SHA1 Digest Context. 
 * @param[in]		hash 	Pointer to the Message-Digest
 *
 * @retval  		20  		success, return the hash size.
 * @retval  		<0   	failed  

 *
 * @note			None
 */
int tls_crypto_sha1_final(psDigestContext_t * md, unsigned char *hash)
{
	s32	i;
	u32 val;
#ifndef HAVE_NATIVE_INT64
	u32	n;
#endif
	if (md->sha1.curlen >= sizeof(md->sha1.buf) || hash == NULL) {
		return ERR_ARG_FAIL;
	}

/*
	increase the length of the message
 */
#ifdef HAVE_NATIVE_INT64
	md->sha1.length += md->sha1.curlen << 3;
#else
	n = (md->sha1.lengthLo + (md->sha1.curlen << 3)) & 0xFFFFFFFFL;
	if (n < md->sha1.lengthLo) {
		md->sha1.lengthHi++;
	}
	md->sha1.lengthHi += (md->sha1.curlen >> 29);
	md->sha1.lengthLo = n;
#endif /* HAVE_NATIVE_INT64 */

/*
	append the '1' bit
 */
	md->sha1.buf[md->sha1.curlen++] = (unsigned char)0x80;

/*
	if the length is currently above 56 bytes we append zeros then compress.
	Then we can fall back to padding zeros and length encoding like normal.
 */
	if (md->sha1.curlen > 56) {
		while (md->sha1.curlen < 64) {
			md->sha1.buf[md->sha1.curlen++] = (unsigned char)0;
		}
		hd_sha1_compress(md);
		md->sha1.curlen = 0;
	}

/*
	pad upto 56 bytes of zeroes
 */
	while (md->sha1.curlen < 56) {
		md->sha1.buf[md->sha1.curlen++] = (unsigned char)0;
	}

/*
	store length
 */
#ifdef HAVE_NATIVE_INT64
	STORE64H(md->sha1.length, md->sha1.buf+56);
#else
	STORE32H(md->sha1.lengthHi, md->sha1.buf+56);
	STORE32H(md->sha1.lengthLo, md->sha1.buf+60);
#endif /* HAVE_NATIVE_INT64 */
	hd_sha1_compress(md);

/*
	copy output
 */
	for (i = 0; i < 5; i++) {
		val = tls_reg_read32(HR_CRYPTO_SHA1_DIGEST0 + (4*i));
		STORE32H(val, hash+(4*i));
	}
	memset(md, 0x0, sizeof(psDigestContext_t));
	return SHA1_HASH_SIZE;
}

static void hd_md5_compress(psDigestContext_t *md)
{
	unsigned int sec_cfg, val, i;
	tls_reg_write32(HR_CRYPTO_SRC_ADDR, (unsigned int)md->md5.buf);
	val = tls_reg_read32(HR_CRYPTO_SEC_CFG);
	sec_cfg = (val & 0xF0000000) | (CRYPTO_METHOD_MD5 << 16) |  (64 & 0xFFFF); 
	tls_reg_write32(HR_CRYPTO_SEC_CFG, sec_cfg);
	tls_reg_write32(HR_CRYPTO_SHA1_DIGEST0, md->md5.state[0]);
	tls_reg_write32(HR_CRYPTO_SHA1_DIGEST1, md->md5.state[1]);
	tls_reg_write32(HR_CRYPTO_SHA1_DIGEST2, md->md5.state[2]);
	tls_reg_write32(HR_CRYPTO_SHA1_DIGEST3, md->md5.state[3]);
	tls_reg_write32(HR_CRYPTO_SEC_CTRL, 0x1);//start crypto
	while (!crypto_complete)
	{

	}
	crypto_complete = 0;
	for (i = 0; i < 4; i++) {
		val = tls_reg_read32(HR_CRYPTO_SHA1_DIGEST0 + (4*i));
		md->md5.state[i] = val;
	}
}

 
/**
 * @brief			This function initializes Message-Diggest context for usage in MD5 algorithm, starts a new MD5 operation and writes a new Digest Context. 
 *				This function begins a MD5 Message-Diggest Algorithm, i.e. fills the psDigestContext_t structure pointed to by md with necessary data. 
 *				MD5 is the algorithm which takes as input a message of arbitrary length and produces as output a 128-bit "fingerprint" or "message digest" of the input.
 *				It is conjectured that it is computationally infeasible to produce two messages having the same message digest,
 *				or to produce any message having a given prespecified target message digest.
 *
 * @param[in]		md		MD5 Digest Context. 
 *
 * @return		None
 *
 * @note			None
 */
void tls_crypto_md5_init(psDigestContext_t * md) {
	md->md5.state[0] = 0x67452301UL;
	md->md5.state[1] = 0xefcdab89UL;
	md->md5.state[2] = 0x98badcfeUL;
	md->md5.state[3] = 0x10325476UL;
	md->md5.curlen = 0;
#ifdef HAVE_NATIVE_INT64
	md->md5.length = 0;
#else
	md->md5.lengthHi = 0;
	md->md5.lengthLo = 0;
#endif /* HAVE_NATIVE_INT64 */
}


/**
 * @brief			Process a message block using MD5 algorithm.
 *				This function performs a MD5 block update operation. It continues an MD5 message-digest operation,
 *				by processing InputLen-byte length message block pointed to by buf, and by updating the MD5 context pointed to by md. 
 *				This function may be called as many times as necessary, so the message may be processed in blocks.
 *
 * @param[in]		md		MD5 Digest Context. 
 * @param[in]  	buf 		InputLen-byte length message block
 * @param[in]  	len 		The buf 's length 
 *
 * @return		None
 *
 * @note			None
 */
void tls_crypto_md5_update(psDigestContext_t *md, const unsigned char *buf, u32 len)
{
	u32 n;

	while (len > 0) {
		n = min(len, (64 - md->md5.curlen));
		memcpy(md->md5.buf + md->md5.curlen, buf, (size_t)n);
		md->md5.curlen	+= n;
		buf				+= n;
		len				-= n;

/*
		is 64 bytes full?
 */
		if (md->md5.curlen == 64) {
			hd_md5_compress(md);
#ifdef HAVE_NATIVE_INT64
			md->md5.length += 512;
#else
			n = (md->md5.lengthLo + 512) & 0xFFFFFFFFL;
			if (n < md->md5.lengthLo) {
				md->md5.lengthHi++;
			}
			md->md5.lengthLo = n;
#endif /* HAVE_NATIVE_INT64 */
			md->md5.curlen = 0;
		}
	}
}

/**
 * @brief			This function ends a MD5 operation and produces a Message-Digest.
 *				This function finalizes MD5 algorithm, i.e. ends an MD5 Message-Digest operation, 
 *				writing the Message-Digest in the 16-byte buffer pointed to by hash in according to the information stored in context. 
 *
 * @param[in]		md		MD5 Digest Context. 
 * @param[in]		hash 	the Message-Digest
 *
 * @retval  		16  		success, return the hash size.
 * @retval  		<0   	failed  
 *
 * @note			None
 */
s32 tls_crypto_md5_final(psDigestContext_t * md, unsigned char *hash)
{
	s32 i;
	u32 val;
#ifndef HAVE_NATIVE_INT64
	u32	n;
#endif

//	psAssert(md != NULL);
	if (hash == NULL) {
		psTraceCrypto("NULL hash storage passed to psMd5Final\n");
		return PS_ARG_FAIL;
	}

/*
	increase the length of the message
 */
#ifdef HAVE_NATIVE_INT64
	md->md5.length += md->md5.curlen << 3;
#else
	n = (md->md5.lengthLo + (md->md5.curlen << 3)) & 0xFFFFFFFFL;
	if (n < md->md5.lengthLo) {
		md->md5.lengthHi++;
	}
	md->md5.lengthHi += (md->md5.curlen >> 29);
	md->md5.lengthLo = n;
#endif /* HAVE_NATIVE_INT64 */

/*
	append the '1' bit
 */
	md->md5.buf[md->md5.curlen++] = (unsigned char)0x80;

/*
	if the length is currently above 56 bytes we append zeros then compress.
	Then we can fall back to padding zeros and length encoding like normal.
 */
	if (md->md5.curlen > 56) {
		while (md->md5.curlen < 64) {
			md->md5.buf[md->md5.curlen++] = (unsigned char)0;
		}
		hd_md5_compress(md);
		md->md5.curlen = 0;
	}

/*
	pad upto 56 bytes of zeroes
 */
	while (md->md5.curlen < 56) {
		md->md5.buf[md->md5.curlen++] = (unsigned char)0;
	}
/*
	store length
 */
#ifdef HAVE_NATIVE_INT64
	STORE64L(md->md5.length, md->md5.buf+56);
#else
	STORE32L(md->md5.lengthLo, md->md5.buf+56);
	STORE32L(md->md5.lengthHi, md->md5.buf+60);
#endif /* HAVE_NATIVE_INT64 */
	hd_md5_compress(md);

/*
	copy output
 */
	for (i = 0; i < 4; i++) {
		val = tls_reg_read32(HR_CRYPTO_SHA1_DIGEST0 + (4*i));
		STORE32L(val, hash+(4*i));
	}
	memset(md, 0x0, sizeof(psDigestContext_t));
	return MD5_HASH_SIZE;
}

static void rsaMonMulSetLen(const u32 len)
{
    RSAN = len;
}
static void rsaMonMulWriteMc(const u32 mc)
{
	u32 val = 0;
    RSAMC = mc;
	val = RSAMC;
	if(val == mc)
	{
		val = 1;
		return;
	}
}
static void rsaMonMulWriteA(const u32 *const in)
{
    memcpy((u32*)&RSAXBUF, in, RSAN * sizeof(u32));
}
static void rsaMonMulWriteB(const u32 *const in)
{
    memcpy((u32*)&RSAYBUF, in, RSAN * sizeof(u32));
}
static void rsaMonMulWriteM(const u32 *const in)
{
    memcpy((u32*)&RSAMBUF, in, RSAN * sizeof(u32));
}
static void rsaMonMulReadA(u32 *const in)
{
    memcpy(in, (u32*)&RSAXBUF, RSAN * sizeof(u32));
}
static void rsaMonMulReadB(u32 *const in)
{
    memcpy(in, (u32*)&RSAYBUF, RSAN * sizeof(u32));
}
static void rsaMonMulReadD(u32 *const in)
{
    memcpy(in, (u32*)&RSADBUF, RSAN * sizeof(u32));
}
static int rsaMulModRead(unsigned char w, pstm_int * a)
{
	u32 in[64];
	int err = 0;
	memset(in, 0, 64 * sizeof(u32));
	switch(w)
	{
		case 'A':
			rsaMonMulReadA(in);
			break;
		case 'B':
			rsaMonMulReadB(in);
			break;
		case 'D':
			rsaMonMulReadD(in);
			break;
	}
	pstm_reverse((unsigned char *)in, RSAN * sizeof(u32));
	/* this a should be initialized outside. */
	//if ((err = pstm_init_for_read_unsigned_bin(NULL, a, RSAN * sizeof(u32) + sizeof(pstm_int))) != ERR_CRY_OK){
	//	return err;
	//}
	if ((err = pstm_read_unsigned_bin(a, (unsigned char *)in, RSAN * sizeof(u32))) != ERR_CRY_OK) {
		pstm_clear(a);
		return err;
	}
	return 0;
}
static void rsaMulModWrite(unsigned char w, pstm_int * a)
{
	u32 in[64];
	memset(in, 0, 64 * sizeof(u32));
	pstm_to_unsigned_bin_nr(NULL, a, (unsigned char*)in);
	switch(w)
	{
		case 'A':
			rsaMonMulWriteA(in);
			break;
		case 'B':
			rsaMonMulWriteB(in);
			break;
		case 'M':
			rsaMonMulWriteM(in);
			break;
	}
}
static void rsaMonMulAA(void)
{
    RSACON = 0x2c;

    while (!crypto_complete)
    {

    }
    crypto_complete = 0;
}
static void rsaMonMulDD(void)
{
    RSACON = 0x20;

    while (!crypto_complete)
    {

    }
    crypto_complete = 0;
}
static void rsaMonMulAB(void)
{
    RSACON = 0x24;

    while (!crypto_complete)
    {

    }
    crypto_complete = 0;
}
static void rsaMonMulBD(void)
{
    RSACON = 0x28;

    while (!crypto_complete)
    {

    }
    crypto_complete = 0;
}
/******************************************************************************
compute mc, s.t. mc * in = 0xffffffff
******************************************************************************/
static void rsaCalMc(u32 *mc, const u32 in)
{
    u32 y = 1;
	u32 i = 31;
	u32 left = 1;
	u32 right = 0;
    for(i = 31; i != 0; i--)
	{
		left <<= 1;										/* 2^(i-1) */
		right = (in * y) & left;                        /* (n*y) mod 2^i */
		if( right )
		{
			y += left;
		}
	}
    *mc =  ~y + 1;
}


/**
 * @brief			This function implements the large module power multiplication algorithm.
 *				res = a**e (mod n)  
 *
 * @param[in]		a 		Pointer to a bignumber. 
 * @param[in]		e 		Pointer to a bignumber.
 * @param[in]  	n 		Pointer to a bignumber.
 * @param[out]  	res 		Pointer to the result bignumber.
 *
 * @retval  		0  		success 
 * @retval  		other   	failed  
 *
 * @note			None
 */
int tls_crypto_exptmod(pstm_int *a, pstm_int *e, pstm_int *n, pstm_int *res)
{
	int i = 0;
	u32 k = 0, mc = 0, dp0;
	u8 monmulFlag = 0;
	pstm_int R, X, Y;

	tls_fls_sem_lock();
	pstm_init(NULL, &X);
	pstm_init(NULL, &Y);
	pstm_init(NULL, &R);
	k = pstm_count_bits(n);//n->used * DIGIT_BIT;//pstm_count_bits(n);
	k = ((k / 32) + (k % 32 > 0 ? 1 : 0)) * 32;
	pstm_set(&Y, k);
	pstm_set(&X, 2);
	pstm_exptmod(NULL, &X, &Y, n, &R); //R = 2^k % n
	//pstm_set(&Y, 1);
	pstm_mulmod(NULL, a, &R, n, &X); //X = A * R
	pstm_copy(&R, &Y);
	if(n->used > 1)
		dp0 = 0xFFFFFFFF & ((n->dp[0]) | (u32)(n->dp[1] << DIGIT_BIT));
	else
		dp0 = n->dp[0];
	rsaCalMc(&mc, dp0);
	k = pstm_count_bits(n);
	rsaMonMulSetLen(k/32 + (k%32 == 0 ? 0 : 1));
	rsaMonMulWriteMc(mc);
	rsaMulModWrite('M', n);
	rsaMulModWrite('B', &X);
	rsaMulModWrite('A', &Y);
	k = pstm_count_bits(e);
	for(i=k-1;i>=0;i--){
		//montMulMod(&Y, &Y, n, &Y);
		//if(pstm_get_bit(e, i))
		//	montMulMod(&Y, &X, n, &Y);
            if(monmulFlag == 0)
            {
                rsaMonMulAA();
                monmulFlag = 1;
            }
            else
            {
                rsaMonMulDD();
                monmulFlag = 0;
            }

            if(pstm_get_bit(e, i))
            {
                if(monmulFlag == 0)
                {
                    rsaMonMulAB();
                    monmulFlag = 1;
                }
                else
                {
                    rsaMonMulBD();
                    monmulFlag = 0;
                }
            }
	}
	pstm_set(&R, 1);
	rsaMulModWrite('B', &R);
	//montMulMod(&Y, &R, n, res);
	if(monmulFlag == 0)
	{
	    rsaMonMulAB();
	    rsaMulModRead('D', res);
	}
	else
	{
	    rsaMonMulBD();
	    rsaMulModRead('A', res);
	}
	pstm_clamp(res);
	pstm_clear(&X);
	pstm_clear(&Y);
	pstm_clear(&R);
	tls_fls_sem_unlock();

	return 0;
}


/**
 * @brief			This function initializes the encryption module.
 *
 * @param		None
 *
 * @return  		None
 *
 * @note			None
 */
void tls_crypto_init(void)
{
	NVIC_ClearPendingIRQ(RSA_IRQn);
	NVIC_ClearPendingIRQ(CRYPTION_IRQn);
	tls_irq_enable(RSA_IRQn);
	tls_irq_enable(CRYPTION_IRQn);
}

//#define TEST_ALL_CRYPTO

#ifdef TEST_ALL_CRYPTO
#define KEY_LEN 16
#define CHAR_LEN 16
#define MAX_CHAR_LEN   2048
int test_rc4(char* key, int keylen, char* pt, int len, u8 mode){
	int ret = -1;
	int i = 0, j = 0;
	psCipherContext_t  ctx;
	unsigned char *ct = NULL;
	ct = tls_mem_alloc(len);
	if(ct == NULL){
		goto out;
	}

	if(mode == 0)//software encrypt
	{
		psArc4Init(&ctx, key, keylen);
		if(psArc4(&ctx, pt, ct, len) < 0)
		{
			goto out;
		}
		if(tls_crypto_rc4_init(&ctx, key, keylen) < 0)
		{
			goto out;
		}
		if(tls_crypto_rc4(&ctx, ct, ct, len) < 0)
		{
			goto out;
		}
	}
	else//hardware encrypt
	{
		if(tls_crypto_rc4_init(&ctx, key, keylen) < 0)
		{
			goto out;
		}
		if(tls_crypto_rc4(&ctx, pt, ct, len) < 0)
		{
			goto out;
		}
		
		psArc4Init(&ctx, key, keylen);
		if(psArc4(&ctx, ct, ct, len) < 0)
		{
			goto out;
		}
	}

	if(memcmp(pt, ct, len))
	{
		goto out;
	}
	ret = 0;

out:
	if(ct)
		tls_mem_free(ct);
	return ret;
}

int test_aes_ctr(char* key, int keylen, char * IV, char* pt, int len, u8 mode){
	int ret = -1;
	psCipherContext_t  ctx;
	unsigned char *ct = NULL;
	
	ct = tls_mem_alloc(MAX_CHAR_LEN);
	if(ct == NULL){
		goto out;
	}
	
	if(mode == 0)//software encrypt
	{
		if(psAesInit(&ctx, IV, key, keylen) < 0)
		{
			goto out;
		}
		if(psAesEncrypt_CTR(&ctx, pt, ct, len) < 0)
		{
			goto out;
		}
		
		if(tls_crypto_aes_init(&ctx, IV, key, keylen, CRYPTO_MODE_CTR) != 0)
		{
			goto out;
		}
		if(tls_crypto_aes_encrypt_decrypt(&ctx, ct, ct, len, CRYPTO_WAY_DECRYPT) < 0)
		{
			goto out;
		}
	}
	else//hardware encrypt
	{
		if(tls_crypto_aes_init(&ctx, IV, key, keylen, CRYPTO_MODE_CTR) != 0)
		{
			goto out;
		}
		if(tls_crypto_aes_encrypt_decrypt(&ctx, pt, ct, len, CRYPTO_WAY_ENCRYPT) < 0)
		{
			goto out;
		}
		
		if(psAesInit(&ctx, IV, key, keylen) < 0)
		{
			goto out;
		}
		if(psAesEncrypt_CTR(&ctx, ct, ct, len) < 0)
		{
			goto out;
		}
	}
	if(memcmp(pt, ct, len))
	{
		goto out;
	}
	ret = 0;

out:
	if(ct)
		tls_mem_free(ct);
	return ret;
}
int test_aes_cbc(char* key, int keylen, char * IV, char* pt, int len, u8 mode){
	int ret = -1;
	psCipherContext_t  ctx;
	unsigned char *ct = NULL;
	
	ct = tls_mem_alloc(MAX_CHAR_LEN);
	if(ct == NULL){
		goto out;
	}
	
	if(mode == 0)//software encrypt
	{
		if(psAesInit(&ctx, IV, key, keylen) < 0)
		{
			goto out;
		}
		if(psAesEncrypt(&ctx, pt, ct, len) < 0)
		{
			goto out;
		}
		
		if(tls_crypto_aes_init(&ctx, IV, key, keylen, CRYPTO_MODE_CBC) != 0)
		{
			goto out;
		}
		if(tls_crypto_aes_encrypt_decrypt(&ctx, ct, ct, len, CRYPTO_WAY_DECRYPT) < 0)
		{
			goto out;
		}
	}
	else//hardware encrypt
	{
		if(tls_crypto_aes_init(&ctx, IV, key, keylen, CRYPTO_MODE_CBC) != 0)
		{
			goto out;
		}
		if(tls_crypto_aes_encrypt_decrypt(&ctx, pt, ct, len, CRYPTO_WAY_ENCRYPT) < 0)
		{
			goto out;
		}
		
		if(psAesInit(&ctx, IV, key, keylen) < 0)
		{
			goto out;
		}
		if(psAesDecrypt(&ctx, ct, ct, len) < 0)
		{
			goto out;
		}
	}
	if(memcmp(pt, ct, len))
	{
		goto out;
	}
	ret = 0;

out:
	if(ct)
		tls_mem_free(ct);
	return ret;
}
int test_aes_ecb(char* key, int keylen, char * IV, char* pt, int len, u8 mode){
	int ret = -1;
	psCipherContext_t  ctx;
	unsigned char *ct = NULL;
	
	ct = tls_mem_alloc(MAX_CHAR_LEN);
	if(ct == NULL){
		goto out;
	}
	
	if(mode == 0)//software encrypt
	{
		if(psAesInit(&ctx, IV, key, keylen) < 0)
		{
			goto out;
		}
		if(psAesEncrypt_ECB(&ctx, pt, ct, len) < 0)
		{
			goto out;
		}
		
		if(tls_crypto_aes_init(&ctx, IV, key, keylen, CRYPTO_MODE_ECB) != 0)
		{
			goto out;
		}
		if(tls_crypto_aes_encrypt_decrypt(&ctx, ct, ct, len, CRYPTO_WAY_DECRYPT) < 0)
		{
			goto out;
		}
	}
	else//hardware encrypt
	{
		if(tls_crypto_aes_init(&ctx, IV, key, keylen, CRYPTO_MODE_ECB) != 0)
		{
			goto out;
		}
		if(tls_crypto_aes_encrypt_decrypt(&ctx, pt, ct, len, CRYPTO_WAY_ENCRYPT) < 0)
		{
			goto out;
		}
		
		if(psAesInit(&ctx, IV, key, keylen) < 0)
		{
			goto out;
		}
		if(psAesDecrypt_ECB(&ctx, ct, ct, len) < 0)
		{
			goto out;
		}
	}
	if(memcmp(pt, ct, len))
	{
		goto out;
	}
	ret = 0;

out:
	if(ct)
		tls_mem_free(ct);
	return ret;
}
int test_3des_cbc(char* key, int keylen, char * IV, char* pt, int len, u8 mode){
	int ret=-1;
	psCipherContext_t  ctx;
	unsigned char *ct = NULL;
	
	ct = tls_mem_alloc(MAX_CHAR_LEN);
	if(ct == NULL){
		goto out;
	}
	

	if(mode == 0)//software encrypt
	{
		if(psDes3Init(&ctx, IV, key, keylen) < 0)
		{
			goto out;
		}
		if(psDes3Encrypt(&ctx, pt, ct, len) < 0)
		{
			goto out;
		}
		if(tls_crypto_3des_init(&ctx, IV, key, keylen, CRYPTO_MODE_CBC) != 0)
		{
			goto out;
		}
		
		if(tls_crypto_3des_encrypt_decrypt(&ctx, ct, ct, len, CRYPTO_WAY_DECRYPT) < 0)
		{
			goto out;
		}
	}
	else//hardware encrypt
	{
		if(tls_crypto_3des_init(&ctx, IV, key, keylen, CRYPTO_MODE_CBC) != 0)
		{
			goto out;
		}
		
		if(tls_crypto_3des_encrypt_decrypt(&ctx, pt, ct, len, CRYPTO_WAY_ENCRYPT) < 0)
		{
			goto out;
		}
		
		if(psDes3Init(&ctx, IV, key, keylen) < 0)
		{
			goto out;
		}
		if(psDes3Decrypt(&ctx, ct, ct, len) < 0)
		{
			goto out;
		}
	}
	if(memcmp(pt, ct, len))
	{
		goto out;
	}
	ret = 0;
out:
	if(ct)
		tls_mem_free(ct);
}
int test_3des_ecb(char* key, int keylen, char * IV, char* pt, int len, u8 mode){
	int ret=-1;
	psCipherContext_t  ctx;
	unsigned char *ct = NULL;
	
	ct = tls_mem_alloc(MAX_CHAR_LEN);
	if(ct == NULL){
		goto out;
	}
	

	if(mode == 0)//software encrypt
	{
		if(psDes3Init(&ctx, IV, key, keylen) < 0)
		{
			goto out;
		}
		if(psDes3Encrypt_ECB(&ctx, pt, ct, len) < 0)
		{
			goto out;
		}
		if(tls_crypto_3des_init(&ctx, IV, key, keylen, CRYPTO_MODE_ECB) != 0)
		{
			goto out;
		}
		
		if(tls_crypto_3des_encrypt_decrypt(&ctx, ct, ct, len, CRYPTO_WAY_DECRYPT) < 0)
		{
			goto out;
		}
	}
	else//hardware encrypt
	{
		if(tls_crypto_3des_init(&ctx, IV, key, keylen, CRYPTO_MODE_ECB) != 0)
		{
			goto out;
		}
		
		if(tls_crypto_3des_encrypt_decrypt(&ctx, pt, ct, len, CRYPTO_WAY_ENCRYPT) < 0)
		{
			goto out;
		}
		
		if(psDes3Init(&ctx, IV, key, keylen) < 0)
		{
			goto out;
		}
		if(psDes3Decrypt_ECB(&ctx, ct, ct, len) < 0)
		{
			goto out;
		}
	}
	if(memcmp(pt, ct, len))
	{
		goto out;
	}
	ret = 0;
out:
	if(ct)
		tls_mem_free(ct);
}
int test_des_ecb(char* key, int keylen, char * IV, char* pt, int len, u8 mode){
	int ret=-1;
	psCipherContext_t  ctx;
	unsigned char *ct = NULL;
	
	ct = tls_mem_alloc(MAX_CHAR_LEN);
	if(ct == NULL){
		goto out;
	}
	

	if(mode == 0)//software encrypt
	{
		if(psDesInit(&ctx, IV, key, keylen) < 0)
		{
			goto out;
		}
		if(psDesEncrypt_ECB(&ctx, pt, ct, len) < 0)
		{
			goto out;
		}
		if(tls_crypto_des_init(&ctx, IV, key, keylen, CRYPTO_MODE_ECB) != 0)
		{
			goto out;
		}
		
		if(tls_crypto_des_encrypt_decrypt(&ctx, ct, ct, len, CRYPTO_WAY_DECRYPT) < 0)
		{
			goto out;
		}
	}
	else//hardware encrypt
	{
		if(tls_crypto_des_init(&ctx, IV, key, keylen, CRYPTO_MODE_ECB) != 0)
		{
			goto out;
		}
		
		if(tls_crypto_des_encrypt_decrypt(&ctx, pt, ct, len, CRYPTO_WAY_ENCRYPT) < 0)
		{
			goto out;
		}
		
		if(psDesInit(&ctx, IV, key, keylen) < 0)
		{
			goto out;
		}
		if(psDesDecrypt_ECB(&ctx, ct, ct, len) < 0)
		{
			goto out;
		}
	}
	if(memcmp(pt, ct, len))
	{
		goto out;
	}
	ret = 0;
out:
	if(ct)
		tls_mem_free(ct);
}
int test_des_cbc(char* key, int keylen, char * IV, char* pt, int len, u8 mode){
	int ret=-1;
	psCipherContext_t  ctx;
	unsigned char *ct = NULL;
	
	ct = tls_mem_alloc(MAX_CHAR_LEN);
	if(ct == NULL){
		goto out;
	}
	

	if(mode == 0)//software encrypt
	{
		if(psDesInit(&ctx, IV, key, keylen) < 0)
		{
			goto out;
		}
		if(psDesEncrypt(&ctx, pt, ct, len) < 0)
		{
			goto out;
		}
		if(tls_crypto_des_init(&ctx, IV, key, keylen, CRYPTO_MODE_CBC) != 0)
		{
			goto out;
		}
		
		if(tls_crypto_des_encrypt_decrypt(&ctx, ct, ct, len, CRYPTO_WAY_DECRYPT) < 0)
		{
			goto out;
		}
	}
	else//hardware encrypt
	{
		if(tls_crypto_des_init(&ctx, IV, key, keylen, CRYPTO_MODE_CBC) != 0)
		{
			goto out;
		}
		
		if(tls_crypto_des_encrypt_decrypt(&ctx, pt, ct, len, CRYPTO_WAY_ENCRYPT) < 0)
		{
			goto out;
		}
		
		if(psDesInit(&ctx, IV, key, keylen) < 0)
		{
			goto out;
		}
		if(psDesDecrypt(&ctx, ct, ct, len) < 0)
		{
			goto out;
		}
	}
	if(memcmp(pt, ct, len))
	{
		goto out;
	}
	ret = 0;
out:
	if(ct)
		tls_mem_free(ct);
}
int test_sha1(unsigned char *pt, int len){
	int i = 0, ret = -1;
	psDigestContext_t  ctx;
	unsigned char *ct = NULL, *cth = NULL;
	ct = tls_mem_alloc(20);
	if(ct == NULL){
		goto out;
	}
	cth = tls_mem_alloc(20);
	if(cth == NULL){
		goto out;
	}
	psSha1Init(&ctx);
	psSha1Update(&ctx, pt, len);
	psSha1Final(&ctx, ct);
	
	tls_crypto_sha1_init(&ctx);
	tls_crypto_sha1_update(&ctx, pt, len);
	tls_crypto_sha1_final(&ctx, cth);
	if(memcmp(ct, cth, 20) != 0)
		goto out;
	ret = 0;
out:
	if(ct)
		tls_mem_free(ct);
	if(cth)
		tls_mem_free(cth);
	return ret;
}
int test_md5(unsigned char *pt, int len){
	int i = 0, ret = -1;
	psDigestContext_t  ctx;
	unsigned char *ct = NULL, *cth = NULL;
	ct = tls_mem_alloc(MD5_HASH_SIZE);
	if(ct == NULL){
		goto out;
	}
	cth = tls_mem_alloc(MD5_HASH_SIZE);
	if(cth == NULL){
		goto out;
	}
	psMd5Init(&ctx);
	psMd5Update(&ctx, pt, len);
	psMd5Final(&ctx, ct);
	
	tls_crypto_md5_init(&ctx);
	tls_crypto_md5_update(&ctx, pt, len);
	tls_crypto_md5_final(&ctx, cth);
	if(memcmp(ct, cth, MD5_HASH_SIZE) != 0)
		goto out;
	ret = 0;
out:
	if(ct)
		tls_mem_free(ct);
	if(cth)
		tls_mem_free(cth);
	return ret;
}

int test_crc(u32 key, unsigned char *pt, int len, CRYPTO_CRC_TYPE crc_type, u8 mode){
	int i = 0, ret = -1;
	u32 crc_result = 0, crc_result1 = 0;
	psCrcContext_t ctx;
	
	tls_crypto_crc_init(&ctx, key, crc_type, mode);
	tls_crypto_crc_update(&ctx, pt, len);
	tls_crypto_crc_update(&ctx, pt, len);
	tls_crypto_crc_update(&ctx, pt, len);
	tls_crypto_crc_final(&ctx, &crc_result);
	
	tls_crc_init(&ctx, key, crc_type, mode);
	tls_crc_update(&ctx, pt, len);
	tls_crc_update(&ctx, pt, len);
	tls_crc_update(&ctx, pt, len);
	tls_crc_final(&ctx, &crc_result1);
	if(crc_result != crc_result1)
		goto out;
	ret = 0;
out:
	return ret;
}

/******************************************************************************
Generate random number
******************************************************************************/
static void rsaRnd(u32 *res, const u32 len)
{
    u32 i = len;
    u32 *pRes = res;

    //RNGCTR = 1;

    while(i--)
    {
        //while(RNGSTR==0)
        //{}
        *pRes++ = rand();//RNGOUT;
    }
}

int test_crc_md5_sha1(void)
{
	int ret = -1;
	u32 key = 0xFFFFFFFF;
	int len = 32;
	CRYPTO_CRC_TYPE crc_type=0;
	u8 mode=3;
	u32 crc_result = 0, crc_result1 = 0;
	psCrcContext_t h_crc8_ctx;
	psCrcContext_t crc8_ctx;
	psDigestContext_t  h_sha1_ctx;
	psDigestContext_t  sha1_ctx;
	psDigestContext_t  h_md5_ctx;
	psDigestContext_t  md5_ctx;
	unsigned char *pt = NULL;
	unsigned char *ct = NULL, *cth = NULL;
	unsigned char *md5_ct = NULL, *md5_cth = NULL;
	ct = tls_mem_alloc(20);
	if(ct == NULL){
		goto out;
	}
	cth = tls_mem_alloc(20);
	if(cth == NULL){
		goto out;
	}
	md5_ct = tls_mem_alloc(MD5_HASH_SIZE);
	if(md5_ct == NULL){
		goto out;
	}
	md5_cth = tls_mem_alloc(MD5_HASH_SIZE);
	if(md5_cth == NULL){
		goto out;
	}
	pt = tls_mem_alloc(MAX_CHAR_LEN);
	if(pt == NULL){
		goto out;
	}
	for(crc_type = 0; crc_type < 4; crc_type++)
	{
		for(mode = 0; mode < 4; mode++)
		{
			psMd5Init(&md5_ctx);
			tls_crypto_md5_init(&h_md5_ctx);
			tls_crypto_crc_init(&h_crc8_ctx, key, crc_type, mode);
			tls_crc_init(&crc8_ctx, key, crc_type, mode);
			psSha1Init(&sha1_ctx);
			tls_crypto_sha1_init(&h_sha1_ctx);
			
			for(len = 0x100; len < MAX_CHAR_LEN; len+=103)
			{
				rsaRnd(pt, len/sizeof(u32));
				psMd5Update(&md5_ctx, pt, len);
				tls_crypto_crc_update(&h_crc8_ctx, pt, len);
				tls_crypto_md5_update(&h_md5_ctx, pt, len);
				tls_crypto_sha1_update(&h_sha1_ctx, pt, len);
				tls_crc_update(&crc8_ctx, pt, len);
				psSha1Update(&sha1_ctx, pt, len);
			}
			tls_crypto_crc_final(&h_crc8_ctx, &crc_result);
			tls_crc_final(&crc8_ctx, &crc_result1);
			tls_crypto_md5_final(&h_md5_ctx, md5_cth);
			tls_crypto_sha1_final(&h_sha1_ctx, cth);
			psSha1Final(&sha1_ctx, ct);
			psMd5Final(&md5_ctx, md5_ct);

			if(crc_result != crc_result1)
				goto out;
			if(memcmp(ct, cth, 20) != 0)
				goto out;
			if(memcmp(md5_ct, md5_cth, MD5_HASH_SIZE) != 0)
				goto out;
		}
	}
	ret = 0;
out:
	if(ct)
		tls_mem_free(ct);
	if(cth)
		tls_mem_free(cth);
	if(md5_ct)
		tls_mem_free(md5_ct);
	if(md5_cth)
		tls_mem_free(md5_cth);
	if(pt)
		tls_mem_free(pt);
	return ret;
}

int test_crc_all(void)
{
	int ret = -1;
	u32 key = 0xFFFFFFFF;
	int len = 32;
	CRYPTO_CRC_TYPE crc_type=0;
	u8 mode;
	unsigned char *pt = NULL;
	pt = tls_mem_alloc(MAX_CHAR_LEN);
	if(pt == NULL){
		goto out;
	}
	for(len = 0x100; len < MAX_CHAR_LEN; len+=8)
	{
		for(crc_type = 0; crc_type < 4; crc_type++)
		{
			for(mode = 0; mode < 4; mode++)
			{
				rsaRnd(pt, len/sizeof(u32));
				if(test_crc(key, pt, len, crc_type, mode))
				{
					goto out;
				}
			}
		}
	}
	ret = 0;
out:
	if(pt)
		tls_mem_free(pt);
	return ret;
}
int test_rc4_all(void)
{
	int ret = -1;
	int keylen = 16, len = 16;
	unsigned char key[16] = "abcdefghijklmnop";
	unsigned char *pt = NULL;
	pt = tls_mem_alloc(MAX_CHAR_LEN);
	if(pt == NULL){
		goto out;
	}
	for(len = 16; len < MAX_CHAR_LEN; len+=8)
	{
		rsaRnd(pt, len/sizeof(u32));
		if(test_rc4(key, keylen, pt, len, 0))
		{
			goto out;
		}
		rsaRnd(pt, len/sizeof(u32));
		if(test_rc4(key, keylen, pt, len, 1))
		{
			goto out;
		}
	}
	
	ret = 0;
out:
	if(pt)
		tls_mem_free(pt);
	return ret;
}
int test_sha1_all(void)
{
	int ret = -1;
	int len = 16;
	unsigned char *pt = NULL;
	pt = tls_mem_alloc(MAX_CHAR_LEN);
	if(pt == NULL){
		goto out;
	}
	for(len = 16; len < MAX_CHAR_LEN; len+=8)
	{
		rsaRnd(pt, len/sizeof(u32));
		if(test_sha1( pt, len))
		{
			goto out;
		}
	}
	
	ret = 0;
out:
	if(pt)
		tls_mem_free(pt);
	return ret;
}
int test_md5_all(void)
{
	int ret = -1;
	int len = 16;
	unsigned char *pt = NULL;
	pt = tls_mem_alloc(MAX_CHAR_LEN);
	if(pt == NULL){
		goto out;
	}
	for(len = 16; len < MAX_CHAR_LEN; len+=8)
	{
		rsaRnd(pt, len/sizeof(u32));
		if(test_md5( pt, len))
		{
			goto out;
		}
	}
	
	ret = 0;
out:
	if(pt)
		tls_mem_free(pt);
	return ret;
}
int test_aes_ctr_all(void)
{
	int ret = -1;
	int keylen = 16, len = 16;
	unsigned char key[16] = "abcdefghijklmnop";
	unsigned char IV[16] = "bcdefghijklmnopq";
	unsigned char *pt = NULL;
	pt = tls_mem_alloc(MAX_CHAR_LEN);
	if(pt == NULL){
		goto out;
	}
	for(len = 16; len < MAX_CHAR_LEN; len+=16)
	{
		rsaRnd(pt, len/sizeof(u32));
		if(test_aes_ctr(key, keylen, IV, pt, len, 0))
		{
			goto out;
		}
		rsaRnd(pt, len/sizeof(u32));
		if(test_aes_ctr(key, keylen, IV, pt, len, 1))
		{
			goto out;
		}
	}
	
	ret = 0;
out:
	if(pt)
		tls_mem_free(pt);
	return ret;
}
int test_aes_cbc_all(void)
{
	int ret = -1;
	int keylen = 16, len = 16;
	unsigned char key[16] = "abcdefghijklmnop";
	unsigned char IV[16] = "bcdefghijklmnopq";
	unsigned char *pt = NULL;
	pt = tls_mem_alloc(MAX_CHAR_LEN);
	if(pt == NULL){
		goto out;
	}
	for(len = 16; len < MAX_CHAR_LEN; len+=16)
	{
		rsaRnd(pt, len/sizeof(u32));
		if(test_aes_cbc(key, keylen, IV, pt, len, 0))
		{
			goto out;
		}
		rsaRnd(pt, len/sizeof(u32));
		if(test_aes_cbc(key, keylen, IV, pt, len, 1))
		{
			goto out;
		}
	}
	
	ret = 0;
out:
	if(pt)
		tls_mem_free(pt);
	return ret;
}
int test_aes_ecb_all(void)
{
	int ret = -1;
	int keylen = 16, len = 16;
	unsigned char key[16] = "abcdefghijklmnop";
	unsigned char IV[16] = "bcdefghijklmnopq";
	unsigned char *pt = NULL;
	pt = tls_mem_alloc(MAX_CHAR_LEN);
	if(pt == NULL){
		goto out;
	}
	for(len = 16; len < MAX_CHAR_LEN; len+=16)
	{
		rsaRnd(pt, len/sizeof(u32));
		if(test_aes_ecb(key, keylen, IV, pt, len, 0))
		{
			goto out;
		}
		rsaRnd(pt, len/sizeof(u32));
		if(test_aes_ecb(key, keylen, IV, pt, len, 1))
		{
			goto out;
		}
	}
	
	ret = 0;
out:
	if(pt)
		tls_mem_free(pt);
	return ret;
}
int test_3des_cbc_all(void)
{
	int ret = -1;
	int keylen = DES3_KEY_LEN, len = 8;
	unsigned char key[DES3_KEY_LEN] = "abcdefghijklmnopqrstuvwx";
	unsigned char IV[DES3_IV_LEN] = "bcdefghi";
	unsigned char *pt = NULL;
	pt = tls_mem_alloc(MAX_CHAR_LEN);
	if(pt == NULL){
		goto out;
	}
	for(; len < MAX_CHAR_LEN; len+=8)
	{
		rsaRnd(pt, len/sizeof(u32));
		if(test_3des_cbc(key, keylen, IV, pt, len, 0))
		{
			goto out;
		}
		rsaRnd(pt, len/sizeof(u32));
		if(test_3des_cbc(key, keylen, IV, pt, len, 1))
		{
			goto out;
		}
	}
	
	ret = 0;
out:
	if(pt)
		tls_mem_free(pt);
	return ret;
}
int test_3des_ecb_all(void)
{
	int ret = -1;
	int keylen = DES3_KEY_LEN, len = 8;
	unsigned char key[DES3_KEY_LEN] = "abcdefghijklmnopqrstuvwx";
	unsigned char IV[DES3_IV_LEN] = "bcdefghi";
	unsigned char *pt = NULL;
	pt = tls_mem_alloc(MAX_CHAR_LEN);
	if(pt == NULL){
		goto out;
	}
	for(; len < MAX_CHAR_LEN; len+=8)
	{
		rsaRnd(pt, len/sizeof(u32));
		if(test_3des_ecb(key, keylen, IV, pt, len, 0))
		{
			goto out;
		}
		rsaRnd(pt, len/sizeof(u32));
		if(test_3des_ecb(key, keylen, IV, pt, len, 1))
		{
			goto out;
		}
	}
	
	ret = 0;
out:
	if(pt)
		tls_mem_free(pt);
	return ret;
}
int test_des_ecb_all(void)
{
	int ret = -1;
	int keylen = DES_KEY_LEN, len = 8;
	unsigned char key[DES_KEY_LEN] = "abcdefgh";
	unsigned char IV[DES3_IV_LEN] = "bcdefghi";
	unsigned char *pt = NULL;
	pt = tls_mem_alloc(MAX_CHAR_LEN);
	if(pt == NULL){
		goto out;
	}
	for(; len < MAX_CHAR_LEN; len+=8)
	{
		rsaRnd(pt, len/sizeof(u32));
		if(test_des_ecb(key, keylen, IV, pt, len, 0))
		{
			goto out;
		}
		rsaRnd(pt, len/sizeof(u32));
		if(test_des_ecb(key, keylen, IV, pt, len, 1))
		{
			goto out;
		}
	}
	
	ret = 0;
out:
	if(pt)
		tls_mem_free(pt);
	return ret;
}
int test_des_cbc_all(void)
{
	int ret = -1;
	int keylen = DES_KEY_LEN, len = 8;
	unsigned char key[DES_KEY_LEN] = "abcdefgh";
	unsigned char IV[DES3_IV_LEN] = "bcdefghi";
	unsigned char *pt = NULL;
	pt = tls_mem_alloc(MAX_CHAR_LEN);
	if(pt == NULL){
		goto out;
	}
	for(; len < MAX_CHAR_LEN; len+=8)
	{
		rsaRnd(pt, len/sizeof(u32));
		if(test_des_cbc(key, keylen, IV, pt, len, 0))
		{
			goto out;
		}
		rsaRnd(pt, len/sizeof(u32));
		if(test_des_cbc(key, keylen, IV, pt, len, 1))
		{
			goto out;
		}
	}
	
	ret = 0;
out:
	if(pt)
		tls_mem_free(pt);
	return ret;
}

/*     res = a^e % n      DIGIT_BIT must be 32, or you need to re calc the RSAN value and the mc value  */
int rsaMontExptMod(pstm_int *a, pstm_int *e, pstm_int *n, pstm_int *res)
{
	int i = 0;
	u32 k = 0, mc = 0;
	u8 monmulFlag = 0;
	pstm_int R, X, Y;
	pstm_init(NULL, &X);
	pstm_init(NULL, &Y);
	pstm_init(NULL, &R);
	k = n->used * DIGIT_BIT;//pstm_count_bits(n);
	pstm_set(&Y, k);
	pstm_set(&X, 2);
	pstm_exptmod(NULL, &X, &Y, n, &R); //R = 2^k % n
	//pstm_set(&Y, 1);
	pstm_mulmod(NULL, a, &R, n, &X); //X = A * R
	pstm_copy(&R, &Y);
	
	rsaCalMc(&mc, n->dp[0]);
	rsaMonMulSetLen(n->used);
	rsaMonMulWriteMc(mc);
	rsaMulModWrite('M', n);
	rsaMulModWrite('B', &X);
	rsaMulModWrite('A', &Y);
	k = pstm_count_bits(e);
	for(i=k-1;i>=0;i--){
		//montMulMod(&Y, &Y, n, &Y);
		//if(pstm_get_bit(e, i))
		//	montMulMod(&Y, &X, n, &Y);
            if(monmulFlag == 0)
            {
                rsaMonMulAA();
                monmulFlag = 1;
            }
            else
            {
                rsaMonMulDD();
                monmulFlag = 0;
            }

            if(pstm_get_bit(e, i))
            {
                if(monmulFlag == 0)
                {
                    rsaMonMulAB();
                    monmulFlag = 1;
                }
                else
                {
                    rsaMonMulBD();
                    monmulFlag = 0;
                }
            }
	}
	pstm_set(&R, 1);
	rsaMulModWrite('B', &R);
	//montMulMod(&Y, &R, n, res);
	if(monmulFlag == 0)
	{
	    rsaMonMulAB();
	    rsaMulModRead('D', res);
	}
	else
	{
	    rsaMonMulBD();
	    rsaMulModRead('A', res);
	}
	pstm_clamp(res);
	pstm_clear(&X);
	pstm_clear(&Y);
	pstm_clear(&R);
	return 0;
}

int exptModTest(u32 len){
	u32 * a = NULL;
	u32 * b = NULL;
	u32 * m = NULL;
	
	pstm_int	pa;
	pstm_int	pb;
	pstm_int	pm;
	pstm_int	pres;
	pstm_int	mres;
	int err = -1;
	
	u32 mc = 0;
	a = tls_mem_alloc(len * sizeof(u32));
	if(a == NULL)
		goto out;
	b = tls_mem_alloc(len * sizeof(u32));
	if(b== NULL)
		goto out;
	m = tls_mem_alloc(len * sizeof(u32));
	if(m == NULL)
		goto out;
#if 1
	rsaRnd(a, len);
	rsaRnd(b, len);
	rsaRnd(m, len);
	m[0] |= 0x01;
	a[len-1] = 0;
	b[len-1] = 0;
	b[len-2] = 0;
#else
a[0] = 0x1DD31133;
a[1] = 0xB8A4D048;
a[2] = 0x47713BC4 ;
a[3] = 0x42EB5E0E ;
a[4] = 0x44D6F5FC;
a[5] = 0xF9C80DC7 ;
a[6] = 0x75F2D4DD;
a[7] = 0x2CF39311;
a[8] = 0x25994486;
a[9] = 0xD4B262D1;
a[10] = 0x429992AC;
a[11] = 0xCFE41022;
a[12] = 0x77BFE5F3;
a[13] = 0x71361EBB ;
a[14] = 0x9D5374B1;
a[15] = 0xF49234E7 ;
a[16] = 0x0;
a[17] = 0x0;
a[18] = 0x0;
a[19] = 0x0;
a[20] = 0x0;
a[21] = 0x0;
a[22] = 0x0;
a[23] = 0x0;
a[24] = 0x0;
a[25] = 0x0;
a[26] = 0x0;
a[27] = 0x0;
a[28] = 0x0;
a[29] = 0x0;
a[30] = 0x0;
a[31] = 0x0;
a[32] = 0x0;
a[33] = 0x0;
a[34] = 0x0;
a[35] = 0x0;
a[36] = 0x0;
a[37] = 0x0;
a[38] = 0x0;
a[39] = 0x0;
a[40] = 0x0;
a[41] = 0x0;
a[42] = 0x0;
a[43] = 0x0;
a[44] = 0x0;
a[45] = 0x0;
a[46] = 0x0;
a[47] = 0x0;
a[48] = 0x0;
a[49] = 0x0;
a[50] = 0x0;
a[51] = 0x0;
a[52] = 0x0;
a[53] = 0x0;
a[54] = 0x0;
a[55] = 0x0;
a[56] = 0x0;
a[57] = 0x0;
a[58] = 0x0;
a[59] = 0x0;
a[60] = 0x0;
a[61] = 0x0;
a[62] = 0x0;
a[63] = 0x0;

b[0] = 0x26315342;
b[1] = 0x5E7A4F8D;
b[2] = 0xCAEC5A27;
b[3] = 0xB53E1326;
b[4] = 0x523A7348;
b[5] = 0xC4E2FC4F;
b[6] = 0x9DEE4D75;
b[7] = 0xCD9CE8D5;
b[8] = 0x0;
b[9] = 0x0;
b[10] = 0x0;
b[11] = 0x0;
b[12] = 0x0;
b[13] = 0x0;
b[14] = 0x0;
b[15] = 0x0;
b[16] = 0x0;
b[17] = 0x0;
b[18] = 0x0;
b[19] = 0x0;
b[20] = 0x0;
b[21] = 0x0;
b[22] = 0x0;
b[23] = 0x0;
b[24] = 0x0;
b[25] = 0x0;
b[26] = 0x0;
b[27] = 0x0;
b[28] = 0x0;
b[29] = 0x0;
b[30] = 0x0;
b[31] = 0x0;
b[32] = 0x0;
b[33] = 0x0;
b[34] = 0x0;
b[35] = 0x0;
b[36] = 0x0;
b[37] = 0x0;
b[38] = 0x0;
b[39] = 0x0;
b[40] = 0x0;
b[41] = 0x0;
b[42] = 0x0;
b[43] = 0x0;
b[44] = 0x0;
b[45] = 0x0;
b[46] = 0x0;
b[47] = 0x0;
b[48] = 0x0;
b[49] = 0x0;
b[50] = 0x0;
b[51] = 0x0;
b[52] = 0x0;
b[53] = 0x0;
b[54] = 0x0;
b[55] = 0x0;
b[56] = 0x0;
b[57] = 0x0;
b[58] = 0x0;
b[59] = 0x0;
b[60] = 0x0;
b[61] = 0x0;
b[62] = 0x0;
b[63] = 0x0;

m[0] = 0xfda31a0b;
m[1] = 0x6bc894eb;
m[2] = 0xc79ac381;
m[3] = 0xc2d6bfb0;
m[4] = 0x7af55f47;
m[5] = 0xbfef6a12;
m[6] = 0xb07aa16e;
m[7] = 0xe8517da4;
m[8] = 0xfb313dd3;
m[9] = 0x4023c0e8;
m[10] = 0x14892c0d;
m[11] = 0x3b220767;
m[12] = 0xeeae653e;
m[13] = 0x48a3585b;
m[14] = 0xf54dcfeb;
m[15] = 0x259f881b;
m[16] = 0xab888a5b;
m[17] = 0x385cf671;
m[18] = 0xc0efe32f;
m[19] = 0xb94fe6dc;
m[20] = 0x1ef81224;
m[21] = 0x203faed4;
m[22] = 0x37dcd3f2;
m[23] = 0x59adb9dd;
m[24] = 0x9a696663;
m[25] = 0x9c4234ad;
m[26] = 0x2fe0a674;
m[27] = 0xd61401e2;
m[28] = 0x98a81f0c;
m[29] = 0xb82b62f7;
m[30] = 0xc052b828;
m[31] = 0x47966b41;
m[32] = 0x63238814;
m[33] = 0x87b722aa;
m[34] = 0xcaecdb0c;
m[35] = 0x17faa31c;
m[36] = 0xb116dc97;
m[37] = 0xd96aa8e1;
m[38] = 0x86481396;
m[39] = 0x8adbaeb5;
m[40] = 0x48c7f345;
m[41] = 0xf8a660ed;
m[42] = 0x8f6318f9;
m[43] = 0xc50475f6;
m[44] = 0xb95aeb64;
m[45] = 0x3f5ddf0f;
m[46] = 0x38c2f4e4;
m[47] = 0x8950b200;
m[48] = 0xfc9c54fb;
m[49] = 0xa152967e;
m[50] = 0x41f8aad6;
m[51] = 0xad7ba552;
m[52] = 0x43561858;
m[53] = 0xe77fef0f;
m[54] = 0x3d56023b;
m[55] = 0xcb591817;
m[56] = 0x9d171380;
m[57] = 0x24a0f121;
m[58] = 0x57b0bb2c;
m[59] = 0x705251ee;
m[60] = 0x8324e642;
m[61] = 0x2fb245a0;
m[62] = 0x7c7438b3;
m[63] = 0xb10abd76;

#endif

	pstm_reverse(a, len * sizeof(u32));
	pstm_reverse(b, len * sizeof(u32));
	pstm_reverse(m, len * sizeof(u32));
	if ((err = pstm_init_for_read_unsigned_bin(NULL, &pa, len * sizeof(u32))) != PS_SUCCESS){
		goto out;
	}
	if ((err = pstm_read_unsigned_bin(&pa, a, len * sizeof(u32))) != PS_SUCCESS) {
		goto out;
	}
	if ((err = pstm_init_for_read_unsigned_bin(NULL, &pb, len * sizeof(u32))) != PS_SUCCESS){
		goto out;
	}
	if ((err = pstm_read_unsigned_bin(&pb, b, len * sizeof(u32))) != PS_SUCCESS) {
		goto out;
	}
	if ((err = pstm_init_for_read_unsigned_bin(NULL, &pm, len * sizeof(u32))) != PS_SUCCESS){
		goto out;
	}
	if ((err = pstm_read_unsigned_bin(&pm, m, len * sizeof(u32))) != PS_SUCCESS) {
		goto out;
	}
	pstm_init(NULL, &pres);
	pstm_init(NULL, &mres);

	tls_crypto_exptmod(&pa, &pb, &pm, &pres);
	//rsaMontExptMod(&pa, &pb, &pm, &mres);
	pstm_exptmod(NULL, &pa, &pb, &pm, &mres);
	if(pstm_cmp(&mres, &pres) != PSTM_EQ)
	{
		err = -1;
		goto out;
	}
	err = 0;
out:
	if(a)
		tls_mem_free(a);
	if(b)
		tls_mem_free(b);
	if(m)
		tls_mem_free(m);
	pstm_clear(&pa);
	pstm_clear(&pb);
	pstm_clear(&pm);
	pstm_clear(&pres);
	pstm_clear(&mres);
	return err;
}

int test_rsa_all(void)
{
	int i=0,err = -1;
	for(i=64;i>=16;i = i/2)
	{
		if(exptModTest(i))
			goto out;
	}
	err = 0;
out:
	return err;
}

int test_crypto_all(void)
{
	int ret = -1;
	tls_crypto_init();
	
	if(test_crc_md5_sha1())
	{
		printf("crc md5 err\n");
		goto out;
	}
	if(test_crc_all())
	{
		printf("crc err\n");
		goto out;
	}
	if(test_rsa_all())
	{
		printf("rsa err\n");
		goto out;
	}
	if(test_md5_all())
	{
		printf("md5 err\n");
		goto out;
	}
	if(test_sha1_all())
	{
		printf("sha1 err\n");
		goto out;
	}
	if(test_aes_ctr_all())
	{
		printf("aes ctr err\n");
		goto out;
	}
	if(test_aes_cbc_all())
	{
		printf("aes cbc err\n");
		goto out;
	}
	if(test_aes_ecb_all())
	{
		printf("aes ecb err\n");
		goto out;
	}
	if(test_rc4_all())
	{
		printf("rc4 err\n");
		goto out;
	}
	if(test_3des_ecb_all())
	{
		printf("3des ecb err\n");
		goto out;
	}
	if(test_3des_cbc_all())
	{
		printf("3des cbc err\n");
		goto out;
	}
	if(test_des_ecb_all())
	{
		printf("des ecb err\n");
		goto out;
	}
	if(test_des_cbc_all())
	{
		printf("des cbc err\n");
		goto out;
	}
	ret = 0;
out:
	return ret;
}
#endif

