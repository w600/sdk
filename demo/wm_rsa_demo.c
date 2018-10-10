#include <string.h>
#include "wm_include.h"
#include "wm_crypto_hard.h"
#include "wm_demo.h"

#if DEMO_RSA

int getRsaBig(unsigned char *p, uint32 len, pstm_int *big)
{
	if (pstm_init_for_read_unsigned_bin(NULL, big, len) != PSTM_OKAY) {
		return PS_MEM_FAIL;
	}
	if (pstm_read_unsigned_bin(big, p, len) != 0) {
		pstm_clear(big);
		printf("getRsaBig failed\n");
		return PS_PARSE_FAIL;
	}
	return PS_SUCCESS;
}
int getRsaKey(unsigned char *e, uint32 elen, unsigned char *d, uint32 dlen, 
					 unsigned char *n, uint32 nlen, psRsaKey_t *pubKey)
{
	int ret = PS_PARSE_FAIL;
	memset(pubKey, 0x0, sizeof(psRsaKey_t));
	if(getRsaBig(e, elen, &pubKey->e))
		goto out;
	if(getRsaBig(d, dlen, &pubKey->d))
		goto out;
	if(getRsaBig(n, nlen, &pubKey->N))
		goto out;
	pubKey->size = pstm_unsigned_bin_size(&pubKey->N);
	ret = PS_SUCCESS;
out:
	return ret;
}

int getRsaKeyByStr(const char *e, const char *d, const char *n, psRsaKey_t *pubKey)
{
	int ret = -1, i = 0;;
	unsigned char *ee = NULL;
	unsigned char *dd = NULL;
	unsigned char *nn = NULL;
	uint32 elen = strlen(e) / 2;
	uint32 dlen = strlen(d) / 2;
	uint32 nlen = strlen(n) / 2;
	ee = tls_mem_alloc(elen);
	if(ee == NULL){
		goto out;
	}
	dd = tls_mem_alloc(dlen);
	if(dd == NULL){
		goto out;
	}
	nn = tls_mem_alloc(nlen);
	if(nn == NULL){
		goto out;
	}
	for(i = 0; i < elen; i++)
	{
		sscanf(e + (i * 2), "%02X", ee + i);
	}
	for(i = 0; i < dlen; i++)
	{
		sscanf(d + (i * 2), "%02X", dd+ i);
	}
	for(i = 0; i < nlen; i++)
	{
		sscanf(n + (i * 2), "%02X", nn + i);
	}
	ret = getRsaKey(ee, elen, dd, dlen, nn, nlen, pubKey);
out:
	if(ee)
		tls_mem_free(ee);
	if(dd)
		tls_mem_free(dd);
	if(nn)
		tls_mem_free(nn);
	return ret;
}

void freeRsaKey(psRsaKey_t *key)
{
	pstm_clear(&(key->N));
	pstm_clear(&(key->e));
	pstm_clear(&(key->d));
}

int test_rsa(psRsaKey_t * key, unsigned char *in, int inLen)
{
	int ret = -1, len = inLen, i;
	int keySize = key->size;
	unsigned char *out = NULL;
	unsigned char *outout = NULL;

	out = tls_mem_alloc(keySize);
	if(out == NULL)
	{
		goto out;
	}
	outout = tls_mem_alloc(keySize);
	if(outout == NULL)
	{
		goto out;
	}	

	if(psRsaEncryptPriv(NULL, key, in, inLen, out, keySize, NULL) < 0)
	{
		goto out;
	}

	if(psRsaDecryptPub(NULL, key, out, keySize, outout, inLen, NULL) < 0)
	{
		goto out;
	}
	
	if(memcmp(in, outout, inLen))
	{
		goto out;
	}

	if(psRsaEncryptPub(NULL, key, in, inLen, out, keySize, NULL) < 0)
	{
		goto out;
	}

	if(psRsaDecryptPriv(NULL, key, out, keySize, outout, inLen, NULL) < 0)
	{
		goto out;
	}

	if(memcmp(in, outout, inLen))
	{
		goto out;
	}
	
	ret = 0;
out:
	if(out)
		tls_mem_free(out);
	if(outout)
		tls_mem_free(outout);
	return ret;	
}

int rsa128_demo(void)
{
#define KEY_SIZE   16
	int ret = -1, len = 4, i = 0;
	psRsaKey_t pubkey;
	char *e = "010001";
	char *d = "006DFD720E301A062B9ACA4BE269633D";
	char *n = "8D7F323AB44D756BC881D09EDBA021B9";
	unsigned char *in = NULL;

	in = tls_mem_alloc(KEY_SIZE);
	if(in == NULL)
	{
		printf("malloc err\n");
		goto out;
	}

	for(i=0; i<KEY_SIZE; i++)
	{
		in[i] = rand();
	}
	if(getRsaKeyByStr(e, d, n, &pubkey))
	{
		printf("getRsaKeyByStr err\n");
		goto out;
	}
	
	len = KEY_SIZE - 11;
	if(test_rsa(&pubkey, in, len))
	{
		printf("rsa128 test fail\n");
		goto out;
	}
	
	len = KEY_SIZE - 15;
	if(test_rsa(&pubkey, in, len))
	{
		printf("rsa128 test fail\n");
		goto out;
	}	

	printf("rsa128 test sucess\n");
	ret = 0;
out:
	if(in != NULL)
	{
		tls_mem_free(in);
	}
	freeRsaKey(&pubkey);
	return ret;	
}

int rsa256_demo(void)
{
#define KEY_SIZE   32
	int ret = -1, len = 4, i = 0;
	psRsaKey_t pubkey;
	char *e = "010001";
	char *d = "A834A242A7F8AB804581EA3BC37E0921EDBBDBC755078FEC097191D28304F825";
	char *n = "B05BFAC56C23D78E6902AC5F2FFC94267A362F67A3422EA88DC90E64D0FD0CC5";
	unsigned char *in = NULL;

	in = tls_mem_alloc(KEY_SIZE);
	if(in == NULL)
	{
		printf("malloc err\n");
		goto out;
	}

	for(i=0; i<KEY_SIZE; i++)
	{
		in[i] = rand();
	}
	if(getRsaKeyByStr(e, d, n, &pubkey))
	{
		printf("getRsaKeyByStr err\n");
		goto out;
	}
	
	len = KEY_SIZE - 11;
	if(test_rsa(&pubkey, in, len))
	{
		printf("rsa256 test fail\n");
		goto out;
	}
	
	len = KEY_SIZE - 15;
	if(test_rsa(&pubkey, in, len))
	{
		printf("rsa256 test fail\n");
		goto out;
	}	

	printf("rsa256 test sucess\n");
	ret = 0;
out:
	if(in != NULL)
	{
		tls_mem_free(in);
	}
	freeRsaKey(&pubkey);
	return ret;	
}

int rsa512_demo(void)
{
#define KEY_SIZE   64
	int ret = -1, len = 4, i = 0;
	psRsaKey_t pubkey;
	char *e = "010001";
	char *d = "528F5501EE3730E68DEE5E91EE9F9D95D63B7E5A776D99494B092E8032685A09736FB4BBED02A495ABF423A65833D80707152A22C3EC94744F0FD435FF37D601";
	char *n = "860593CE009DA860C8346E48FAE96064914B48CEB415EB4BBD41E15E6FB5004BCED662716B416AE1C2160923022F38DDC39034B0EDE5CCA941226108B4CE473D";
	unsigned char *in = NULL;

	in = tls_mem_alloc(KEY_SIZE);
	if(in == NULL)
	{
		printf("malloc err\n");
		goto out;
	}

	for(i=0; i<KEY_SIZE; i++)
	{
		in[i] = rand();
	}
	if(getRsaKeyByStr(e, d, n, &pubkey))
	{
		printf("getRsaKeyByStr err\n");
		goto out;
	}
	
	len = KEY_SIZE - 11;
	if(test_rsa(&pubkey, in, len))
	{
		printf("rsa512 test fail\n");
		goto out;
	}
	
	len = KEY_SIZE - 15;
	if(test_rsa(&pubkey, in, len))
	{
		printf("rsa512 test fail\n");
		goto out;
	}	

	printf("rsa512 test sucess\n");
	ret = 0;
out:
	if(in != NULL)
	{
		tls_mem_free(in);
	}
	freeRsaKey(&pubkey);
	return ret;	
}

int rsa1024_demo(void)
{
#define KEY_SIZE   128
	int ret = -1, len = 4, i = 0;
	psRsaKey_t pubkey;
	char *e = "010001";
	char *d = "10472A02092A7B762B58F106F685A7C7BF89A9BB63D1995AA18DD69D60D12A0A2A57DD68FDC9A3F7B88A8CE9F9AD3691A679BCA92FA69863FE624ADF0C3DDA45663DC2C7AF657E9F94C1912FF43F3B25F7707DA9ED4012F94ABB5459A7D3B85D5073238956C683674D60E97B04E5C73533AF1B362C990C93DED2ADFEBA73FA01";
	char *n = "831F490969DD687C0F942642303956C30FE71E9E00E9820560ACEFFDB775644A24D0AB3271DC4F962ADD2EB5F322FF358605A2F48E7791937844C25EDEED536D6FE1E8842AA07CE2604B93FF9DC48DB89B9F0744D499566109C3984EE9E01CA27077858408F1204EB929836C0396D410471CD0944AFE0D84E83BD36277A64963";
	unsigned char *in = NULL;

	in = tls_mem_alloc(KEY_SIZE);
	if(in == NULL)
	{
		printf("malloc err\n");
		goto out;
	}

	for(i=0; i<KEY_SIZE; i++)
	{
		in[i] = rand();
	}
	if(getRsaKeyByStr(e, d, n, &pubkey))
	{
		printf("getRsaKeyByStr err\n");
		goto out;
	}
	
	len = KEY_SIZE - 11;
	if(test_rsa(&pubkey, in, len))
	{
		printf("rsa1024 test fail\n");
		goto out;
	}
	
	len = KEY_SIZE - 15;
	if(test_rsa(&pubkey, in, len))
	{
		printf("rsa1024 test fail\n");
		goto out;
	}	

	printf("rsa1024 test sucess\n");
	ret = 0;
out:
	if(in != NULL)
	{
		tls_mem_free(in);
	}
	freeRsaKey(&pubkey);
	return ret;	
}

int rsa2048_demo(void)
{
#define KEY_SIZE   256
	int ret = -1, len = 4, i = 0;
	psRsaKey_t pubkey;
	char *e = "010001";
	char *d = "42A99675F95DAE21A1E951C252CDE058AB3810A85D954A24F3EFFF92A38A6EF3012405DBF36A2813AA9080DA1F089474408293B987F34F0D604BAA2D8180196AEF323DAB1C244539D384B89C3F76581A80A5E335FC39593084C07241DD0267B207B556EAD8DA5CC1E900278E584E8C3E1E9E89AA4D9EA3C6C69211253492744AE5259515A7E2D8F7A45F1E38D0F0D31469833F4B3A5E3EE09B0922BD9FB44DFF04E2DBE243C3407E70FB27B03AE271B511E0AB6A0E6947FF19F3FFAD388159B60FC1B9C58DACE4A92FFCA16412510AB90F665968A44B7C9C12AF98CD5B1E7EB38790079FD0531EF3A3CEE3313FE7A778EBE63AAA494B778285A803CC39820841";
	char *n = "B3459DB697592E0642E20EDEF5442AAD07774FB17D81BAFC8E28EBD66F1BF29C6FED95D16A194A3ED8912B493778E7681CA502B61B3CAF8FE30495C47F75C9DE99F8318DF0117E8514E39E1B2FDD9FBE5FD962177B8CAC4C0854729155E910AA4114A3498D37963DC9456667BE3FF56050FA2EF1A49E6D03076CD8CF4C12544F82BEFC8A39745BE2FBC514479D79AB2877B33742536403B340CC7711936A220370EC2A189F97D6B3D1178CB9E63036A75F14AE65AB7DD6830B18AD2BA44204E97F8AE2218AC024466AA07BB90712DB2FF8F91F5C0817F19D3821FA4E7A0B66BB65B0A72BA6CC44EC4FD4A12EB7312469C37F90118C87AA742A44AEB60710C3ED";
	unsigned char *in = NULL;

	in = tls_mem_alloc(KEY_SIZE);
	if(in == NULL)
	{
		printf("malloc err\n");
		goto out;
	}

	for(i=0; i<KEY_SIZE; i++)
	{
		in[i] = rand();
	}
	if(getRsaKeyByStr(e, d, n, &pubkey))
	{
		printf("getRsaKeyByStr err\n");
		goto out;
	}
	
	len = KEY_SIZE - 11;
	if(test_rsa(&pubkey, in, len))
	{
		printf("rsa2048 test fail\n");
		goto out;
	}
	
	len = KEY_SIZE - 15;
	if(test_rsa(&pubkey, in, len))
	{
		printf("rsa2048 test fail\n");
		goto out;
	}	

	printf("rsa2048 test sucess\n");
	ret = 0;
out:
	if(in != NULL)
	{
		tls_mem_free(in);
	}
	freeRsaKey(&pubkey);
	return ret;	
}

int rsa_demo(void)
{
	tls_crypto_init();

//	while(1)
	{
		printf("rsa test start\n");
		rsa128_demo();
		rsa256_demo();
		rsa512_demo();
		rsa1024_demo();
		rsa2048_demo();
		printf("rsa test end\n");
	}
    return WM_SUCCESS;
}

#endif


