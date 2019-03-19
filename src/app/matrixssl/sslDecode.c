/*
 *	sslDecode.c
 *	Release $Name: MATRIXSSL-3-6-1-OPEN $
 *
 *	Secure Sockets Layer protocol message decoding portion of MatrixSSL
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
#if TLS_CONFIG_HARD_CRYPTO
#include "wm_crypto_hard.h"
#endif
/******************************************************************************/

#define SSL_MAX_IGNORED_MESSAGE_COUNT	1024

static int32 parseSSLHandshake(ssl_t *ssl, char *inbuf, uint32 len);

#ifdef USE_CERT_CHAIN_PARSING
static int32 parseSingleCert(ssl_t *ssl, unsigned char *c, unsigned char *end, 
						   int32 certLen);
#endif /* USE_CERT_CHAIN_PARSING */

#ifndef USE_PKCS11
static int32 addCompressCount(ssl_t *ssl, int32 padLen);
#endif

#ifdef USE_ZLIB_COMPRESSION
/* Does not need to be a large value because we're only inflating the 16
	byte FINISHED message.  In fact, compression will grow 16 bytes but
	this is a good reminder that FUTURE support will need to account for
	likely data growth here */
#define MATRIX_INFLATE_FINISHED_OH	128
#endif
/******************************************************************************/
/*
	Parse incoming data per http://wp.netscape.com/eng/ssl3
	
	Input parameters to decode:
	.	buf points to the start of data to decode
	.	len points to the length in bytes of data to decode
	.	size is the number of allocated bytes that follow buf
	

	
	Meaningful parameters after the call to decode:
	MATRIXSSL_SUCCESS
	.	buf will point to the first undecoded byte (could==inbuf or inbuf+inlen)
	.	remaining will indicate how many more bytes of undecoded data remain
	*	call again if more to decode or return if handshake is complete
	
	SSL_PARTIAL
	.	buf will not have moved (because partials start parse over)
	.	reqLen will indicate how many bytes the entire full record is 
	*	get more data from peer and call again
	
	SSL_FULL (implies decode completed fully but couldn't fit response)
	.	buf will not have moved (it is reset to the front of final record)
	.	len will be 0 to indicate no remaining unprocessed data
	.	reqLen will inform how large buf should be grown before re-invoking
	*	realloc the buf to the reqLen size and call again
	
	SSL_SEND_RESPONSE
	.	buf will point to the encoded handshake data to send
	.	len will be length of data to send (from start offset)
	*	pass the buf to the transport layer for sending to peer
	
	SSL_ALERT
	.	buf will point to start of received alert (2 bytes alert level and desc)
	.	len will be length of alert data (should be 2)
	.	alertLevel will be 1 (warning) or 2 (fatal)
	.	alertDesc will be SSL specified alert code
	
	MATRIXSSL_ERROR (unrecoverable failure)
	.	decodeErr is internal parse err code
	
	SSL_PROCESS_DATA (ONLY CASE WITH DECRYPTED DATA AND POSSIBLE UNENCRYPTED)
	.	unencrypted user data ready for processing is at prevBuf
	.	buf points to start of any remaining unencrypted data
	.	remaining is length of remaining encrypted data yet to decode
	.	len is length of unencrypted data ready for user processing
	*	pass unencypted data to application level
	*	call decode again if more encrypted data remaining
	
*/
int32 matrixSslDecode(ssl_t *ssl, unsigned char **buf, uint32 *len,
					uint32 size, uint32 *remaining, uint32 *requiredLen,
					int32 *error, unsigned char *alertLevel,
					unsigned char *alertDescription)
{
	unsigned char	*c, *p, *end, *pend, *ctStart, *origbuf;
	unsigned char	*mac, macError;
	int32			rc;
	unsigned char	padLen = 0;
	psBuf_t			tmpout;
	psDigestContext_t	dummyMd;
	uint32 currParsingLen = 0;
#ifdef USE_CERT_CHAIN_PARSING
	int32			certlen, i, nextCertLen;
#endif /* USE_CERT_CHAIN_PARSING */
#ifdef USE_ZLIB_COMPRESSION
	int32	preInflateLen, postInflateLen, currLen;
	int zret;
#endif	
/*
	If we've had a protocol error, don't allow further use of the session
*/
	*error = PS_SUCCESS;
	if (ssl->flags & SSL_FLAGS_ERROR || ssl->flags & SSL_FLAGS_CLOSED) {
		psTraceInfo("Can't use matrixSslDecode on closed/error-flagged sess\n");
		*error = PS_PROTOCOL_FAIL;
		return MATRIXSSL_ERROR;
	}

	origbuf = *buf;	/* Save the original buffer location */


/*
	This flag is set if the previous call to this routine returned an SSL_FULL
	error from encodeResponse, indicating that there is data to be encoded, 
	but the out buffer was not big enough to handle it.  If we fall in this 
	case, the user has increased the out buffer size and is re-calling this 
	routine
*/
	if (ssl->flags & SSL_FLAGS_NEED_ENCODE) {
		ssl->flags &= ~SSL_FLAGS_NEED_ENCODE;
		goto encodeResponse;
	}
	*requiredLen = 0;
	c = *buf; /* c is record parse pointer */
	end = *buf + *len;
	
/*
	Processing the SSL Record header:
	If the high bit of the first byte is set and this is the first 
	message we've seen, we parse the request as an SSLv2 request
	http://wp.netscape.com/eng/security/SSL_2.html
	SSLv2 also supports a 3 byte header when padding is used, but this should 
	not be required for the initial plaintext message, so we don't support it
	v3 Header:
		1 byte type
		1 byte major version
		1 byte minor version
		2 bytes length
	v2 Header
		2 bytes length (ignore high bit)
*/
	if (end - c == 0) {
/*
		This case could happen if change cipher spec was last
		message	in the buffer or if there is a zero-length record
		at the end of a multi-record application data buffer.
*/
		return MATRIXSSL_SUCCESS;
	}
	if (end - c < SSL2_HEADER_LEN) {
		*requiredLen = SSL2_HEADER_LEN;
		return SSL_PARTIAL;
	}
#ifdef USE_APP_DATA_PARTIAL_PARSING	
	if(ssl->deBlockSize <= 1 && ssl->rec.byteParsed)
		goto PARTIAL_PARSED;
#endif
#ifdef USE_CERT_CHAIN_PARSING
/*
	If we're in process of parsing a partial record, then skip the 
	usual record header parse.  Currently we're only supporting
	partial parsing for the certificate messages since they are the
	largest in size.
*/
	if (ssl->rec.partial != 0x0) {
		psAssert(ssl->rec.type == SSL_RECORD_TYPE_HANDSHAKE);
		psAssert(ssl->hsState == SSL_HS_CERTIFICATE);
/*
		Get this next record length based on the certificate size,
		which will always be the first three bytes of a partial here
*/
		ssl->rec.len = c[0] << 16;
		ssl->rec.len |= c[1] << 8;
		ssl->rec.len |= c[2];
		ssl->rec.len += 3;
		goto SKIP_RECORD_PARSE;
	}
#endif /* USE_CERT_CHAIN_PARSING */

	if (ssl->majVer != 0 || (*c & 0x80) == 0) {
		if (end - c < ssl->recordHeadLen) {
			*requiredLen = ssl->recordHeadLen;
			return SSL_PARTIAL;
		}
		ssl->rec.type = *c; c++;
		ssl->rec.majVer = *c; c++;
		ssl->rec.minVer = *c; c++;
		ssl->rec.len = *c << 8; c++;
		ssl->rec.len += *c; c++;
	} else {
		ssl->rec.type = SSL_RECORD_TYPE_HANDSHAKE;
		ssl->rec.majVer = 2;
		ssl->rec.minVer = 0;
		ssl->rec.len = (*c & 0x7f) << 8; c++;
		ssl->rec.len += *c; c++;
	}
/*
	Validate the various record headers.  The type must be valid,
	the major and minor versions must match the negotiated versions (if we're
	past ClientHello) and the length must be < 16K and > 0
*/
	if (ssl->rec.type != SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC &&
			ssl->rec.type != SSL_RECORD_TYPE_ALERT &&
			ssl->rec.type != SSL_RECORD_TYPE_HANDSHAKE &&
			ssl->rec.type != SSL_RECORD_TYPE_APPLICATION_DATA) {
		ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
		psTraceIntInfo("Record header type not valid: %d\n", ssl->rec.type);
		goto encodeResponse;
	}

/*
	Verify the record version numbers unless this is the first record we're
	reading.
*/
	if (ssl->hsState != SSL_HS_SERVER_HELLO &&
			ssl->hsState != SSL_HS_CLIENT_HELLO) {
		if (ssl->rec.majVer != ssl->majVer || ssl->rec.minVer != ssl->minVer) {
#ifdef SSL_REHANDSHAKES_ENABLED
			/* If in DONE state and this version doesn't match the previously
				negotiated one that can be OK because a CLIENT_HELLO for a
				rehandshake might be acting like a first time send and using
				a lower version to get to the parsing phase.  Unsupported 
				versions will be weeded out at CLIENT_HELLO parse time */
			if (ssl->hsState != SSL_HS_DONE ||
					ssl->rec.type != SSL_RECORD_TYPE_HANDSHAKE) {
				ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
				psTraceInfo("Record header version not valid\n");
				goto encodeResponse;
			}
#else
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			psTraceInfo("Record header version not valid\n");
			goto encodeResponse;
#endif	
		}
	}
/*
	Verify max and min record lengths
*/
	if (ssl->rec.len > SSL_MAX_RECORD_LEN || ssl->rec.len == 0) {
		ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
		psTraceIntInfo("Record header length not valid: %d\n", ssl->rec.len);
		goto encodeResponse;
	}
/*
	This implementation requires the entire SSL record to be in the 'in' buffer
	before we parse it.  This is because we need to MAC the entire record before
	allowing it to be used by the caller.
*/
#ifdef USE_CERT_CHAIN_PARSING
SKIP_RECORD_PARSE:
	if ((end - c < ssl->rec.len) || ssl->rec.partial) {
/*
		This feature will only work if the CERTIFICATE message is sent in a
		different record from the SERVER_HELLO message.
*/
		if (ssl->hsState != SSL_HS_CERTIFICATE) {
			ssl->rec.partial = 0x0;
			*requiredLen = ssl->rec.len + ssl->recordHeadLen;
			return SSL_PARTIAL;
		}
/*
		Not supporting cert stream parsing for re-handshake.  This is
		important because the block cipher assumes a single pass is a record
		and will use explicit IV each pass 
*/
		if (ssl->flags & SSL_FLAGS_READ_SECURE) {
			ssl->rec.partial = 0x0;
			*requiredLen = ssl->rec.len + ssl->recordHeadLen;
			return SSL_PARTIAL;
		}
/*
		Manipulate the rec.len for partial handling
*/
		i = 0;
		if (ssl->rec.partial == 0x0) {
/*
			Initialization for partial parse counters
*/
			ssl->rec.hsBytesHashed = 0;
			ssl->rec.hsBytesParsed = 0;
			ssl->rec.partial = 0x1;
			ssl->rec.trueLen = ssl->rec.len + ssl->recordHeadLen;
			ssl->rec.len = 0;
/*
			Best to identify and isolate full certificate boundaries
			ASAP to keep parsing logic as high level as possible.

			Current state of record buffer: pointer at start of HS record
			which begins with 4 bytes of hsType(1) and hsLen(3).  After
			the header are 3 bytes of certchainlen and 3 bytes of first
			cert len.  Make sure we have at least one full cert here before
			allowing the partial parse.
*/
			if (end - c < (ssl->hshakeHeadLen + 6)) { /* 3*2 cert chain len */
				ssl->rec.partial = 0x0; /* Unusable.  Reset */
				*requiredLen = ssl->hshakeHeadLen + 6;
				return SSL_PARTIAL;
			}
			ssl->rec.len += (ssl->hshakeHeadLen + 3);
			i = ssl->hshakeHeadLen;
			certlen = c[i] << 16; i++;
			certlen |= c[i] << 8; i++;
			certlen |= c[i]; i++;
/*
			This feature only works if the CERTIFICATE message is the only
			message in the record.  Test this by seeing that trueLen doesn't
			claim there is more to follow
*/
			if (ssl->rec.trueLen != (certlen + 3 + ssl->hshakeHeadLen +
					ssl->recordHeadLen)) {
				ssl->rec.partial = 0x0; /* Unusable.  Reset */
				*requiredLen = ssl->rec.trueLen;
				return SSL_PARTIAL;
			}
/*
			First cert length
*/
			ssl->rec.len += 3;
			certlen = c[i] << 16; i++;
			certlen |= c[i] << 8; i++;
			certlen |= c[i];
			ssl->rec.len += certlen;
		}
/*
		One complete cert?
*/	
		if (end - c < ssl->rec.len) {
/*
			If there isn't a full cert in the first partial, we reset and
			handle as the standard SSL_PARTIAL case.
*/
			if (ssl->rec.hsBytesParsed == 0) {
				ssl->rec.partial = 0x0; /* Unusable.  Reset */
				*requiredLen = ssl->rec.len + ssl->recordHeadLen;
			} else {
				/* Record header has already been parsed */
				*requiredLen = ssl->rec.len;
			}
			return SSL_PARTIAL; /* Standard partial case */
		}
/*
		More than one complete cert?
*/	
		while (end - c > ssl->rec.len)
		{
			if (ssl->rec.len + ssl->rec.hsBytesParsed == ssl->rec.trueLen) {
/*				
				Don't try to read another cert if the total of already parsed
				record and the length of the current record match the 'trueLen'.
				If they are equal, we know we are on the final cert and don't
				need to look for more
*/
				break;
			}
			psAssert(ssl->rec.len + ssl->rec.hsBytesParsed <= ssl->rec.trueLen);
			nextCertLen = c[ssl->rec.len] << 16;
			nextCertLen |= c[ssl->rec.len + 1] << 8;
			nextCertLen |= c[ssl->rec.len + 2];
			if (end - c > (ssl->rec.len + nextCertLen + 3)) {
				ssl->rec.len += (nextCertLen + 3);
			} else {
				break;
			}
		}
	}
#else
	if (end - c < ssl->rec.len) {	
#ifdef USE_APP_DATA_PARTIAL_PARSING	
		if(ssl->deBlockSize > 1 || ssl->rec.type != SSL_RECORD_TYPE_APPLICATION_DATA)
#endif
		{
			*requiredLen = ssl->rec.len + ssl->recordHeadLen;
			return SSL_PARTIAL;
		}
	}
#endif


#ifdef USE_MATRIXSSL_STATS
	if (ssl->rec.type == SSL_RECORD_TYPE_APPLICATION_DATA) {
		matrixsslUpdateStat(ssl, APP_DATA_RECV_STAT, ssl->rec.len +
			ssl->recordHeadLen);
	}
#endif	

#ifdef USE_APP_DATA_PARTIAL_PARSING
PARTIAL_PARSED:
#endif
/*
	Decrypt the entire record contents.  The record length should be
	a multiple of block size, or decrypt will return an error
	If we're still handshaking and sending plaintext, the decryption 
	callback will point to a null provider that passes the data unchanged
*/
	ctStart = origbuf; /* Clear-text start.  Decrypt to the front */


	/* Sanity check ct len.  Step 1 of Lucky 13 MEE-TLS-CBC decryption. 
		max{b, t + 1} is always "t + 1" because largest possible blocksize
		is 16 and smallest possible tag len is 16. Multiple of block size test
		is done in decrypt */
	if ((ssl->flags & SSL_FLAGS_READ_SECURE) && (ssl->deBlockSize > 1) &&
			!(ssl->flags & SSL_FLAGS_GMAC_R)) {
#ifdef USE_TLS_1_1
		if (ssl->flags & SSL_FLAGS_TLS_1_1) {
			if (ssl->rec.len < (ssl->deMacSize + 1 + ssl->deBlockSize)) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Ciphertext length failed sanity\n"); 
				goto encodeResponse;
			}
		} else {
			if (ssl->rec.len < (ssl->deMacSize + 1)) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Ciphertext length failed sanity\n"); 
				goto encodeResponse;
			}
		}
#else
		if (ssl->rec.len < (ssl->deMacSize + 1)) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Ciphertext length failed sanity\n"); 
			goto encodeResponse;
		}
#endif /* USE_TLS_1_1 */
	}
#ifdef USE_APP_DATA_PARTIAL_PARSING	
	if(ssl->deBlockSize <= 1 && ssl->rec.type == SSL_RECORD_TYPE_APPLICATION_DATA){
		if(ssl->rec.byteParsed + *len >= ssl->rec.len){
			currParsingLen = ssl->rec.len - ssl->rec.byteParsed;
			//printf("ssl->rec.len=%d, currParsingLen=%d, ssl->rec.byteParsed=%d\n", ssl->rec.len, currParsingLen, ssl->rec.byteParsed);
		}
		else if(ssl->rec.byteParsed + *len + ssl->deMacSize > ssl->rec.len){
			currParsingLen = ssl->rec.len - ssl->rec.byteParsed - ssl->deMacSize;
			//printf("ssl->rec.len=%d, currParsingLen=%d, ssl->rec.byteParsed=%d\n", ssl->rec.len, currParsingLen, ssl->rec.byteParsed);
		}
		else{
			currParsingLen = *len;
			//printf("ssl->rec.len=%d, currParsingLen=%d, ssl->rec.byteParsed=%d\n", ssl->rec.len, currParsingLen, ssl->rec.byteParsed);
		}
		if(ssl->rec.byteParsed == 0)
			currParsingLen -= ssl->recordHeadLen;
	}
	else
#endif
	{
		currParsingLen = ssl->rec.len;
	}
		
	/* CT to PT */
	if (ssl->decrypt(ssl, c, ctStart, currParsingLen) < 0) {
		ssl->err = SSL_ALERT_DECRYPT_ERROR;
		psTraceInfo("Couldn't decrypt record data\n"); 
		goto encodeResponse;
	}
#ifdef USE_APP_DATA_PARTIAL_PARSING	
	if(ssl->deBlockSize <= 1 && ssl->rec.type == SSL_RECORD_TYPE_APPLICATION_DATA){
		if(ssl->rec.byteParsed + *len >= ssl->rec.len){
			ssl->rec.byteParsed = 0;
		}
		else{
			ssl->rec.byteParsed += currParsingLen;
		}
	}
#endif
	c += currParsingLen;

#if defined(USE_TLS_1_2) && defined(USE_AES_GCM)
	if ((ssl->flags & SSL_FLAGS_TLS_1_2) &&	(ssl->flags & SSL_FLAGS_GMAC_R)) {
		/* GMAC needs a bit of manual length manipulation for buffer mgmnt */  
		ssl->rec.len -= TLS_GCM_TAG_LEN + ssl->nonceCtrLen;
	}
#endif
/*
	If we're reading a secure message, we need to validate the MAC and 
	padding (if using a block cipher).  Insecure messages do not have 
	a trailing MAC or any padding.

	SECURITY - There are several vulnerabilities in block cipher padding
	that we handle in the below code.  For more information see:
	http://www.openssl.org/~bodo/tls-cbc.txt
*/
	if (ssl->flags & SSL_FLAGS_READ_SECURE && !(ssl->flags & SSL_FLAGS_GMAC_R)){
/*
		Start tracking MAC errors, rather then immediately catching them to
		stop timing and alert description attacks that differentiate between
		a padding error and a MAC error.
*/
		macError = 0;
/*
		Decode padding only if blocksize is > 0 (we're using a block cipher),
		otherwise no padding will be present, and the mac is the last 
		macSize bytes of the record.
*/
		if (ssl->deBlockSize <= 1) {
#ifdef USE_APP_DATA_PARTIAL_PARSING
			if(ssl->rec.byteParsed > 0 && ssl->rec.byteParsed == currParsingLen){
				ssl->verifyMac(ssl, ssl->rec.type, NULL, ssl->rec.len - ssl->deMacSize, NULL);
			}
			if(ssl->rec.byteParsed > 0){
				mac = ctStart + currParsingLen;
			}
			else
#endif
				mac = ctStart + currParsingLen - ssl->deMacSize;
		} else {
/*
			The goal from here through completion of ssl->verifyMac call is a
			constant processing time for a given record length.  Going to
			follow the suggestions of the Lucky 13 research paper section
			"Careful implementation of MEE-TLS-CBC decryption".
			http://www.isg.rhul.ac.uk/tls/TLStiming.pdf

			Consistent timing is still a "goal" here.  This implementation
			accounts for the largest timing discrepencies but is not a 
			strict "clock cycles" equalizer.  The complexity of the attack
			circumstances and plaintext recovery possibilities using these
			techniques is almost entirely in the academic realm. Improvements
			to this code will be an ongoing process as research uncovers
			more practical plaintext recovery threats.
			
			Our first step is to create a hash context that might possibly
			be used to compress some dummy data for Step 5.
*/
			if (ssl->deMacSize == SHA256_HASH_SIZE) {
#ifdef USE_SHA256
				psSha256Init(&dummyMd);
#endif
#ifdef USE_SHA384			
			} else if (ssl->deMacSize == SHA384_HASH_SIZE) {
				psSha384Init(&dummyMd);
#endif				
			} else {
				psSha1Init(&dummyMd);
			}
/*			
			Verify the pad data for block ciphers
			c points within the cipher text, p points within the plaintext
			The last byte of the record is the pad length
*/
			p = ctStart + ssl->rec.len;
			padLen = *(p - 1);
/*
			SSL3.0 requires the pad length to be less than blockSize
			TLS can have a pad length up to 255 for obfuscating the data len
*/
			if (ssl->majVer == SSL3_MAJ_VER && ssl->minVer == SSL3_MIN_VER && 
					padLen >= ssl->deBlockSize) {
				macError = 1;
			}
/*
			The minimum record length is the size of the mac, plus pad bytes
			plus one length byte
*/
			if (ssl->rec.len < ssl->deMacSize + padLen + 1) {
				/* Step 3 of Lucky 13 MEE-TLS-CBC decryption: Run a loop as
					if there were 256 bytes of padding, with a dummy check
					in each iteration*/
				for (rc = 255; rc >= 0; rc--) {
					/* make the test a moving target so it doesn't get 
						optimized out at compile. The loop is written
						this way so the macError assignment will be done
						only once */
					if ((unsigned char)rc == padLen) {
						macError = 1;	/* No incr to avoid any wraps */
					}
				}
			}
#ifdef USE_TLS
/*
			TLS specifies that all pad bytes must have the same value
			as the final pad length byte.  Some SSL3 implementations also 
			do this by convention, but some just fill with random bytes.
			(We're just overloading the 'mac' ptr here, this has nothing to 
			do with real MAC.)
*/
			if (!macError && ssl->majVer == TLS_MAJ_VER &&
					ssl->minVer >= TLS_MIN_VER) {
				for (mac = p - padLen - 1; mac < p; mac++) {
					if (*mac != padLen) {
						macError = 1;
					}
				}
				/* Lucky 13 step 4. If this fails, then run a loop as if there
					were 256 - padlen - 1 bytes of padding, with a dummy
					check in each iteration */
				if (macError) {
					for (rc = 256 - padLen - 1; rc > 0; rc--) {
						/* make the test a moving target so it doesn't get 
							optimized out at compile.  Again, make it so
							the loop condition doesn't get hit more than
							once. */
						if ((unsigned char)rc == padLen) {
							macError = 2; /* change value for smart compilers */
						}
					}
				}	
			}
#endif /* USE_TLS */
/*
			The mac starts macSize bytes before the padding and length byte.
			If we have a macError, just fake the mac as the last macSize bytes
			of the record, so we are sure to have enough bytes to verify
			against, we'll fail anyway, so the actual contents don't matter.
*/
			if (!macError) {
				/* No padding errors */
				mac = p - padLen - 1 - ssl->deMacSize;
				/* Lucky 13 step 5: Otherwise (the padding is now correctly
					formatted) run a loop as if there were 256 - padlen - 1
					bytes of padding, doing a dummy check in each iteration */
				for (rc = 256 - padLen - 1; rc > 0; rc--) {
					/* make this test look like the others */
					if ((unsigned char)rc == padLen) {
						macError = 1; /* not really an error.  reset below */
					}
				}	
				macError = 0;
			} else {
				/* Lucky 13 step 3 and 4 condition:  Then let P' denote the ﬁrst
					plen - t bytes of P, compute a MAC on SQN||HDR||P' and do a
					constant-time comparison of the computed MAC with the
					last t bytes of P. Return fatal error. */
				mac = origbuf + ssl->rec.len - ssl->deMacSize;
			}
		}
/*
		Verify the MAC of the message by calculating our own MAC of the message
		and comparing it to the one in the message.  We do this step regardless
		of whether or not we've already set macError to stop timing attacks.
		Clear the mac in the callers buffer if we're successful
*/
#ifdef USE_TLS_1_1
		if ((ssl->flags & SSL_FLAGS_TLS_1_1) && (ssl->deBlockSize > 1)) {
			ctStart += ssl->deBlockSize; /* skip explicit IV */
		}
#endif		

#ifndef USE_PKCS11 
		if (ssl->deBlockSize > 1) {
			/* Run this helper regardless of error status thus far */
			rc = addCompressCount(ssl, padLen);
			if (macError == 0) {
			/* Lucky 13 Step 5.  Doing this extra MAC compression here rather
				than inside the real verify to keep this code patch at the
				protocol level.
			*/
				if (ssl->deMacSize == SHA256_HASH_SIZE) {
					while (rc > 0) {
#ifdef USE_SHA256 
						sha256_compress(&dummyMd, dummyMd.sha256.buf);
#endif
						rc--;
					}
#ifdef USE_SHA384			
				} else if (ssl->deMacSize == SHA384_HASH_SIZE) {
					while (rc > 0) {
						sha512_compress(&dummyMd, dummyMd.sha512.buf);
						rc--;
					}
#endif			
				} else {
					while (rc > 0) {
					extern void SHA1Transform(u32 state[5], const unsigned char buffer[64]);
						SHA1Transform(dummyMd.sha1.state, dummyMd.sha1.buf);
						rc--;
					}
				}
			}
		}
#endif /* PKCS11 */
		
		if (ssl->verifyMac(ssl, ssl->rec.type, ctStart, 
				(uint32)(mac - ctStart), mac) < 0 || macError) {
			ssl->err = SSL_ALERT_BAD_RECORD_MAC;
			psTraceInfo("Couldn't verify MAC or pad of record data\n");
			goto encodeResponse;
		}
		
#ifdef USE_APP_DATA_PARTIAL_PARSING
		if(ssl->deBlockSize <= 1 && ssl->rec.byteParsed == 0 && ssl->rec.type == SSL_RECORD_TYPE_APPLICATION_DATA)
		{
			if (ssl->verifyMac(ssl, ssl->rec.type, NULL, 
					0, mac) < 0 || macError) {
				ssl->err = SSL_ALERT_BAD_RECORD_MAC;
				psTraceInfo("Couldn't verify MAC or pad of record data\n");
				goto encodeResponse;
			}
		}
#else
		memset(mac, 0x0, ssl->deMacSize);
#endif
/*
		Record data starts at ctStart and ends at mac
*/
		p = ctStart;
		pend = mac;
	} else {
/*
		The record data is the entire record as there is no MAC or padding
*/
		p = ctStart;
		pend = mac = ctStart + ssl->rec.len;
	}
	
#ifdef USE_ZLIB_COMPRESSION
	/* Currently only supporting compression of FINISHED message.
		Compressed application data is handled outside MatrixSSL.
		Re-handshakes are not allowed with compression and we've
		incremented ssl->compression if we've already been through here
		so we'll know */
	if (ssl->compression == 2 && ssl->flags & SSL_FLAGS_READ_SECURE &&
			ssl->rec.type == SSL_RECORD_TYPE_HANDSHAKE) {
		ssl->err = SSL_ALERT_INTERNAL_ERROR;
		psTraceInfo("Re-handshakes not supported on compressed sessions\n");
		goto encodeResponse;
	}
	if (ssl->compression && ssl->flags & SSL_FLAGS_READ_SECURE &&
			ssl->rec.type == SSL_RECORD_TYPE_HANDSHAKE) {
		/* TODO - handle the cases below where the buffer has to grow */
		currLen = ssl->inflate.total_out;
		preInflateLen = (int32)(pend - p);
		ssl->zlibBuffer = psMalloc(MATRIX_NO_POOL, preInflateLen +
			MATRIX_INFLATE_FINISHED_OH);
		memset(ssl->zlibBuffer, 0, preInflateLen + MATRIX_INFLATE_FINISHED_OH);
		if (ssl->zlibBuffer == NULL) {
			ssl->err = SSL_ALERT_INTERNAL_ERROR;
			psTraceInfo("Couldn't allocate compressed scratch pad\n");
			goto encodeResponse;
		}
		if (preInflateLen > 0) { /* zero length record possible */
			/* psTraceBytes("pre inflate", ctStart, preInflateLen); */
			ssl->inflate.next_in = ctStart;
			ssl->inflate.avail_in = preInflateLen;
			ssl->inflate.next_out = ssl->zlibBuffer;
			ssl->inflate.avail_out = SSL_MAX_PLAINTEXT_LEN;
			if ((zret = inflate(&ssl->inflate, Z_SYNC_FLUSH)) != Z_OK) {
				ssl->err = SSL_ALERT_INTERNAL_ERROR;
				psFree(ssl->zlibBuffer); ssl->zlibBuffer = NULL;
				inflateEnd(&ssl->inflate);
				psTraceIntInfo("ZLIB inflate failed %d\n", zret);
				goto encodeResponse;
			}
			if (ssl->inflate.avail_in != 0) {
				ssl->err = SSL_ALERT_INTERNAL_ERROR;
				psFree(ssl->zlibBuffer); ssl->zlibBuffer = NULL;
				inflateEnd(&ssl->inflate);
				psTraceInfo("ZLIB inflate didn't work in one pass\n");
				goto encodeResponse;
			}
			postInflateLen = ssl->inflate.total_out - currLen;
				
			/* psTraceBytes("post inflate", ssl->zlibBuffer,
				postInflateLen); */
				
			if (postInflateLen <= preInflateLen) {
				/* Easy case where compressed data was actually larger.
					Don't need to update c or inlen because the next
					good data is already correctly being pointed to */
				memcpy(p, ssl->zlibBuffer, postInflateLen);
				mac = p + postInflateLen;
				pend = mac;
			} else {
				/* Data expanded.  Fit it in the buffer and update all
					the associated lengths and pointers
						
					Add back in the MAC and pad to preInflate so we're
					looking at the useful boundaries of the buffers */
				preInflateLen += (int32)(c - mac);
				/* reusing currLen var.  Now the difference in lengths */
				currLen = postInflateLen - preInflateLen;
				if ((int32)(c - ssl->inbuf) == ssl->inlen) {
					/* Good, this was the only data in the buffer.  Just
						check there is room to append */
					if ((ssl->insize - ssl->inlen) >= postInflateLen) {
						memcpy(p, ssl->zlibBuffer, postInflateLen);
						c += currLen;
						mac = p + postInflateLen;
						pend = mac;
					} else {
						/* Only one here but not enough room to store it */
						ssl->err = SSL_ALERT_INTERNAL_ERROR;
						psFree(ssl->zlibBuffer); ssl->zlibBuffer = NULL;
						inflateEnd(&ssl->inflate);
						psTraceInfo("ZLIB buffer management needed\n");
						goto encodeResponse;
					}
				} else {
					/* Push any existing data further back in the buffer to
						make room for this uncompressed length.  c pointing
						to start of next record that needs to be pushed
						back. currLen is how far to push back.
						p pointing to where zlibBuffer should copy
						to.  postInflateLen is amount to copy there. */
					if (currLen < (ssl->insize - ssl->inlen)) {
						/* Good, fits in current buffer.  Move all valid
							data back currLen */
						memmove(c + currLen, c,
							ssl->inlen - (int32)(c - ssl->inbuf));
						c += currLen;
						memcpy(p, ssl->zlibBuffer, postInflateLen);
						mac = p + postInflateLen;
						pend = mac;
					} else {
						/* Need to realloc more space AND push the records
							back */
						ssl->err = SSL_ALERT_INTERNAL_ERROR;
						psFree(ssl->zlibBuffer); ssl->zlibBuffer = NULL;
						inflateEnd(&ssl->inflate);
						psTraceInfo("ZLIB buffer management needed\n");
						goto encodeResponse;
					}
				}
				/* Finally increase inlen and *len to account for it now */
				ssl->inlen += currLen;
				*len += currLen;
				ssl->rec.len += currLen;
			}
		}
		psFree(ssl->zlibBuffer); ssl->zlibBuffer = NULL;
		/* Will not need the context any longer since FINISHED is the only
			supported message */
		inflateEnd(&ssl->inflate);
		ssl->compression = 2;
	}
#endif /* USE_ZLIB_COMPRESSION */		
	
/*
	Check now for maximum plaintext length of 16kb. 
*/
	if (ssl->maxPtFrag == 0xFF) { /* Still negotiating size */
		if ((int32)(pend - p) > SSL_MAX_PLAINTEXT_LEN) {
			ssl->err = SSL_ALERT_RECORD_OVERFLOW;
			psTraceInfo("Record overflow\n");
			goto encodeResponse;
		}
	} else {
		if ((int32)(pend - p) > ssl->maxPtFrag) {
			ssl->err = SSL_ALERT_RECORD_OVERFLOW;
			psTraceInfo("Record overflow\n");
			goto encodeResponse;
		}
	}


/*
	Take action based on the actual record type we're dealing with
	'p' points to the start of the data, and 'pend' points to the end
*/
	switch (ssl->rec.type) {
	case SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC:
		psTraceStrHs(">>> %s parsing CHANGE_CIPHER_SPEC message\n",
			(ssl->flags & SSL_FLAGS_SERVER) ? "Server" : "Client");
/*
		Body is single byte with value 1 to indicate that the next message
		will be encrypted using the negotiated cipher suite
*/
		if (pend - p < 1) {
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			psTraceInfo("Invalid length for CipherSpec\n");
			goto encodeResponse;
		}
		if (*p == 1) {
			p++;
		} else {
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			psTraceInfo("Invalid value for CipherSpec\n");
			goto encodeResponse;
		}
		

		*remaining = *len - (c - origbuf);
		*buf = c;
/*
		If we're expecting finished, then this is the right place to get
		this record.  It is really part of the handshake but it has its
		own record type.
		Activate the read cipher callbacks, so we will decrypt incoming
		data from now on.
*/
		if (ssl->hsState == SSL_HS_FINISHED) {
			sslActivateReadCipher(ssl);
		} else {
#ifdef USE_STATELESS_SESSION_TICKETS
			/* RFC 5077 allows the server to not acknowlege whether or not it
				accepted our session ticket in the SERVER_HELLO extension so
				there was no place prior to recieving this CCS to find out.
				Different cipher suites types will be in different states */
			if (ssl->hsState == SSL_HS_CERTIFICATE && ssl->sid &&
					ssl->sid->sessionTicketFlag == SESS_TICKET_FLAG_IN_LIMBO) {
				/* Do all the things that should have been done earlier */
				ssl->flags |= SSL_FLAGS_RESUMED;
#ifdef USE_MATRIXSSL_STATS
				matrixsslUpdateStat(ssl, RESUMPTIONS_STAT, 1);
#endif
				if (sslCreateKeys(ssl) < 0) {
					ssl->err = SSL_ALERT_INTERNAL_ERROR;
					goto encodeResponse;
				}
				ssl->hsState = SSL_HS_FINISHED;
				sslActivateReadCipher(ssl);
				ssl->sid->sessionTicketFlag = 0;
#ifdef USE_ANON_DH_CIPHER_SUITE
			/* Anon DH could be in SERVER_KEY_EXCHANGE state */
			} else if ((ssl->flags & SSL_FLAGS_ANON_CIPHER) &&
					(ssl->hsState == SSL_HS_SERVER_KEY_EXCHANGE) && ssl->sid &&
					ssl->sid->sessionTicketFlag == SESS_TICKET_FLAG_IN_LIMBO) {
				/* Do all the things that should have been done earlier */
				ssl->flags |= SSL_FLAGS_RESUMED;
#ifdef USE_MATRIXSSL_STATS
				matrixsslUpdateStat(ssl, RESUMPTIONS_STAT, 1);
#endif
				if (sslCreateKeys(ssl) < 0) {
					ssl->err = SSL_ALERT_INTERNAL_ERROR;
					goto encodeResponse;
				}
				ssl->hsState = SSL_HS_FINISHED;
				sslActivateReadCipher(ssl);
				ssl->sid->sessionTicketFlag = 0;
#endif /* USE_ANON_DH_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
			/* PSK could be in SERVER_KEY_EXCHANGE state */
			} else if ((ssl->flags & SSL_FLAGS_PSK_CIPHER) &&
					(ssl->hsState == SSL_HS_SERVER_KEY_EXCHANGE) && ssl->sid &&
					ssl->sid->sessionTicketFlag == SESS_TICKET_FLAG_IN_LIMBO) {
				/* Do all the things that should have been done earlier */
				ssl->flags |= SSL_FLAGS_RESUMED;
#ifdef USE_MATRIXSSL_STATS
				matrixsslUpdateStat(ssl, RESUMPTIONS_STAT, 1);
#endif
				if (sslCreateKeys(ssl) < 0) {
					ssl->err = SSL_ALERT_INTERNAL_ERROR;
					goto encodeResponse;
				}
				ssl->hsState = SSL_HS_FINISHED;
				sslActivateReadCipher(ssl);
				ssl->sid->sessionTicketFlag = 0;
#endif /* USE_PSK_CIPHER_SUITE */
			} else {
				ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
				psTraceIntInfo("Invalid CipherSpec order: %d\n", ssl->hsState);
				goto encodeResponse;
			}
#else		
			ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
			psTraceIntInfo("Invalid CipherSpec order: %d\n", ssl->hsState);
			goto encodeResponse;
#endif			
		}
		return MATRIXSSL_SUCCESS;

	case SSL_RECORD_TYPE_ALERT:
/*
		Decoded an alert
		1 byte alert level (warning or fatal)
		1 byte alert description corresponding to SSL_ALERT_*
*/
		if (pend - p < 2) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Error in length of alert record\n");
			goto encodeResponse;
		}
		*alertLevel = *p; p++;
		*alertDescription = *p; p++;
		*len =  2;
		psTraceIntInfo("Received alert %d\n", (int32)(*alertDescription));
/*
		If the alert is fatal, or is a close message (usually a warning),
		flag the session with ERROR so it cannot be used anymore.
		Caller can decide whether or not to close on other warnings.
*/
		if (*alertLevel == SSL_ALERT_LEVEL_FATAL) { 
			ssl->flags |= SSL_FLAGS_ERROR;
		}
		if (*alertDescription == SSL_ALERT_CLOSE_NOTIFY) {
			ssl->flags |= SSL_FLAGS_CLOSED;
		}
		*buf = c;
		return SSL_ALERT;

	case SSL_RECORD_TYPE_HANDSHAKE:
/*
		We've got one or more handshake messages in the record data.
		The handshake parsing function will take care of all messages
		and return an error if there is any problem.
		If there is a response to be sent (either a return handshake
		or an error alert, send it).  If the message was parsed, but no
		response is needed, loop up and try to parse another message
*/
#ifdef USE_CERT_CHAIN_PARSING
		if (ssl->rec.partial) {
			if (ssl->rec.hsBytesParsed == 0) {
/*
				Account for the SSL record header for first pass
*/
				ssl->rec.hsBytesParsed = ssl->recordHeadLen;
			}
		}
#endif
		rc = parseSSLHandshake(ssl, (char*)p, (uint32)(pend - p));
		/* If the entire fragment is present, the parse has occured */
		if (ssl->fragMessage != NULL) {
			if (ssl->fragIndex == ssl->fragTotal) {
				psFree(ssl->fragMessage);
				ssl->fragMessage = NULL;
				ssl->fragIndex = ssl->fragTotal = 0;
			}
		}
		switch (rc) {
		case MATRIXSSL_SUCCESS:
			*remaining = *len - (c - origbuf);
			*buf = c;
			return MATRIXSSL_SUCCESS;


		case SSL_PROCESS_DATA:
			/*
				We're here when we've processed an SSL header that requires
				a response. In all cases (except FALSE START), we would not
				expect to have any data remaining in the incoming buffer, since
				the peer would be waiting for our response.
			 */
#ifdef ENABLE_FALSE_START
			if (c < origbuf + *len) {
				/* 
					If there's still incoming data in the buffer, it could be
					FALSE START app data immediately after the FINISHED message,
					and before we've had a chance to encode and send our 
					CHANGE_CIPHER_SPEC and FINISHED message. We hack around
					some values to support this case.
					http://tools.ietf.org/html/draft-bmoeller-tls-falsestart-00
				 */
				if (*c == SSL_RECORD_TYPE_APPLICATION_DATA && 
						ssl->hsState == SSL_HS_DONE &&
						(ssl->flags & SSL_FLAGS_SERVER)) {
					psTraceHs(">>> Server buffering FALSE START APPLICATION_DATA\n");
					ssl->flags |= SSL_FLAGS_FALSE_START;
					*remaining = *len - (c - origbuf);
					*buf = c;
				} else {
					/*
						Implies successful parse of supposed last message in
						flight so check for the corner cases and reset the
						buffer to start to write response
					*/
#endif
					if (*c == SSL_RECORD_TYPE_APPLICATION_DATA && 
							ssl->hsState == SSL_HS_DONE &&
							(ssl->flags & SSL_FLAGS_SERVER)) {
						/* If this asserts, try defining ENABLE_FALSE_START */
						psAssert(origbuf + *len == c);
						*buf = origbuf;
					} else if (*c == SSL_RECORD_TYPE_APPLICATION_DATA &&
							ssl->hsState == SSL_HS_HELLO_REQUEST &&
							(c < (origbuf + *len))) {
						/* message tacked on to end of HELLO_REQUEST. Very
							complicated scenario for the state machine and
							API so we're going to ignore the HELLO_REQUEST
							(fine by the specification) and give precedence to
							the app data. This backup flag data was set aside
							in sslResetContext when	the HELLO_REQUEST was
							received */
						*buf = c;
#ifdef USE_CLIENT_SIDE_SSL
						ssl->sec.anon = ssl->anonBk;
						ssl->flags = ssl->flagsBk;
						ssl->bFlags = ssl->bFlagsBk;
#endif
						ssl->hsState = SSL_HS_DONE;
						return MATRIXSSL_SUCCESS;
					} else {
						/* If this asserts, please report the values of the 
							*c byte and ssl->hsState to support */
						psAssert(origbuf + *len == c);
						*buf = origbuf;
					}
#ifdef ENABLE_FALSE_START
				}
			} else {
				*buf = origbuf;
			}
#endif
			goto encodeResponse;

		case MATRIXSSL_ERROR:
		case SSL_MEM_ERROR:
			if (ssl->err == SSL_ALERT_NONE) {
				ssl->err = SSL_ALERT_INTERNAL_ERROR;
			}
			goto encodeResponse;
		}
		break;

	case SSL_RECORD_TYPE_APPLICATION_DATA:
/*
		Data is in the out buffer, let user handle it
		Don't allow application data until handshake is complete, and we are
		secure.  It is ok to let application data through on the client
		if we are in the SERVER_HELLO state because this could mean that
		the client has sent a CLIENT_HELLO message for a rehandshake
		and is awaiting reply.
*/
		if ((ssl->hsState != SSL_HS_DONE && ssl->hsState != SSL_HS_SERVER_HELLO)
				|| !(ssl->flags & SSL_FLAGS_READ_SECURE)) {
			ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
			psTraceIntInfo("Incomplete handshake: %d\n", ssl->hsState);
			goto encodeResponse;
		}
/*
		Insitu for application data is more tricky than it is for SSL handshake
		messages.  This is because there is never going to be any 'out' data
		for handshake messages until the final record of a flight is parsed.
		Whereas application data necessarily has an 'out' for every 'in'
		record because it is the decrypted data of the 'in'.  So, the managed
		cases result anytime there is more than 1 app record in the 'in' buffer
		where the insitu must hold BOTH a decrypted buffer and the next
		encrypted record.
		
		Create so that:
		.	buf points to start of any remaining unencrypted data
		.	start is length of remaining encrypted data yet to decode
		.	len is length of unencrypted data ready for user processing

*/
		*buf = c;
		*remaining = *len - (c - origbuf);	
		*len = mac - origbuf;
/*
		SECURITY - If the mac is at the current out->end, then there is no data 
		in the record.  These records are valid, but are usually not sent by
		the application layer protocol.  Rather, they are initiated within the 
		remote SSL protocol implementation to avoid some types of attacks when
		using block ciphers.  For more information see:
		http://www.openssl.org/~bodo/tls-cbc.txt

		SECURITY - Returning blank messages has the potential
		for denial of service, because we are not changing the state of the
		system in any way when processing these messages, (although the upper
		level protocol may). To counteract this, we maintain a counter 
		that we share with other types of ignored messages. If too many in a 
		row occur, an alert will be sent and the connection closed.
		We implement this as a leaky bucket, so if a non-blank message comes
		in, the ignored message count is decremented, ensuring that we only
		error on a large number of consecutive blanks.
*/
		if (ctStart == mac) {
			if (ssl->ignoredMessageCount++ >= SSL_MAX_IGNORED_MESSAGE_COUNT) {
				ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
				psTraceIntInfo("Exceeded limit on ignored messages: %d\n", 
							   SSL_MAX_IGNORED_MESSAGE_COUNT);
				goto encodeResponse;
			}
		} else if (ssl->ignoredMessageCount > 0) {
			ssl->ignoredMessageCount--;
		}
		
		return SSL_PROCESS_DATA;
	}
/*
	Should not get here under normal operation
*/
	psTraceIntInfo("Invalid record type in matrixSslDecode: %d\n",
		ssl->rec.type);
	*error = PS_PROTOCOL_FAIL;
	return MATRIXSSL_ERROR;

encodeResponse:
/*
	We decoded a record that needs a response, either a handshake response
	or an alert if we've detected an error.  
*/
#ifdef ENABLE_FALSE_START
	if ((ssl->flags & SSL_FLAGS_FALSE_START) && *buf != origbuf) {
		/*
			Encode the output into ssl->outbuf in this case, rather than back
			into origbuf, since there is still valid data in origbuf that 
			needs to be decoded later.
			Other places in this function we do not reference the ssl inbuf
			or outbuf directly, but this was the cleanest way for this hack.
			Caller must test to see if *buf has been modified if 
			ssl->flags & SSL_FLAGS_FALSE_START
		 */
		tmpout.buf = tmpout.start = tmpout.end = ssl->outbuf + ssl->outlen;
		tmpout.size = ssl->outsize - ssl->outlen;
		memset(origbuf, 0x0, (*buf - origbuf));	/* SECURITY (see below) */
	} else {
#endif
		psAssert(origbuf == *buf);
		tmpout.buf = tmpout.end = tmpout.start = origbuf;
		tmpout.size = size;

/*	
		SECURITY - Clear the decoded incoming record from outbuf before encoding
		the response into outbuf.
*/
		memset(tmpout.buf, 0x0, tmpout.size);

#ifdef ENABLE_FALSE_START
	}
#endif

#ifdef USE_CLIENT_SIDE_SSL	
	if (ssl->hsState == SSL_HS_HELLO_REQUEST) {
/*
		Don't clear the session info.  If receiving a HELLO_REQUEST from a 
		MatrixSSL enabled server the determination on whether to reuse the 
		session is made on that side, so always send the current session
*/
		rc = matrixSslEncodeClientHello(ssl, &tmpout, 0, 0, requiredLen, NULL);
	} else {
#endif /* USE_CLIENT_SIDE_SSL */
		rc = sslEncodeResponse(ssl, &tmpout, requiredLen);
#ifdef USE_CLIENT_SIDE_SSL		
	}
#endif /* USE_CLIENT_SIDE_SSL */
	*alertDescription = SSL_ALERT_NONE;
	if (rc == MATRIXSSL_SUCCESS) {
		if (ssl->err != SSL_ALERT_NONE) {
			/* We know this is always a fatal alert due to an error in
				message parsing or creation so flag this session as error */
			ssl->flags |= SSL_FLAGS_ERROR;
/*
			If tmpbuf has data, it is an alert that needs to be sent so let
			it fall through. Not sure how we would ever not have data in tmpout
*/
			if (tmpout.buf == tmpout.end) {
				psTraceInfo("Unexpected data\n");
				*error = PS_PROTOCOL_FAIL;
				return MATRIXSSL_ERROR;
			}
			*alertDescription = (unsigned char)ssl->err;
			*alertLevel = SSL_ALERT_LEVEL_FATAL;
		}
#ifdef ENABLE_FALSE_START
		if ((ssl->flags & SSL_FLAGS_FALSE_START) && *buf != origbuf) {
			/* Update outlen with the data we added */
			ssl->outlen += tmpout.end - tmpout.buf;
		} else {
#endif
			*remaining = 0;
			*len = tmpout.end - tmpout.buf;
#ifdef ENABLE_FALSE_START
		}
#endif
		return SSL_SEND_RESPONSE;
	}
	if (rc == SSL_FULL) {
#ifdef ENABLE_FALSE_START
		/* We don't support growing outbuf in the false start case */
		if (*buf != origbuf) {
			psAssert(rc != SSL_FULL);
			*error = rc;
			return MATRIXSSL_ERROR;
		}
#endif
		ssl->flags |= SSL_FLAGS_NEED_ENCODE;
		*len = 0; /* No data left to decode */
		/* requiredLen is set by sslEncode Response or ClientHello above */
		return SSL_FULL;
	}
	psAssert(rc < 0);
	*error = rc;
	return MATRIXSSL_ERROR;
}

#ifndef USE_PKCS11
/* Return the number of additional MAC compressions that are needed to blind
	the padding/hmac logic for thwarting Lucky 13 style attacks
*/
static int32 addCompressCount(ssl_t *ssl, int32 padLen)
{
	int32	l1, l2, c1, c2, len;
	
	c1 = c2 = 0;
	len = ssl->rec.len;
	
#ifdef USE_TLS_1_1
	if (ssl->flags & SSL_FLAGS_TLS_1_1) {
		len -= ssl->deBlockSize; /* skip explicit IV */
	}
#endif	
	l1 = 13 + len - ssl->deMacSize;
	l2 = 13 + len - padLen - 1 - ssl->deMacSize;
	
	if (ssl->deMacSize == SHA1_HASH_SIZE || ssl->deMacSize == SHA256_HASH_SIZE){
		while (l1 > 64) {
			c1++; l1 -= 64;
		} 
		if (l1 > 56) {
			c1++;
		}
		while (l2 > 64) {
			c2++; l2 -= 64;
		}
		if (l2 > 56) {
			c2++;
		}
#ifdef USE_SHA384		
	} else if (ssl->deMacSize == SHA384_HASH_SIZE) {
		while (l1 > 128) {
			c1++; l1 -= 128;
		} 
		if (l1 > 112) {
			c1++;
		}
		while (l2 > 128) {
			c2++; l2 -= 128;
		}
		if (l2 > 112) {
			c2++;
		}
	
#endif	
	}

	return c1 - c2;
}
#endif

/******************************************************************************/
/*
	The workhorse for parsing handshake messages.  Also enforces the state
	machine	for proper ordering of handshake messages.
	Parameters:
	ssl - ssl context
	inbuf - buffer to read handshake message from
	len - data length for the current ssl record.  The ssl record
		can contain multiple handshake messages, so we may need to parse
		them all here.
	Return:
		MATRIXSSL_SUCCESS
		SSL_PROCESS_DATA
		MATRIXSSL_ERROR - see ssl->err for details
		MEM_FAIL 
		-MATRIXSSL_ERROR and MEM_FAIL will be caught and an alert sent.  If you
			want to specifiy the alert the set ss->err.  Otherwise it will
			be an INTERNAL_ERROR
*/
static int32 parseSSLHandshake(ssl_t *ssl, char *inbuf, uint32 len)
{
	unsigned char	*c, *end;
	unsigned char	hsType;
	int32			rc, i = 0;
	short			renegotiationExt;
	uint32			hsLen, extLen, extType, cipher = 0;
	unsigned char	hsMsgHash[SHA384_HASH_SIZE];
	void			*pkiData = NULL;

    /* compile warnning */
    IGNORE_PARAMETER(pkiData);

#ifdef USE_SERVER_SIDE_SSL
	unsigned char	*p;
	int32			suiteLen, compareMin, compareMaj;
	uint32			challengeLen, pubKeyLen;
#ifdef USE_CLIENT_AUTH
	int32			certVerifyLen;
#ifdef USE_RSA	
	unsigned char	certVerify[SHA384_HASH_SIZE];
#endif /* USE_RSA */
#endif /* USE_CLIENT_AUTH */
#endif /* USE_SERVER_SIDE_SSL */

#ifdef USE_CLIENT_SIDE_SSL
#ifndef USE_ONLY_PSK_CIPHER_SUITE
	int32			certTypeLen;
#endif	
	uint32			sessionIdLen;
	unsigned char	*extData;
#endif /* USE_CLIENT_SIDE_SSL */

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	int32			certChainLen, parseLen = 0;
	uint32			certLen;
	psX509Cert_t	*cert, *currentCert, *foundIssuer;
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#endif /* USE_ONLY_PSK_CIPHER_SUITE */


#ifdef USE_TLS_1_2
#if defined(USE_CLIENT_SIDE_SSL) && defined(USE_DHE_CIPHER_SUITE)
	uint32	skeHashSigAlg;
#endif
#if defined(VALIDATE_KEY_MATERIAL) && defined(USE_SERVER_SIDE_SSL)
	psX509Cert_t		*crt;
#endif
#ifndef USE_ONLY_PSK_CIPHER_SUITE
	uint32				sigAlgMatch;
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	uint32				hashSigAlg;
#endif /* USE_SERVER_SIDE */
#endif /* ! ONLY_PSK  */
#endif /* USE_TLS_1_2 */

#if defined(USE_CLIENT_SIDE_SSL) && defined(USE_DHE_CIPHER_SUITE)
#ifndef USE_ONLY_PSK_CIPHER_SUITE
	psDigestContext_t	digestCtx;
	unsigned char		*sigStart, *sigStop;
#endif	
#ifdef USE_RSA_CIPHER_SUITE
	unsigned char		sigOut[SHA384_HASH_SIZE];
#endif /* USE_RSA_CIPHER_SUITE */	
	uint32				pubDhLen, hashSize;
#endif /* USE_CLIENT_SIDE_SSL && USE_DHE_CIPHER_SUITE */


#if defined(USE_PSK_CIPHER_SUITE) && defined(USE_SERVER_SIDE_SSL)
	unsigned char	*pskKey;
	uint32			pskLen;
#endif /* USE_PSK_CIPHER_SUITE && USE_SERVER_SIDE_SSL */

#if defined(USE_RSA_CIPHER_SUITE) && defined(USE_SERVER_SIDE_SSL) 
	psPool_t		*ckepkiPool = NULL;
#endif
#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_CLIENT_SIDE_SSL) && defined(USE_DHE_CIPHER_SUITE)
	psPool_t		*skepkiPool = NULL;
#endif
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH) 
	psPool_t		*cvpkiPool = NULL;
#endif
#endif


#if defined(USE_SERVER_SIDE_SSL) &&  defined(USE_ECC_CIPHER_SUITE)
	psEccSet_t		*eccParams = NULL;
	uint32			dataLen;
#endif /* SERVER && USE_ECC_CIPHER_SUITE */


	rc = MATRIXSSL_SUCCESS;
	c = (unsigned char*)inbuf;
	end = (unsigned char*)(inbuf + len);
	
	/* Immediately check if we are working with a fragmented message. */
	if (ssl->fragMessage != NULL) {
		/* Just borrowing hsLen variable.  Is the rest here or do we still
			need more? */
		hsLen = min((uint32)(end - c), ssl->fragTotal - ssl->fragIndex);
		memcpy(ssl->fragMessage + ssl->fragIndex, c, hsLen);
		ssl->fragIndex += hsLen;
		c += hsLen;
		
		if (ssl->fragIndex == ssl->fragTotal) {
			c = ssl->fragMessage + ssl->hshakeHeadLen;
			end = ssl->fragMessage + ssl->fragTotal;
			hsLen = ssl->fragTotal - ssl->hshakeHeadLen;
			goto SKIP_HSHEADER_PARSE;
		} else {
			return MATRIXSSL_SUCCESS;
		}				
	}

	
#ifdef USE_CERT_CHAIN_PARSING
	if (ssl->rec.partial && (ssl->rec.hsBytesParsed > ssl->recordHeadLen)) {
		goto SKIP_HSHEADER_PARSE;
	}
#endif /* USE_CERT_CHAIN_PARSING */

parseHandshake:
	if (end - c < 1) {
		ssl->err = SSL_ALERT_DECODE_ERROR;
		psTraceInfo("Invalid length of handshake message 1\n");
		psTraceIntInfo("%d\n", (int32)(end - c));
		return MATRIXSSL_ERROR;
	}
	hsType = *c; c++;
	
#ifndef SSL_REHANDSHAKES_ENABLED		
/*
	If all rehandshaking is disabled, just catch that here and alert.
*/
	if (ssl->flags & SSL_FLAGS_SERVER) {
		if (hsType == SSL_HS_CLIENT_HELLO && ssl->hsState == SSL_HS_DONE) {
			psTraceInfo("Closing conn with client. Rehandshake is disabled\n");
			ssl->err = SSL_ALERT_NO_RENEGOTIATION;
			return MATRIXSSL_ERROR;
		}
	} else {
		if (hsType == SSL_HS_HELLO_REQUEST && ssl->hsState == SSL_HS_DONE) {
			psTraceInfo("Closing conn with server. Rehandshake is disabled\n");
			ssl->err = SSL_ALERT_NO_RENEGOTIATION;
			return MATRIXSSL_ERROR;
		}
	}
#endif  /* SSL_REHANDSHAKES_ENABLED */

	
/*
	hsType is the received handshake type and ssl->hsState is the expected
	handshake type.  If it doesn't match, there are some possible cases
	that are not errors.  These are checked here. 
*/
	if (hsType != ssl->hsState && 
			(hsType != SSL_HS_CLIENT_HELLO || ssl->hsState != SSL_HS_DONE)) {

/*
		A mismatch is possible in the client authentication case.
		The optional CERTIFICATE_REQUEST may be appearing instead of 
		SERVER_HELLO_DONE.
*/
		if ((hsType == SSL_HS_CERTIFICATE_REQUEST) &&
				(ssl->hsState == SSL_HS_SERVER_HELLO_DONE)) {
/*
			This is where the client is first aware of requested client
			authentication so we set the flag here.

*/
			ssl->flags |= SSL_FLAGS_CLIENT_AUTH;
			ssl->hsState = SSL_HS_CERTIFICATE_REQUEST;
			goto hsStateDetermined;		
		}
/*
		Another possible mismatch allowed is for a HELLO_REQEST message.
		Indicates a rehandshake initiated from the server.
*/
		if ((hsType == SSL_HS_HELLO_REQUEST) &&
				(ssl->hsState == SSL_HS_DONE) &&
				!(ssl->flags & SSL_FLAGS_SERVER)) {
			sslResetContext(ssl);
			ssl->hsState = hsType;
			goto hsStateDetermined;
		}
		
#ifdef USE_STATELESS_SESSION_TICKETS
		/* 	Another possible mismatch allowed is for a
			SSL_HS_NEW_SESSION_TICKET message.  */
		if ((hsType == SSL_HS_NEW_SESSION_TICKET) &&
				(ssl->hsState == SSL_HS_FINISHED) && ssl->sid &&
				(ssl->sid->sessionTicketFlag == SESS_TICKET_FLAG_RECVD_EXT) &&
				!(ssl->flags & SSL_FLAGS_SERVER)) {
			ssl->hsState = hsType;
			goto hsStateDetermined;
		}

#endif /* USE_STATELESS_SESSION_TICKETS */

#ifdef USE_PSK_CIPHER_SUITE
/*
		PSK suites are probably not including SERVER_KEY_EXCHANGE message 
*/
		if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
			if ((hsType == SSL_HS_SERVER_HELLO_DONE) &&
					(ssl->hsState == SSL_HS_SERVER_KEY_EXCHANGE)) {
#ifdef USE_DHE_CIPHER_SUITE
/*
				DH kex suites must be sending a SERVER_KEY_EXCHANGE message
*/
				if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
					psTraceIntInfo("Expecting SKE message: %d\n", hsType);
					ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
					return MATRIXSSL_ERROR;
				}
#endif /* USE_DHE_CIPHER_SUITE */
				ssl->hsState = hsType;
				goto hsStateDetermined;
			}
		}		
#endif /* USE_PSK_CIPHER_SUITE */


		ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
		psTraceIntInfo("Out-of-order handshake message: %d\n", hsType);
		psTraceIntInfo("Wanted: %d\n", ssl->hsState);
		return MATRIXSSL_ERROR;
	}
	
hsStateDetermined:	
	if (hsType == SSL_HS_CLIENT_HELLO) { 
		sslInitHSHash(ssl);
		if (ssl->hsState == SSL_HS_DONE) {
#ifdef SSL_REHANDSHAKES_ENABLED
			/* This is a mechanism where each X bytes of data transfer gains
				you a re-handshake credit.  Prevents the DOS attack	of repeat
				re-handshake requests */
			if (ssl->rehandshakeCount <= 0) {
				ssl->err = SSL_ALERT_NO_RENEGOTIATION;
				psTraceInfo("Client re-handshaking denied\n");
				return MATRIXSSL_ERROR;
			}
			ssl->rehandshakeBytes = 0; /* reset */
			ssl->rehandshakeCount--;
#endif /* SSL_REHANDSHAKES_ENABLED */
/*
			Rehandshake. Server receiving client hello on existing connection
*/
			sslResetContext(ssl);
			ssl->hsState = hsType;
		}
	}

/*
	We need to get a copy of the message hashes to compare to those sent
	in the finished message (which does not include a hash of itself)
	before we update the handshake hashes
*/
	if (ssl->hsState == SSL_HS_FINISHED) {
		sslSnapshotHSHash(ssl, hsMsgHash, 
			(ssl->flags & SSL_FLAGS_SERVER) ? 0 : SSL_FLAGS_SERVER);
	}
#ifdef USE_CLIENT_AUTH
	if (ssl->hsState == SSL_HS_CERTIFICATE_VERIFY) {
		/* Same issue as above for client auth.  Need a handshake snapshot
			that doesn't include this message we are about to process */
		sslSnapshotHSHash(ssl, hsMsgHash, -1);
	}
#endif /* USE_CLIENT_AUTH */

/*
	Process the handshake header and update the ongoing handshake hash
	SSLv3:
		1 byte type
		3 bytes length
	SSLv2:
		1 byte type
*/
	if (ssl->rec.majVer >= SSL3_MAJ_VER) {
		if (end - c < 3) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Invalid length of handshake message 2\n");
			psTraceIntInfo("%d\n", (int32)(end - c));
			return MATRIXSSL_ERROR;
		}
		hsLen = *c << 16; c++;
		hsLen += *c << 8; c++;
		hsLen += *c; c++;
#ifdef USE_CERT_CHAIN_PARSING
		if (((uint32)(end - c) < hsLen) && !ssl->rec.partial) {
#else
		if ((uint32)(end - c) < hsLen) {
#endif
			/* Support for fragmented handshake messages - non-DTLS */
			if (ssl->fragMessage == NULL) {
				/* Initial indication there is a fragmented message */
				ssl->fragTotal = hsLen + ssl->hshakeHeadLen;
				ssl->fragMessage = psMalloc(ssl->hsPool, ssl->fragTotal);
				if (ssl->fragMessage == NULL) {
					ssl->err = SSL_ALERT_INTERNAL_ERROR;
					psTraceInfo("Memory allocation error\n");
					return MATRIXSSL_ERROR;
				}
				ssl->fragIndex = (uint32)(end - c) + ssl->hshakeHeadLen;
				memcpy(ssl->fragMessage, c - ssl->hshakeHeadLen,
					ssl->fragIndex);
				return MATRIXSSL_SUCCESS;
			} else {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid handshake length\n");
				return MATRIXSSL_ERROR;
			}
		}
SKIP_HSHEADER_PARSE:

#ifdef USE_CERT_CHAIN_PARSING
			if (ssl->rec.partial) {
/*
				Length of partial certificate records are being managed
				manually with ssl->rec.len.  The first pass will need to
				include the record header in the hash.
*/
				if (ssl->rec.hsBytesHashed == 0) {
					sslUpdateHSHash(ssl, c - ssl->hshakeHeadLen, ssl->rec.len);
				} else {
					sslUpdateHSHash(ssl, c, ssl->rec.len);
				}
				ssl->rec.hsBytesHashed += ssl->rec.len;
			} else {
				sslUpdateHSHash(ssl, c - ssl->hshakeHeadLen,
					hsLen + ssl->hshakeHeadLen);
			}
#else
			sslUpdateHSHash(ssl, c - ssl->hshakeHeadLen,
				hsLen + ssl->hshakeHeadLen);

#endif

	} else if (ssl->rec.majVer == SSL2_MAJ_VER) {
/*
		Assume that the handshake len is the same as the incoming ssl record
		length minus 1 byte (type), this is verified in SSL_HS_CLIENT_HELLO
*/
		hsLen = len - 1;
		sslUpdateHSHash(ssl, (unsigned char*)inbuf, len);
	} else {
		ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
		psTraceIntInfo("Invalid record version: %d\n", ssl->rec.majVer);
		return MATRIXSSL_ERROR;
	}
/*
	Finished with header.  Process each type of handshake message.
*/
	switch(ssl->hsState) {

#ifdef USE_SERVER_SIDE_SSL
	case SSL_HS_CLIENT_HELLO:
/*
		First two bytes are the highest supported major and minor SSL versions
*/
		psTraceHs(">>> Server parsing CLIENT_HELLO\n");
#ifdef USE_MATRIXSSL_STATS
		matrixsslUpdateStat(ssl, CH_RECV_STAT, 1);
#endif		
		if (end - c < 2) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Invalid ssl header version length\n");
			return MATRIXSSL_ERROR;
		}
#ifdef USE_TLS_1_2
#ifndef USE_ONLY_PSK_CIPHER_SUITE
		sigAlgMatch	= 0;
#endif
#endif
		ssl->reqMajVer = *c; c++;
		ssl->reqMinVer = *c; c++;
/*
		Client should always be sending highest supported protocol.  Server
		will reply with a match or a lower version if enabled (or forced).
*/
		if (ssl->majVer != 0) {
			/* If our forced server version is a later protocol than their 
				request, we have to exit */
			if (ssl->reqMinVer < ssl->minVer) {
				ssl->err = SSL_ALERT_PROTOCOL_VERSION;
				psTraceInfo("Won't support client's SSL version\n");
				return MATRIXSSL_ERROR;
			}
			/* Otherwise we just set our forced version to act like it was
				what the client wanted in order to move through the standard 
				negotiation. */
			compareMin = ssl->minVer;
			compareMaj = ssl->majVer;
		} else {
			compareMin = ssl->reqMinVer;
			compareMaj = ssl->reqMajVer;
		}
		
		if (compareMaj >= SSL3_MAJ_VER) {
			ssl->majVer = compareMaj;
#ifdef USE_TLS
			if (compareMin >= TLS_MIN_VER) {
#ifndef DISABLE_TLS_1_0			
				ssl->minVer = TLS_MIN_VER;
				ssl->flags |= SSL_FLAGS_TLS;
#endif				
#ifdef USE_TLS_1_1 /* TLS_1_1 */
				if (compareMin >= TLS_1_1_MIN_VER) {
#ifndef DISABLE_TLS_1_1				
					ssl->minVer = TLS_1_1_MIN_VER;
					ssl->flags |= SSL_FLAGS_TLS_1_1 | SSL_FLAGS_TLS;
#endif					
				}
#ifdef USE_TLS_1_2
				if (compareMin == TLS_1_2_MIN_VER) {
					ssl->minVer = TLS_1_2_MIN_VER;
					ssl->flags |= SSL_FLAGS_TLS_1_2 | SSL_FLAGS_TLS_1_1 | SSL_FLAGS_TLS;
				}
#endif /* USE_TLS_1_2 */				
#endif /* USE_TLS_1_1 */
				if (ssl->minVer == 0) {
					/* TLS versions are disabled.  Go SSLv3 if available. */
#ifdef DISABLE_SSLV3
					ssl->err = SSL_ALERT_PROTOCOL_VERSION;
					psTraceInfo("Can't support client's SSL version\n");
					return MATRIXSSL_ERROR;
#endif
					ssl->minVer = SSL3_MIN_VER;
				}
			} else if (compareMin == 0) {
#ifdef DISABLE_SSLV3
				ssl->err = SSL_ALERT_PROTOCOL_VERSION;
				psTraceInfo("Client wanted to talk SSLv3 but it's disabled\n");
				return MATRIXSSL_ERROR;
#else			
				ssl->minVer = SSL3_MIN_VER;
#endif /* DISABLE_SSLV3 */				
			}

#else
			ssl->minVer = SSL3_MIN_VER;

#endif /* USE_TLS */

		} else {
			ssl->err = SSL_ALERT_PROTOCOL_VERSION;
			psTraceIntInfo("Unsupported ssl version: %d\n", compareMaj);
			return MATRIXSSL_ERROR;
		}
				
/*
		Support SSLv3 and SSLv2 ClientHello messages.  Browsers usually send v2
		messages for compatibility
*/
		if (ssl->rec.majVer > SSL2_MAJ_VER) {
/*
			Next is a 32 bytes of random data for key generation
			and a single byte with the session ID length
*/
			if (end - c < SSL_HS_RANDOM_SIZE + 1) {
				ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
				psTraceIntInfo("Invalid length of random data %d\n",
					(int32)(end - c));
				return MATRIXSSL_ERROR;
			}
			memcpy(ssl->sec.clientRandom, c, SSL_HS_RANDOM_SIZE);
			c += SSL_HS_RANDOM_SIZE;
			ssl->sessionIdLen = *c; c++;
/*
			If a session length was specified, the client is asking to
			resume a previously established session to speed up the handshake.
*/
			if (ssl->sessionIdLen > 0) {		
				if (ssl->sessionIdLen > SSL_MAX_SESSION_ID_SIZE || 
						end - c < ssl->sessionIdLen) {
					ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
#ifdef USE_MATRIXSSL_STATS
					matrixsslUpdateStat(ssl, FAILED_RESUMPTIONS_STAT, 1);
#endif					
					return MATRIXSSL_ERROR;
				}
				memcpy(ssl->sessionId, c, ssl->sessionIdLen);
				c += ssl->sessionIdLen;
/*
				Look up the session id for ssl session resumption.  If found, we
				load the pre-negotiated masterSecret and cipher.
				A resumed request must meet the following restrictions:
					The id must be present in the lookup table
					The requested version must match the original version
					The cipher suite list must contain the original cipher suite
*/
				if (matrixResumeSession(ssl) >= 0) {
					ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
					ssl->flags |= SSL_FLAGS_RESUMED;
#ifdef USE_MATRIXSSL_STATS
					matrixsslUpdateStat(ssl, RESUMPTIONS_STAT, 1);
#endif						
				} else {
					ssl->flags &= ~SSL_FLAGS_RESUMED;
#ifdef USE_STATELESS_SESSION_TICKETS
					/* Client MAY generate and include a  Session ID in the
						TLS ClientHello.  If the server accepts the ticket
						and the Session ID is not empty, then it MUST respond
						with the same Session ID present in the ClientHello. */
					/* This flag means we received a session we can't resume
						but we have to send it back if we also get a ticket
						later that we like */
					ssl->sessionIdAndTicket = SESSION_ID_STANDARD;
#else
					memset(ssl->sessionId, 0, SSL_MAX_SESSION_ID_SIZE);
					ssl->sessionIdLen = 0;
#ifdef USE_MATRIXSSL_STATS
					matrixsslUpdateStat(ssl, FAILED_RESUMPTIONS_STAT, 1);
#endif
#endif
				}
			} else {
/*
				Always clear the RESUMED flag if no client session id specified
*/
				ssl->flags &= ~SSL_FLAGS_RESUMED;
			}
/*
			Next is the two byte cipher suite list length, network byte order.  
			It must not be zero, and must be a multiple of two.
*/
			if (end - c < 2) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid cipher suite list length\n");
				return MATRIXSSL_ERROR;
			}
			suiteLen = *c << 8; c++;
			suiteLen += *c; c++;
			if (suiteLen <= 0 || suiteLen & 1) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceIntInfo("Unable to parse cipher suite list: %d\n",
					suiteLen);
				return MATRIXSSL_ERROR;
			}
/*
			Now is 'suiteLen' bytes of the supported cipher suite list,
			listed in order of preference.  Loop through and find the 
			first cipher suite we support.
*/
			if (end - c < suiteLen) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Malformed clientHello message\n");
				return MATRIXSSL_ERROR;
			}
#ifdef ENABLE_SECURE_REHANDSHAKES
/*
			Below we stop looking after the first cipher we match but we need
			to search for SCSV if secure rehandshakes are on and first conn 
*/
			if (ssl->myVerifyDataLen == 0) {
				extLen = 0; /* just overloading existing var */
				while (extLen < (uint32)suiteLen) {
					cipher = c[extLen] << 8; extLen++;
					cipher += c[extLen]; extLen++;
					if (cipher == TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
						ssl->secureRenegotiationFlag = PS_TRUE;
					}
				}
			}
#endif						
			p = c + suiteLen;
			while (c < p) {
				cipher = *c << 8; c++;
				cipher += *c; c++;	
/*
				A resumed session can only match the cipher originally 
				negotiated. Otherwise, match the first cipher that we support
*/
				if (ssl->flags & SSL_FLAGS_RESUMED) {
					psAssert(ssl->cipher != NULL);
					if (ssl->cipher->ident == cipher) {
						c = p;
						break;
					}
				} else {
					if ((ssl->cipher = sslGetCipherSpec(ssl, cipher)) != NULL) {
						c = p;
						break;
					}
				}
			}
/*
			If we fell to the default cipher suite, we didn't have
			any in common with the client, or the client is being bad
			and requesting the null cipher!
*/
			if (ssl->cipher == NULL || ssl->cipher->ident != cipher || 
					cipher == SSL_NULL_WITH_NULL_NULL) {
				psTraceIntInfo("Can't support requested cipher: %d\n", cipher);
				ssl->cipher = sslGetCipherSpec(ssl, SSL_NULL_WITH_NULL_NULL);
				ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
				return MATRIXSSL_ERROR;
			}

/*
			Compression parameters
			Overloading extLen in this section
*/
			if (end - c < 1) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid compression header length\n");
				return MATRIXSSL_ERROR;
			}
			extLen = *c++;
			if ((uint32)(end - c) < extLen) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid compression header length\n");
				return MATRIXSSL_ERROR;
			}
#ifdef USE_ZLIB_COMPRESSION
			while (extLen > 0) {
				/* Client wants it and we have it.  Enable if we're not already
					in a compression state.  FUTURE: Could be re-handshake */
				if (ssl->compression == 0) {
					if (*c++ == 0x01) {
						ssl->inflate.zalloc = NULL;
						ssl->inflate.zfree = NULL;
						ssl->inflate.opaque = NULL;
						ssl->inflate.avail_in = 0;
						ssl->inflate.next_in = NULL;
						if (inflateInit(&ssl->inflate) != Z_OK) {
							psTraceInfo("inflateInit fail.  No compression\n");
						} else {
							ssl->deflate.zalloc = Z_NULL;
							ssl->deflate.zfree = Z_NULL;
							ssl->deflate.opaque = Z_NULL;
							if (deflateInit(&ssl->deflate,
									Z_DEFAULT_COMPRESSION) != Z_OK) {
								psTraceInfo("deflateInit fail.  No compression\n");
								inflateEnd(&ssl->inflate);
							} else {
								/* Init good.  Let's enable it */
								ssl->compression = 1;
							}
						}
					}
					extLen--;
				} else {
					c++;
					extLen--;
				}
			}
#else			
			c += extLen;
#endif			

/*
			There could be extension data to parse here:
			Two byte length and extension info.
			http://www.faqs.org/rfcs/rfc3546.html

			NOTE:  This c != end test is only safe because ClientHello is the
			only record/message in the flight of supported handshake protocols.
*/
			renegotiationExt = 0;
			if (c != end) {
				if (end - c < 2) {
					ssl->err = SSL_ALERT_DECODE_ERROR;
					psTraceInfo("Invalid extension header len\n");
					return MATRIXSSL_ERROR;
				}
				extLen = *c << 8; c++; /* Total length of list */
				extLen += *c; c++;
				/* extLen must be minimum 2 b type 2 b len and 0 b value */
				if ((uint32)(end - c) < extLen || extLen < 4) {
					ssl->err = SSL_ALERT_DECODE_ERROR;
					psTraceInfo("Invalid extension header len\n");
					return MATRIXSSL_ERROR;
				}
				while (c != end) { 
					extType = *c << 8; c++; /* Individual hello ext */
					extType += *c; c++;
					if (end - c < 2) {
						ssl->err = SSL_ALERT_DECODE_ERROR;
						psTraceInfo("Invalid extension header len\n");
						return MATRIXSSL_ERROR;
					}
					extLen = *c << 8; c++; /* length of one extension */
					extLen += *c; c++;
					/* Minimum extension value len is 0 bytes */
					if ((uint32)(end - c) < extLen) {
						ssl->err = SSL_ALERT_DECODE_ERROR;
						psTraceInfo("Invalid extension header len\n");
						return MATRIXSSL_ERROR;
					}
#ifdef ENABLE_SECURE_REHANDSHAKES					
/*
					Handle incoming client extensions we support.
*/
					if (extType == EXT_RENEGOTIATION_INFO) {
						renegotiationExt = 1;
						if (ssl->secureRenegotiationFlag == PS_FALSE &&
								ssl->myVerifyDataLen == 0) {
							if (extLen == 1 && *c == '\0') {
								ssl->secureRenegotiationFlag = PS_TRUE;
							} else {
								ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
								psTraceInfo("Cln sent bad renegotiationInfo\n");
								return MATRIXSSL_ERROR;
							}						
						} else if ((extLen == ssl->peerVerifyDataLen + 1) &&
								(ssl->secureRenegotiationFlag == PS_TRUE)) {
							if (*c != ssl->peerVerifyDataLen) {
								ssl->err = SSL_ALERT_DECODE_ERROR;
								psTraceInfo("Invalid renegotiation encoding\n");
								return MATRIXSSL_ERROR;
							}
							c++; extLen--; /* decr extLen when incr c */
							if (memcmp(c, ssl->peerVerifyData,
									ssl->peerVerifyDataLen) != 0) {
								psTraceInfo("Cli verify renegotiation fail\n");
								ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
								return MATRIXSSL_ERROR;
							}
						} else {
							psTraceInfo("Bad state/len of renegotiation ext\n");
							ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
							return MATRIXSSL_ERROR;
						}
					}
#endif /* ENABLE_SECURE_REHANDSHAKES */

#ifdef VALIDATE_KEY_MATERIAL
#if defined(USE_TLS_1_2) && defined(USE_CERT_PARSE)
					/* SignatureAndHashAlgorithm extension */
					if (extType == EXT_SIGNATURE_ALGORITHMS) {
						/* This extension is a bit confusing.  It is responsible
							for telling the server which sig algorithms it
							accepts so here we are checking to see if our local
							identity certificate can use its algorithm.  
							
							In theory, it sounds like the server is free to
							change the hash algorithm of the pub key algorithm
							from what the full signature algorithm of the cert
							is but this is just too much management so we're
							restricting the algorithm to what the server cert is
							
							It also has a role in cipher suite choice but we've
							already tested our cert that it supports the cs
							algorithms so we can ignore that here
						*/
						sigAlgMatch = 1; /* Sent the extension */
						suiteLen = *c << 8; c++; 
						suiteLen += *c; c++;

						/* Minimum length of 2 b type, 2 b alg */
						/* Arbitrary Max of 16 suites */
						if (extLen > (2 + 32) || extLen < 4 || (extLen & 1)) {
							psTraceInfo("Malformed sig_alg len\n");
							ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
							return MATRIXSSL_ERROR;
						}
						extLen -= 2;

						if ((uint32)suiteLen > extLen || suiteLen < 2 || 
								(suiteLen & 1)) {
							psTraceInfo("Malformed sig_alg extension\n");
							ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
							return MATRIXSSL_ERROR;
						}
						/* 
							list of 2 byte pairs in a hash/sig format that
							need to be searched to find match with server
							cert sigAlgorithm
						
							enum {none(0), md5(1), sha1(2), sha224(3),
								sha256(4), sha384(5), sha512(6), (255)
							} HashAlgorithm;

							enum {anonymous(0), rsa(1), dsa(2), ecdsa(3), (255)
							} SignatureAlgorithm;
							
							Test if client will be able to accept our sigs
							based on what our idenity certificate is
						*/
						hashSigAlg = 0;
						while (suiteLen >= 2 && extLen >= 2) {
							i = *c << 8; c++; 
							i += *c; c++;
							suiteLen -= 2;
							extLen -= 2;
							
							if (i == HASH_SIG_1_RSA) {
								hashSigAlg |= HASH_SIG_1_RSA_BM;
							} else if (i == HASH_SIG_5_RSA) {
								hashSigAlg |= HASH_SIG_5_RSA_BM;
							} else if (i == HASH_SIG_256_RSA) {
								hashSigAlg |= HASH_SIG_256_RSA_BM;
#ifdef USE_SHA384
							} else if (i == HASH_SIG_384_RSA) {
								hashSigAlg |= HASH_SIG_384_RSA_BM;
#endif					
							}
#ifdef USE_ECC
							if (i == HASH_SIG_1_ECDSA) {
								hashSigAlg |= HASH_SIG_1_ECDSA_BM;
							} else if (i == HASH_SIG_256_ECDSA) {
								hashSigAlg |= HASH_SIG_256_ECDSA_BM;
#ifdef USE_SHA384
							} else if (i == HASH_SIG_384_ECDSA) {
								hashSigAlg |= HASH_SIG_384_ECDSA_BM;
#endif					
							}
#endif /* USE_ECC */
						}
						
						/* Can skip these tests if we're using a PSK or
							ANON suite */
						if (ssl->cipher->type == CS_DHE_PSK || 
								ssl->cipher->type == CS_PSK ||
								ssl->cipher->type == CS_DH_ANON) {
							sigAlgMatch = 2; /* Full match */
						} else if (ssl->keys == NULL ||
								ssl->keys->cert == NULL) {
							/* No keys aren't going to match anything */
							sigAlgMatch = 1;
						} else {
							sigAlgMatch = 2; /* Un-flag if no match */
							crt = ssl->keys->cert;
#ifdef USE_DHE_CIPHER_SUITE						
							/* Have to look out for the case where the public
								key alg doesn't match the sig algorithm.  This
								is only a concern for DHE based suites where
								we'll be sending a signature in the
								SeverKeyExchange message */
							if (ssl->cipher->type == CS_DHE_RSA ||
									ssl->cipher->type == CS_ECDHE_RSA ||
									ssl->cipher->type == CS_ECDHE_ECDSA) {	
								if (crt->pubKeyAlgorithm == OID_RSA_KEY_ALG) {
									if (!(hashSigAlg & HASH_SIG_1_RSA_BM) && 
#ifdef USE_SHA384
										  !(hashSigAlg & HASH_SIG_384_RSA_BM) &&
#endif
										  !(hashSigAlg & HASH_SIG_256_RSA_BM) &&
										  !(hashSigAlg & HASH_SIG_5_RSA_BM)) {
										sigAlgMatch	= 1;
									}
								}
#ifdef USE_ECC
								if (crt->pubKeyAlgorithm == OID_ECDSA_KEY_ALG) {
									if (!(hashSigAlg & HASH_SIG_1_ECDSA_BM) && 
#ifdef USE_SHA384
										!(hashSigAlg & HASH_SIG_384_ECDSA_BM) &&
#endif
										!(hashSigAlg & HASH_SIG_256_ECDSA_BM) &&
										!(hashSigAlg & HASH_SIG_1_ECDSA_BM)) {
									  sigAlgMatch	= 1;
									}
								}
#endif /* USE_ECC */								
							}
#endif /* USE_DHE_CIPHER_SUITE */
							/* They are going to have to process the whole chain
								so go ahead and look at	them all.  Start with
								full match and unflag if we have to */
							while (crt) {
								if (crt->sigAlgorithm == OID_SHA1_RSA_SIG) {
									if (!(hashSigAlg & HASH_SIG_1_RSA_BM)) {
										sigAlgMatch = 1;
									}
								}
								if (crt->sigAlgorithm == OID_MD5_RSA_SIG) {
									if (!(hashSigAlg & HASH_SIG_5_RSA_BM)) {
										sigAlgMatch = 1;
									}
								}
								if (crt->sigAlgorithm == OID_SHA256_RSA_SIG) {
									if (!(hashSigAlg & HASH_SIG_256_RSA_BM)) {
										sigAlgMatch = 1;
									}
								}
#ifdef USE_SHA384					
								if (crt->sigAlgorithm == OID_SHA384_RSA_SIG) {
									if (!(hashSigAlg & HASH_SIG_384_RSA_BM)) {
										sigAlgMatch = 1;
									}
								}
#endif					
#ifdef USE_ECC
								if (crt->sigAlgorithm == OID_SHA1_ECDSA_SIG) {
									if (!(hashSigAlg & HASH_SIG_1_ECDSA_BM)) {
										sigAlgMatch = 1;
									}
								}
								if (crt->sigAlgorithm == OID_SHA256_ECDSA_SIG) {
									if (!(hashSigAlg & HASH_SIG_256_ECDSA_BM)) {
										sigAlgMatch = 1;
									}
								}
#ifdef USE_SHA384					
								if (crt->sigAlgorithm == OID_SHA384_ECDSA_SIG) {
									if (!(hashSigAlg & HASH_SIG_384_ECDSA_BM)) {
										sigAlgMatch = 1;
									}
								}
#endif
#endif /* USE_ECC */				
								crt = crt->next;
							}
						}
					}
#endif /* USE_TLS_1_2 && USE_CERT_PARSE */
#endif /* VALIDATE_KEY_MATERIAL */

#ifdef USE_TRUNCATED_HMAC
					if (extType == EXT_TRUNCATED_HMAC) {
						if (extLen != 0) {
							psTraceInfo("Bad truncated HMAC extension\n");
							ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
							return MATRIXSSL_ERROR;
						}
						ssl->truncHmac = 1;
					}
#endif /* USE_TRUNCATED_HMAC */

#ifdef USE_STATELESS_SESSION_TICKETS
					/* Server side parsing */
					if (extType == SESSION_TICKET_EXT) {
						/* Have a handy place to store this info.  Tickets are
							the	only way a server will make use of 'sid'.
							Could already exist if rehandshake case here */
						if (ssl->sid == NULL) {
							ssl->sid = psMalloc(NULL, sizeof(sslSessionId_t));
							if (ssl->sid == NULL) {
								ssl->err = SSL_ALERT_INTERNAL_ERROR;
								return MATRIXSSL_ERROR;
							}
							memset(ssl->sid, 0x0, sizeof(sslSessionId_t));
						}
						if (extLen > 0) { /* received a ticket */
							ssl->sessionIdAndTicket = SESSION_ID_TICKET;

							if (matrixUnlockSessionTicket(ssl, c, extLen)
									== PS_SUCCESS) {
								/* Understood the token */
								ssl->flags |= SSL_FLAGS_RESUMED;
								ssl->sid->sessionTicketFlag =
									SESS_TICKET_FLAG_USING_TICKET;
								memcpy(ssl->sec.masterSecret,
									ssl->sid->masterSecret,	SSL_HS_MASTER_SIZE);
#ifdef USE_MATRIXSSL_STATS
								matrixsslUpdateStat(ssl, RESUMPTIONS_STAT, 1);
#endif
							} else {
								/* If client sent a sessionId in the hello,
									we can ignore that here now */
								if (ssl->sessionIdLen > 0) {
									memset(ssl->sessionId, 0,
										SSL_MAX_SESSION_ID_SIZE);
									ssl->sessionIdLen = 0;
								}
								/* Issue another one if we have any keys */
								if (ssl->keys->sessTickets) {
									ssl->sid->sessionTicketFlag =
										SESS_TICKET_FLAG_RECVD_EXT;
								} else {
									ssl->sid->sessionTicketFlag = 0;
								}
#ifdef USE_MATRIXSSL_STATS
								matrixsslUpdateStat(ssl,
									FAILED_RESUMPTIONS_STAT, 1);
#endif
							}
						} else {
							/* Request for session ticket.  Can we honor? */
							if (ssl->keys->sessTickets) {
								ssl->sid->sessionTicketFlag =
									SESS_TICKET_FLAG_RECVD_EXT;
							} else {
								ssl->sid->sessionTicketFlag = 0;
							}
						}
					}
#endif /* USE_STATELESS_SESSION_TICKETS */
					
#ifdef USE_ECC_CIPHER_SUITE
					if (extType == ELLIPTIC_CURVE_EXT) {
						/* Minimum is 2 b dataLen and 2 b cipher */
						if (extLen < 4) {
							psTraceInfo("Invalid ECC Curve len\n");
							ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
							return MATRIXSSL_ERROR;
						}
						dataLen = *c << 8; c++; 
						dataLen += *c; c++;
						extLen -= 2;
						if (dataLen > extLen || dataLen < 2 || (dataLen & 1)) {
							psTraceInfo("Malformed ECC Curve extension\n");
							ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
							return MATRIXSSL_ERROR;
						}
						while (dataLen >= 2 && extLen >= 2) {
							cipher = *c << 8; c++; /* curve ID */
							cipher += *c; c++;
							dataLen -= 2;
							extLen -= 2;
							/* Just making sure we match any */
							if (eccParams == NULL) {
								getEccParamById(cipher, &eccParams);
							}
						}
					}
					if (extType == ELLIPTIC_POINTS_EXT) {
						if (extLen < 1) {
							psTraceInfo("Invaid ECC Points len\n");
							ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
							return MATRIXSSL_ERROR;
						}
						dataLen = *c; c++; /* single byte data len */
						extLen -= 1;
						if (dataLen > extLen || dataLen < 1) {
							psTraceInfo("Malformed ECC Points extension\n");
							ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
							return MATRIXSSL_ERROR;
						}
/*
						One of them has to be a zero (uncompressed) and that
						is all we are looking for at the moment
*/
						if (memchr(c, '\0', dataLen) == NULL) {
							psTraceInfo("ECC Uncommpressed Points missing\n");
							ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
							return MATRIXSSL_ERROR;
						}
						c += dataLen;
						extLen -= dataLen;
					} 
#endif /* USE_ECC_CIPHER_SUITE */
					if (extType == EXT_MAX_FRAGMENT_LEN) {
						if (extLen < 1) {
							psTraceInfo("Invalid frag len ext len\n");
							ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
							return MATRIXSSL_ERROR;
						}
						if (*c == 0x1) {
							ssl->maxPtFrag = 0x200;
						} else if (*c == 0x2) {
							ssl->maxPtFrag = 0x400;
						} else if (*c == 0x3) {
							ssl->maxPtFrag = 0x800;
						} else if (*c == 0x4) {
							ssl->maxPtFrag = 0x1000;
						} else {
							psTraceInfo("Client sent bad frag len ext value\n");
							ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
							return MATRIXSSL_ERROR;
						}
						c++; extLen--;
					}
					if (extType == EXT_SERVER_NAME) {
						/* Must hold 2 b len 1 b zero 2 b len */
						if (extLen < 3 + 2) {
							psTraceInfo("Invalid server name ext len\n");
							ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
							return MATRIXSSL_ERROR;
						}
						/* Two length bytes.  May seem odd to ignore but
							the inner length is repeated right below after
							the expected 0x0 bytes */
						i = *c << 8; c++; 
						i += *c; c++;
						if (*c++ != 0x0) {
							psTraceInfo("Expected host_name in SNI ext\n");
							ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
							return MATRIXSSL_ERROR;

						}
						extLen -= 3;
						i = *c << 8; c++; 
						i += *c; c++;
						extLen -= 2;	/* Length check covered above */
						/* Arbitrary length cap between 1 and min(extlen,255) */
						if (extLen < i || i > 255 || i <= 0) {
							psTraceInfo("Invalid host name ext len\n");
							ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
							return MATRIXSSL_ERROR;
						}
						extLen -= i;
						if (matrixServerSetKeysSNI(ssl, (char*)c, i) < 0) {
							psTraceInfo("Server didn't load SNI keys\n");
							ssl->err = SSL_ALERT_UNRECOGNIZED_NAME;
							return MATRIXSSL_ERROR;
						}
						c += i;
					}
					c += extLen;
				}				
			}
/*
			Handle the extensions that were missing or not what we wanted
*/
#ifdef VALIDATE_KEY_MATERIAL
#if defined(USE_TLS_1_2) && defined(USE_CERT_PARSE)
			if (ssl->flags & SSL_FLAGS_TLS_1_2) {
				if (sigAlgMatch == 1) {
					/* Client sent the extension but our certs didn't match even
						one of the algorithms */
					psTraceInfo("Client couldn't match my sig_algorithms\n");
					ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
					return MATRIXSSL_ERROR;
				} else if (sigAlgMatch == 0) {
					/* Client didn't send the extension at all.  Spec says we
						have to assume SHA1 in this case.  Is that what we're
						using? */
					crt = ssl->keys->cert;
					while (crt) {
						if (crt->sigAlgorithm != OID_SHA1_ECDSA_SIG &&
								crt->sigAlgorithm != OID_SHA1_RSA_SIG) {
							psTraceInfo("Client didn't send sig_algorithms\n");
							ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
							return MATRIXSSL_ERROR;	
						}
						crt = crt->next;
					}
				}
			}
#endif
#endif /* VALIDATE_KEY_MATERIAL */

#ifdef USE_STATELESS_SESSION_TICKETS
		/* If session ID was sent that we didn't like AND no ticket was sent
			then we can forget we ever received a sessionID now */
		if (ssl->sessionIdAndTicket == SESSION_ID_STANDARD) {
			memset(ssl->sessionId, 0, SSL_MAX_SESSION_ID_SIZE);
			ssl->sessionIdLen = 0;
		}
		ssl->sessionIdAndTicket = 0;
#endif

#ifdef ENABLE_SECURE_REHANDSHAKES
			if (renegotiationExt == 0) {
#ifdef REQUIRE_SECURE_REHANDSHAKES
/*
				Check if SCSV was sent instead
*/
				if (ssl->secureRenegotiationFlag == PS_FALSE &&
						ssl->myVerifyDataLen == 0) {
					psTraceInfo("Client doesn't support renegotiation hello\n");
					ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
					return MATRIXSSL_ERROR;	
				}
#endif /* REQUIRE_SECURE_REHANDSHAKES */
				if (ssl->secureRenegotiationFlag == PS_TRUE &&
						ssl->myVerifyDataLen > 0) {
					ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
					psTraceInfo("Cln missing renegotiationInfo on re-hndshk\n");
					return MATRIXSSL_ERROR;
				}
#ifndef ENABLE_INSECURE_REHANDSHAKES
				if (ssl->secureRenegotiationFlag == PS_FALSE &&
						ssl->myVerifyDataLen > 0) {
					ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
					psTraceInfo("Cln attempting insecure handshake\n");
					return MATRIXSSL_ERROR;
				}
#endif /* !ENABLE_INSECURE_REHANDSHAKES */				
			}
#endif /* ENABLE_SECURE_REHANDSHAKES */

		} else {
/*
			Parse a SSLv2 ClientHello message.  The same information is 
			conveyed but the order and format is different.
			First get the cipher suite length, session id length and challenge
			(client random) length - all two byte values, network byte order.
*/
			if (end - c < 6) {
				ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
				psTraceInfo("Can't parse hello message\n");
				return MATRIXSSL_ERROR;
			}
			suiteLen = *c << 8; c++;
			suiteLen += *c; c++;
			if (suiteLen == 0 || suiteLen % 3 != 0) {
				ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
				psTraceInfo("Can't parse hello message\n");
				return MATRIXSSL_ERROR;
			}
			ssl->sessionIdLen = *c << 8; c++;
			ssl->sessionIdLen += *c; c++;
/*
			A resumed session would use a SSLv3 ClientHello, not SSLv2.
*/
			if (ssl->sessionIdLen != 0) {
				ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
				psTraceInfo("Bad resumption request\n");
				return MATRIXSSL_ERROR;
			}
			challengeLen = *c << 8; c++;
			challengeLen += *c; c++;
			if (challengeLen < 16 || challengeLen > 32) {
				psTraceInfo("Bad challenge length\n");
				ssl->err = SSL_ALERT_DECODE_ERROR;
				return MATRIXSSL_ERROR;
			}
/*
			Validate the three lengths that were just sent to us, don't
			want any buffer overflows while parsing the remaining data
*/
			if ((uint32)(end - c) != suiteLen + ssl->sessionIdLen +
					challengeLen) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Malformed SSLv2 clientHello\n");
				return MATRIXSSL_ERROR;
			}
/*
			Parse the cipher suite list similar to the SSLv3 method, except
			each suite is 3 bytes, instead of two bytes.  We define the suite
			as an integer value, so either method works for lookup.
			We don't support session resumption from V2 handshakes, so don't 
			need to worry about matching resumed cipher suite.
*/
			p = c + suiteLen;
			while (c < p) {
				cipher = *c << 16; c++;
				cipher += *c << 8; c++;
				cipher += *c; c++;
				if ((ssl->cipher = sslGetCipherSpec(ssl, cipher)) != NULL) {
					c = p;
					break;
				}
			}
			if (ssl->cipher == NULL || 
					ssl->cipher->ident == SSL_NULL_WITH_NULL_NULL) {
				ssl->cipher = sslGetCipherSpec(ssl, SSL_NULL_WITH_NULL_NULL);
				ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
				psTraceInfo("No matching cipher for SSL handshake\n");
				return MATRIXSSL_ERROR;
			}
/*
			We don't allow session IDs for v2 ClientHellos
*/
			if (ssl->sessionIdLen > 0) {
				ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
				psTraceInfo("SSLv2 sessions not allowed\n");
				return MATRIXSSL_ERROR;
			}
/*
			The client random (between 16 and 32 bytes) fills the least 
			significant bytes in the (always) 32 byte SSLv3 client random field.
*/
			memset(ssl->sec.clientRandom, 0x0, SSL_HS_RANDOM_SIZE);
			memcpy(ssl->sec.clientRandom + (SSL_HS_RANDOM_SIZE - challengeLen), 
				c, challengeLen);
			c += challengeLen;
		}
/*
		ClientHello should be the only one in the record.
*/
		if (c != end) {
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			psTraceInfo("Invalid final client hello length\n");
			return MATRIXSSL_ERROR;
		}
		matrixSslSetKexFlags(ssl);

/*
		If we're resuming a handshake, then the next handshake message we
		expect is the finished message.  Otherwise we do the full handshake.
*/
		if (ssl->flags & SSL_FLAGS_RESUMED) {
			ssl->hsState = SSL_HS_FINISHED;
		} else {
#ifdef USE_ECC_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_ECC_CIPHER) { 
				if (eccParams == NULL) {
/*
					Client didn't send curve extension or we couldn't match
					a curve that was sent.  No mechanism to go back through
					the cipher suite list to try to find another cipher suite
*/
					psTraceInfo("No matching ECC curve\n");   
					ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
					return MATRIXSSL_ERROR;	
				}
			}
#endif /* USE_ECC_CIPHER_SUITE */			
		
#ifdef USE_DHE_CIPHER_SUITE
/*
			If we are DH key exchange we need to generate some keys.  The
			FLAGS_DHE_KEY_EXCH will eventually drive the state matchine to
			the ServerKeyExchange path, but ECDH_ suites need the key gen now
*/
			if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {

#ifdef USE_ECC_CIPHER_SUITE
				if (ssl->flags & SSL_FLAGS_ECC_CIPHER) { 				
					if ((i = psEccMakeKeyEx(ssl->hsPool,
							&ssl->sec.eccKeyPriv, eccParams, pkiData)) < 0) {
						psEccFreeKey(&ssl->sec.eccKeyPriv);
						psTraceInfo("psEccMakeKeyEx failed\n");   
						ssl->err = SSL_ALERT_INTERNAL_ERROR;
						return i;				   
					}			
				} else {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef REQUIRE_DH_PARAMS
/*
					Servers using DH suites know DH key sizes when handshake
					pool is created so that has been accounted for here
*/
					if ((i = psDhKeyGenInts(ssl->hsPool,
							ssl->keys->dhParams->size, &ssl->keys->dhParams->p,
							&ssl->keys->dhParams->g,
							&ssl->sec.dhKeyPriv, pkiData)) < 0) {
						psTraceInfo("Error generating DH keys\n");
						ssl->err = SSL_ALERT_INTERNAL_ERROR;
						return MATRIXSSL_ERROR;
					}
#endif			
#ifdef USE_ECC_CIPHER_SUITE
				}
#endif /* USE_ECC_CIPHER_SUITE */
			}			
#endif /* USE_DHE_CIPHER_SUITE */
			ssl->hsState = SSL_HS_CLIENT_KEY_EXCHANGE;
#ifdef USE_CLIENT_AUTH
/*
			Next state in client authentication case is to receive the cert
*/
			if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
#ifdef USE_ANON_DH_CIPHER_SUITE
/*
				However, what if the server has called for client auth and the
				client is requesting an 'anon' cipher suite?  
				
				SECURITY:  Options are to default to what the
				client wants, what the server wants, or error out.  The
				current implementation does what the client wants.
*/
				if (ssl->flags & SSL_FLAGS_ANON_CIPHER) {
					psTraceIntInfo(
						"Anon cipher %d negotiated.  Disabling client auth\n",
						ssl->cipher->ident);
					ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
				} else {
#endif /* USE_ANON_DH_CIPHER_SUITE */
					ssl->hsState = SSL_HS_CERTIFICATE;
#ifdef USE_ANON_DH_CIPHER_SUITE
				}
#endif /* USE_ANON_DH_CIPHER_SUITE */
			}
#endif /* USE_CLIENT_AUTH */
		}
/*
		Now that we've parsed the ClientHello, we need to tell the caller that
		we have a handshake response to write out.
		The caller should call sslWrite upon receiving this return code.
*/
		rc = SSL_PROCESS_DATA;
		break;

	case SSL_HS_CLIENT_KEY_EXCHANGE:
/*
		RSA: This message contains the premaster secret encrypted with the 
		server's public key (from the Certificate).  The premaster
		secret is 48 bytes of random data, but the message may be longer
		than that because the 48 bytes are padded before encryption 
		according to PKCS#1v1.5.  After encryption, we should have the 
		correct length.
*/
		psTraceHs(">>> Server parsing CLIENT_KEY_EXCHANGE\n");
		if ((uint32)(end - c) < hsLen) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Invalid ClientKeyExchange length\n");
			return MATRIXSSL_ERROR;
		}

		pubKeyLen = hsLen;
#ifdef USE_TLS
/*
		TLS - Two byte length is explicit.
*/
		if (ssl->majVer >= TLS_MAJ_VER && ssl->minVer >= TLS_MIN_VER) {
			if (end - c < 2) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid ClientKeyExchange length\n");
				return MATRIXSSL_ERROR;
			}
#ifdef USE_ECC_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
				pubKeyLen = *c; c++;
			} else {
#endif /* USE_ECC_CIPHER_SUITE */
			pubKeyLen = *c << 8; c++;
			pubKeyLen += *c; c++;
#ifdef USE_ECC_CIPHER_SUITE
			}
#endif /* USE_ECC_CIPHER_SUITE */
			if ((uint32)(end - c) < pubKeyLen) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid ClientKeyExchange length\n");
				return MATRIXSSL_ERROR;
			}
		}
#endif /* USE_TLS */


#ifdef USE_DHE_CIPHER_SUITE 
		if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
			if (ssl->majVer == SSL3_MAJ_VER && ssl->minVer == SSL3_MIN_VER) {
#ifdef USE_ECC_CIPHER_SUITE
			/* Support ECC ciphers in SSLv3.  This isn't really a desirable
				combination and it's a fuzzy area in the specs but it works */
			if (!(ssl->flags & SSL_FLAGS_ECC_CIPHER)) {
#endif
/*
				DH cipher suites use the ClientDiffieHellmanPublic format
				which always includes the explicit key length regardless
				of protocol.  If TLS, we already stripped it out above.
*/
				if (end - c < 2) {
					ssl->err = SSL_ALERT_DECODE_ERROR;
					psTraceInfo("Invalid ClientKeyExchange length\n");
					return MATRIXSSL_ERROR;
				}
				pubKeyLen = *c << 8; c++;
				pubKeyLen += *c; c++;
				if ((uint32)(end - c) < pubKeyLen) {
					ssl->err = SSL_ALERT_DECODE_ERROR;
					psTraceInfo("Invalid ClientKeyExchange length\n");
					return MATRIXSSL_ERROR;
				}
#ifdef USE_ECC_CIPHER_SUITE
			} else {
				pubKeyLen = *c; c++;
			}
#endif
			}
#ifdef USE_PSK_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
/*
				That initial pubKeyLen we read off the top was actually the
				length of the PSK id that we need to find a key for
*/
				if ((uint32)(end - c) < pubKeyLen) {
					ssl->err = SSL_ALERT_DECODE_ERROR;
					psTraceInfo("Invalid ClientKeyExchange PSK length\n");
					return MATRIXSSL_ERROR;
				}
				matrixSslPskGetKey(ssl, c, pubKeyLen, &pskKey, &pskLen);
				if (pskKey == NULL) {
					psTraceInfo("Error making premaster from PSK\n");
					return MATRIXSSL_ERROR;
				}
				c += pubKeyLen;
/*
				This is the DH pub key now
*/
				pubKeyLen = *c << 8; c++;
				pubKeyLen += *c; c++;
				if ((uint32)(end - c) < pubKeyLen) {
					ssl->err = SSL_ALERT_DECODE_ERROR;
					psTraceInfo("Invalid ClientKeyExchange length\n");
					return MATRIXSSL_ERROR;
				}
			}
#endif /* USE_PSK_CIPHER_SUITE */			

#ifdef USE_ECC_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
				ssl->sec.eccKeyPub = psMalloc(ssl->hsPool, sizeof(psEccKey_t));
				if (ssl->sec.eccKeyPub == NULL) {
					return SSL_MEM_ERROR;
				}
				memset(ssl->sec.eccKeyPub, 0, sizeof(psEccKey_t));
				if (psEccX963ImportKey(ssl->hsPool, c, pubKeyLen,
						ssl->sec.eccKeyPub) < 0) {
					ssl->err = SSL_ALERT_DECODE_ERROR;
					return MATRIXSSL_ERROR;
				}
				c += pubKeyLen;
			
				ssl->sec.premasterSize = ssl->sec.eccKeyPriv->dp->size;
				ssl->sec.premaster = psMalloc(ssl->hsPool,
					ssl->sec.premasterSize);
				if (ssl->sec.premaster == NULL) {
					return SSL_MEM_ERROR;
				}	
				if ((i = psEccGenSharedSecret(ssl->hsPool, ssl->sec.eccKeyPriv,
						ssl->sec.eccKeyPub, ssl->sec.premaster,
						&ssl->sec.premasterSize, pkiData)) < 0) {
					ssl->err = SSL_ALERT_INTERNAL_ERROR;
					psFree(ssl->sec.premaster);
					ssl->sec.premaster = NULL;
					return MATRIXSSL_ERROR;				  
				}
				psEccFreeKey(&ssl->sec.eccKeyPub);
				psEccFreeKey(&ssl->sec.eccKeyPriv);
			} else {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef REQUIRE_DH_PARAMS
			if (psDhImportPubKey(ssl->hsPool, c, pubKeyLen,
					&ssl->sec.dhKeyPub) < 0) {
				return MATRIXSSL_ERROR;
			}
/*
			Now know the premaster details.  Create it.

			The additional 1 here is to catch the cases where the public key
			ends up being a byte less than the final premaster size.
*/
			ssl->sec.premasterSize = pubKeyLen + 1;

#ifdef USE_PSK_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
/*
				Premaster is appended with the PSK.  Account for that length
				here to avoid a realloc after the standard DH premaster is
				created below.
*/
					ssl->sec.premasterSize += pskLen + 4; /* uint16 len heads */
			}
#endif /* USE_PSK_CIPHER_SUITE */

			ssl->sec.premaster = psMalloc(ssl->hsPool, ssl->sec.premasterSize);
			if (ssl->sec.premaster == NULL) {
				return SSL_MEM_ERROR;
			}
			if ((i = psDhGenSecret(ssl->hsPool, &ssl->sec.dhKeyPriv,
					&ssl->sec.dhKeyPub, ssl->sec.dhP, ssl->sec.dhPLen,
					ssl->sec.premaster, 
					&ssl->sec.premasterSize, pkiData)) < 0) {
				return MATRIXSSL_ERROR;
			}
			psFree(ssl->sec.dhP); ssl->sec.dhP = NULL; ssl->sec.dhPLen = 0;
			psFree(ssl->sec.dhG); ssl->sec.dhG = NULL; ssl->sec.dhGLen = 0;
			psDhFreeKey(&ssl->sec.dhKeyPub);
			psDhFreeKey(&ssl->sec.dhKeyPriv);
#ifdef USE_PSK_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
/*
				Need to prepend a uint16 length to the premaster key. 
*/
				memmove(&ssl->sec.premaster[2], ssl->sec.premaster,
					ssl->sec.premasterSize);
				ssl->sec.premaster[0] = (ssl->sec.premasterSize & 0xFF00) >> 8;
				ssl->sec.premaster[1] = (ssl->sec.premasterSize & 0xFF);
/*
				Next, uint16 length of PSK and key itself
*/
				ssl->sec.premaster[ssl->sec.premasterSize + 2] =
					(pskLen & 0xFF00) >> 8;
				ssl->sec.premaster[ssl->sec.premasterSize + 3] =(pskLen & 0xFF);
				memcpy(&ssl->sec.premaster[ssl->sec.premasterSize + 4], pskKey,
					pskLen);
/*
				Lastly, adjust the premasterSize
*/
				ssl->sec.premasterSize += pskLen + 4;
			}
#endif /* USE_PSK_CIPHER_SUITE */
#endif /* REQUIRE_DH_PARAMS */
#ifdef USE_ECC_CIPHER_SUITE
			}
#endif /* USE_ECC_CIPHER_SUITE */
		} else {
#endif /* USE_DHE_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
			
				if (ssl->majVer == SSL3_MAJ_VER && ssl->minVer == SSL3_MIN_VER){
					/* SSLv3 for basic PSK suites will not have read off
						pubKeyLen at this point */
					pubKeyLen = *c << 8; c++;
					pubKeyLen += *c; c++;	
				}
/*
				This message is the key id that we need to find a PSK for.
*/
				matrixSslPskGetKey(ssl, c, pubKeyLen, &pskKey, &pskLen);
				if (pskKey == NULL) {
					psTraceInfo("Error making premaster from PSK\n");
					return MATRIXSSL_ERROR;
				}
				ssl->sec.premasterSize = (pskLen * 2) + 4;
				ssl->sec.premaster = psMalloc(ssl->hsPool,
					ssl->sec.premasterSize);
				if (ssl->sec.premaster == NULL) {
					return SSL_MEM_ERROR;
				}	
				memset(ssl->sec.premaster, 0, ssl->sec.premasterSize);
				ssl->sec.premaster[0] = (pskLen & 0xFF00) >> 8;
				ssl->sec.premaster[1] = (pskLen & 0xFF);
				/* memset to 0 handled middle portion */
				ssl->sec.premaster[2 + pskLen] = (pskLen & 0xFF00) >> 8;
				ssl->sec.premaster[3 + pskLen] = (pskLen & 0xFF);
				memcpy(&ssl->sec.premaster[4 + pskLen], pskKey, pskLen);
			} else {
#endif
#ifdef USE_ECC_CIPHER_SUITE
				if (ssl->cipher->type == CS_ECDH_ECDSA ||
						ssl->cipher->type == CS_ECDH_RSA) {
					if (ssl->majVer == SSL3_MAJ_VER &&
							ssl->minVer == SSL3_MIN_VER) {
						/* Support ECC ciphers in SSLv3.  This isn't really a
							desirable combination and it's a fuzzy area in the
							specs but it works */
						pubKeyLen = *c; c++;
					}
					ssl->sec.eccKeyPub = psMalloc(ssl->hsPool,
						sizeof(psEccKey_t));
					if (ssl->sec.eccKeyPub == NULL) {
						return SSL_MEM_ERROR;
					}
					memset(ssl->sec.eccKeyPub, 0, sizeof(psEccKey_t));
					if (psEccX963ImportKey(ssl->hsPool, c, pubKeyLen,
							ssl->sec.eccKeyPub) < 0) {
						ssl->err = SSL_ALERT_DECODE_ERROR;
						return MATRIXSSL_ERROR;
					}
					c += pubKeyLen;
			
					ssl->sec.premasterSize =
						ssl->keys->privKey->key->ecc.dp->size;
					ssl->sec.premaster = psMalloc(ssl->hsPool,
						ssl->sec.premasterSize);
					if (ssl->sec.premaster == NULL) {
						return SSL_MEM_ERROR;
					}	
					if ((i = psEccGenSharedSecret(ssl->hsPool,
							&ssl->keys->privKey->key->ecc, ssl->sec.eccKeyPub,
							ssl->sec.premaster,	&ssl->sec.premasterSize,
							pkiData)) < 0) {
						ssl->err = SSL_ALERT_INTERNAL_ERROR;
						psFree(ssl->sec.premaster);
						ssl->sec.premaster = NULL;
						return MATRIXSSL_ERROR;				  
					}
					psEccFreeKey(&ssl->sec.eccKeyPub);
				} else {
#endif /* USE_ECC_CIPHER_SUITE */				

#ifdef USE_RSA_CIPHER_SUITE
				/*	Standard RSA suite. Now have a handshake pool to allocate
					the premaster storage */
				ssl->sec.premasterSize = SSL_HS_RSA_PREMASTER_SIZE;
				ssl->sec.premaster = psMalloc(ssl->hsPool,
					SSL_HS_RSA_PREMASTER_SIZE);
				if (ssl->sec.premaster == NULL) {
					return SSL_MEM_ERROR;
				}


				if ((i = csRsaDecryptPriv(ckepkiPool, ssl->keys->privKey, c,
						pubKeyLen, ssl->sec.premaster, ssl->sec.premasterSize,
						pkiData)) != ssl->sec.premasterSize) {
					ssl->err = SSL_ALERT_DECRYPT_ERROR;
					psTraceIntInfo("csRsaDecryptPriv ret: %d\n", i);
					psTraceIntInfo("ssl->sec.premasterSize: %d\n", ssl->sec.premasterSize);
					return MATRIXSSL_ERROR;
				}
/*
				The first two bytes of the decrypted message should be the
				client's requested version number (which may not be the same
				as the final negotiated version). The other 46 bytes -
				pure random!
			
				SECURITY - 
				Many SSL clients (Including Microsoft IE 6.0) incorrectly set
				the first two bytes to the negotiated version rather than the
				requested version.  This is known in OpenSSL as the
				SSL_OP_TLS_ROLLBACK_BUG. We allow this to slide only if we
				don't support TLS, TLS was requested, and the negotiated
				versions match.
*/
				if (*ssl->sec.premaster != ssl->reqMajVer) {
					ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
					psTraceInfo("Incorrect version in ClientKeyExchange\n");
					return MATRIXSSL_ERROR;
				}
				if (*(ssl->sec.premaster + 1) != ssl->reqMinVer) {
#ifndef USE_TLS
					if (ssl->reqMinVer < TLS_MIN_VER ||
							*(ssl->sec.premaster + 1) != ssl->minVer) {
#endif /* USE_TLS */
						ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
						psTraceInfo("Incorrect version in ClientKeyExchange\n");
						return MATRIXSSL_ERROR;
#ifndef USE_TLS
					}
#endif /* USE_TLS */
				}
#else /* RSA is the 'default' so if that didn't get hit there is a problem */
		psTraceInfo("There is no handler for ClientKeyExchange parse. ERROR\n");
		return MATRIXSSL_ERROR;
#endif /* USE_RSA_CIPHER_SUITE */			
#ifdef USE_ECC_CIPHER_SUITE
				}
#endif /* USE_ECC_CIPHER_SUITE */					
#ifdef USE_PSK_CIPHER_SUITE
			}
#endif /* USE_PSK_CIPHER_SUITE */
#ifdef USE_DHE_CIPHER_SUITE
		}
#endif /* USE_DHE_CIPHER_SUITE */

/*
		Now that we've got the premaster secret, derive the various
		symmetric keys using it and the client and server random values.
		Update the cached session (if found) with the masterSecret and
		negotiated cipher.	
*/
		if (sslCreateKeys(ssl) < 0) {
			ssl->err = SSL_ALERT_INTERNAL_ERROR;
			return MATRIXSSL_ERROR;
		}
		matrixUpdateSession(ssl);

		c += pubKeyLen;
		ssl->hsState = SSL_HS_FINISHED;


#ifdef USE_CLIENT_AUTH
/*
		In the non client auth case, we are done with the handshake pool
*/
		if (!(ssl->flags & SSL_FLAGS_CLIENT_AUTH)) {
			ssl->hsPool = NULL;
		}
#else
		ssl->hsPool = NULL;
#endif


#ifdef USE_CLIENT_AUTH
/*
		Tweak the state here for client authentication case
*/
		if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {	
			ssl->hsState = SSL_HS_CERTIFICATE_VERIFY;		
		}
#endif /* USE_CLIENT_AUTH */
		break;
#endif /* USE_SERVER_SIDE_SSL */

	case SSL_HS_FINISHED:
/*
		Before the finished handshake message, we should have seen the
		CHANGE_CIPHER_SPEC message come through in the record layer, which
		would have activated the read cipher, and set the READ_SECURE flag.
		This is the first handshake message that was sent securely.
*/
		psTraceStrHs(">>> %s parsing FINISHED message\n",
			(ssl->flags & SSL_FLAGS_SERVER) ? "Server" : "Client");
		if (!(ssl->flags & SSL_FLAGS_READ_SECURE)) {
			ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
			psTraceInfo("Finished before ChangeCipherSpec\n");
			return MATRIXSSL_ERROR;
		}
/*
		The contents of the finished message is a 16 byte MD5 hash followed
		by a 20 byte sha1 hash of all the handshake messages so far, to verify
		that nothing has been tampered with while we were still insecure.
		Compare the message to the value we calculated at the beginning of
		this function.
*/
#ifdef USE_TLS
		if (ssl->flags & SSL_FLAGS_TLS) {
			if (hsLen != TLS_HS_FINISHED_SIZE) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid Finished length\n");
				return MATRIXSSL_ERROR;
			}
		} else {
#endif /* USE_TLS */
			if (hsLen != MD5_HASH_SIZE + SHA1_HASH_SIZE) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid Finished length\n");
				return MATRIXSSL_ERROR;
			}
#ifdef USE_TLS
		}
#endif /* USE_TLS */
		if ((uint32)(end - c) < hsLen) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Invalid Finished length\n");
			return MATRIXSSL_ERROR;
		}
		if (memcmp(c, hsMsgHash, hsLen) != 0) {
			ssl->err = SSL_ALERT_DECRYPT_ERROR;
			psTraceInfo("Invalid handshake msg hash\n");
			return MATRIXSSL_ERROR;
		}
#ifdef ENABLE_SECURE_REHANDSHAKES		
/*
		Got the peer verify_data for secure renegotiations
*/
		memcpy(ssl->peerVerifyData, c, hsLen);
		ssl->peerVerifyDataLen = hsLen;
#endif /* ENABLE_SECURE_REHANDSHAKES */		
		c += hsLen;
		ssl->hsState = SSL_HS_DONE;
/*
		Now that we've parsed the Finished message, if we're a resumed 
		connection, we're done with handshaking, otherwise, we return
		SSL_PROCESS_DATA to get our own cipher spec and finished messages
		sent out by the caller.
*/
		if (ssl->flags & SSL_FLAGS_SERVER) {
			if (!(ssl->flags & SSL_FLAGS_RESUMED)) {
				rc = SSL_PROCESS_DATA;
			} else {
#ifdef USE_SSL_INFORMATIONAL_TRACE
				/* Server side resumed completion */
				matrixSslPrintHSDetails(ssl);
#endif
#ifdef USE_UNIFIED_PKCS11
				/* Too ugly to track DTLS client/server/normal/resumed cases
					for deleting old crypto session objects for the minimum
					lifecycle so we're just looking for any leftover cases
					here when we are certain handshake is complete */
				if (ssl->sec.oldCrypt != CK_INVALID_HANDLE &&
						ssl->sec.oldCrypt != ssl->sec.pkcs11Ses) {
					pkcs11CloseSession(ssl->sec.oldCrypt);
					ssl->sec.oldCrypt = CK_INVALID_HANDLE;
				}
#endif
			}
		} else {
#ifdef USE_STATELESS_SESSION_TICKETS
			/* Now that FINISHED is verified, we can mark the ticket as 
				valid to conform to section 3.3 of the 5077 RFC */
			if (ssl->sid && ssl->sid->sessionTicketLen > 0) {
				ssl->sid->sessionTicketFlag = SESS_TICKET_FLAG_USING_TICKET;
			}
#endif
			if (ssl->flags & SSL_FLAGS_RESUMED) {
				rc = SSL_PROCESS_DATA;
			} else {
#ifdef USE_SSL_INFORMATIONAL_TRACE
				/* Client side standard completion */
				matrixSslPrintHSDetails(ssl);
#endif			
#ifdef USE_UNIFIED_PKCS11
				/* Too ugly to track DTLS client/server/normal/resumed cases
					for deleting old crypto session objects for the minimum
					lifecycle so we're just looking for any leftover cases
					here when we are certain handshake is complete */
				if (ssl->sec.oldCrypt != CK_INVALID_HANDLE &&
						ssl->sec.oldCrypt != ssl->sec.pkcs11Ses) {
					pkcs11CloseSession(ssl->sec.oldCrypt);
					ssl->sec.oldCrypt = CK_INVALID_HANDLE;
				}
#endif
			}
		}
#ifndef USE_ONLY_PSK_CIPHER_SUITE		
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
/*
		There is also an attempt to free the cert during
		the sending of the finished message to deal with client
		and server and differing handshake types.  Both cases are 
		attempted keep the lifespan of this allocation as short as possible.
*/
		if (ssl->sec.cert) {
			psX509FreeCert(ssl->sec.cert);
			ssl->sec.cert = NULL;
		}
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

		break;

#ifdef USE_CLIENT_SIDE_SSL
	case SSL_HS_HELLO_REQUEST:
/*	
		No body message and the only one in record flight
*/
		psTraceHs(">>> Client parsing HELLO_REQUEST message\n");
		if (end - c != 0) {
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			psTraceInfo("Invalid hello request message\n");
			return MATRIXSSL_ERROR;
		}
#ifdef SSL_REHANDSHAKES_ENABLED		
		if (ssl->rehandshakeCount <= 0) {
			ssl->err = SSL_ALERT_NO_RENEGOTIATION;
			psTraceInfo("Server re-handshaking denied\n");
			/* Reset the state to done */
			ssl->hsState = SSL_HS_DONE;
			return MATRIXSSL_ERROR;
		}
		ssl->rehandshakeCount--;
#endif
/*
		Intentionally not changing state here to SERVER_HELLO.  The
		encodeResponse case	this will fall into needs to distinguish
		between calling the normal sslEncodeResponse or encodeClientHello.
		The HELLO_REQUEST state is used to make that determination and the
		writing of CLIENT_HELLO will properly move the state along itself.
*/

		rc = SSL_PROCESS_DATA;
		break;

	case SSL_HS_SERVER_HELLO: 
	
		psTraceHs(">>> Client parsing SERVER_HELLO message\n");
#ifdef USE_MATRIXSSL_STATS
		matrixsslUpdateStat(ssl, SH_RECV_STAT, 1);
#endif			
/*
		Need to track hsLen because there is no explict	way to tell if
		hello extensions are appended so it isn't clear if the record data
		after the compression parameters are a new message or extension data
*/
		extData = c;

		
/*
		First two bytes are the negotiated SSL version
		We support only 3.0 (other options are 2.0 or 3.1)
*/
		if (end - c < 2) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Invalid ssl header version length\n");
			return MATRIXSSL_ERROR;
		}
		ssl->reqMajVer = *c; c++;
		ssl->reqMinVer = *c; c++;
		if (ssl->reqMajVer != ssl->majVer) {
			ssl->err = SSL_ALERT_PROTOCOL_VERSION;
			psTraceIntInfo("Unsupported ssl version: %d\n", ssl->reqMajVer);
			return MATRIXSSL_ERROR;
		}

#ifdef USE_TLS
/*
		See if the protocol is being downgraded
*/
		if (ssl->reqMinVer != ssl->minVer) {
			if (ssl->reqMinVer == SSL3_MIN_VER && ssl->minVer >= TLS_MIN_VER) {
#ifdef DISABLE_SSLV3
				ssl->err = SSL_ALERT_PROTOCOL_VERSION;
				psTraceInfo("Server wants to talk SSLv3 but it's disabled\n");
				return MATRIXSSL_ERROR;
#else					
/*
				Server minVer now becomes OUR initial requested version.
				This is used during the creation of the premaster where
				this initial requested version is part of the calculation.
				The RFC actually says to use the original requested version
				but no implemenations seem to follow that and just use the
				agreed upon one.
*/
				ssl->reqMinVer = ssl->minVer;
				ssl->minVer = SSL3_MIN_VER;
				ssl->flags &= ~SSL_FLAGS_TLS;
#ifdef USE_TLS_1_1
				ssl->flags &= ~SSL_FLAGS_TLS_1_1;
#endif /* USE_TLS_1_1 */
#ifdef USE_TLS_1_2
				ssl->flags &= ~SSL_FLAGS_TLS_1_2;
#endif /* USE_TLS_1_2 */
#endif /* DISABLE_SSLV3 */	
			} else {
#ifdef USE_TLS_1_1
#ifdef USE_TLS_1_2
				/* Step down one at a time */
				if (ssl->reqMinVer < TLS_1_2_MIN_VER &&
						(ssl->flags & SSL_FLAGS_TLS_1_2)) {
					ssl->flags &= ~SSL_FLAGS_TLS_1_2;
					if (ssl->reqMinVer == TLS_1_1_MIN_VER) {
#ifdef DISABLE_TLS_1_1
						ssl->err = SSL_ALERT_PROTOCOL_VERSION;
						psTraceInfo("Server wants to talk TLS1.1 but it's disabled\n");
						return MATRIXSSL_ERROR;
#endif					
						ssl->reqMinVer = ssl->minVer;
						ssl->minVer = TLS_1_1_MIN_VER;
						goto PROTOCOL_DETERMINED;
					}
				}
#endif /* USE_TLS_1_2 */
				if (ssl->reqMinVer == TLS_MIN_VER &&
                        ssl->minVer <= TLS_1_2_MIN_VER) {
#ifdef DISABLE_TLS_1_0
					ssl->err = SSL_ALERT_PROTOCOL_VERSION;
					psTraceInfo("Server wants to talk TLS1.0 but it's disabled\n");
					return MATRIXSSL_ERROR;
#endif											
					ssl->reqMinVer = ssl->minVer;
					ssl->minVer = TLS_MIN_VER;
					ssl->flags &= ~SSL_FLAGS_TLS_1_1;
				} else {
#endif/* USE_TLS_1_1 */
					/* Wasn't able to settle on a common protocol */
					ssl->err = SSL_ALERT_PROTOCOL_VERSION;
					psTraceIntInfo("Unsupported ssl version: %d\n",
						ssl->reqMajVer);
					return MATRIXSSL_ERROR;
#ifdef USE_TLS_1_1
				}
#endif /* USE_TLS_1_1 */		
			}
		}
#endif /* USE_TLS */

#if defined (USE_TLS_1_2) || defined (USE_DTLS)
PROTOCOL_DETERMINED:
#endif /* USE_TLS_1_2 || USE_DTLS */
/*
		Next is a 32 bytes of random data for key generation
		and a single byte with the session ID length
*/
		if (end - c < SSL_HS_RANDOM_SIZE + 1) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Invalid length of random data\n");
			return MATRIXSSL_ERROR;
		}
		memcpy(ssl->sec.serverRandom, c, SSL_HS_RANDOM_SIZE);
		c += SSL_HS_RANDOM_SIZE;
		sessionIdLen = *c; c++;
		if (sessionIdLen > SSL_MAX_SESSION_ID_SIZE || 
				(uint32)(end - c) < sessionIdLen) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			return MATRIXSSL_ERROR;
		}
/*
		If a session length was specified, the server has sent us a
		session Id.  We may have requested a specific session, and the
		server may or may not agree to use that session.
*/
			//TODO INTERCEPTOR
		if (sessionIdLen > 0) {
			if (ssl->sessionIdLen > 0) {
				if (memcmp(ssl->sessionId, c, sessionIdLen) == 0) {
					ssl->flags |= SSL_FLAGS_RESUMED;
				} else {
					ssl->cipher = sslGetCipherSpec(ssl,SSL_NULL_WITH_NULL_NULL);
#ifndef USE_PKCS11_TLS_ALGS
					memset(ssl->sec.masterSecret, 0x0, SSL_HS_MASTER_SIZE);
#endif
					ssl->sessionIdLen = (unsigned char)sessionIdLen;
					memcpy(ssl->sessionId, c, sessionIdLen);
					ssl->flags &= ~SSL_FLAGS_RESUMED;
#ifdef USE_MATRIXSSL_STATS
					matrixsslUpdateStat(ssl, FAILED_RESUMPTIONS_STAT, 1);
#endif	
				}
			} else {
				ssl->sessionIdLen = (unsigned char)sessionIdLen;
				memcpy(ssl->sessionId, c, sessionIdLen);
			}
			c += sessionIdLen;
		} else {
			if (ssl->sessionIdLen > 0) {
				ssl->cipher = sslGetCipherSpec(ssl, SSL_NULL_WITH_NULL_NULL);
#ifndef USE_PKCS11_TLS_ALGS
				memset(ssl->sec.masterSecret, 0x0, SSL_HS_MASTER_SIZE);
#endif
				ssl->sessionIdLen = 0;
				memset(ssl->sessionId, 0x0, SSL_MAX_SESSION_ID_SIZE);
				ssl->flags &= ~SSL_FLAGS_RESUMED;
#ifdef USE_MATRIXSSL_STATS
				matrixsslUpdateStat(ssl, FAILED_RESUMPTIONS_STAT, 1);
#endif				
			}
		}
/*
		Next is the two byte cipher suite
*/
		if (end - c < 2) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Invalid cipher suite length\n");
			return MATRIXSSL_ERROR;
		}
		cipher = *c << 8; c++;
		cipher += *c; c++;

/*
		A resumed session can only match the cipher originally 
		negotiated. Otherwise, match the first cipher that we support
*/
		if (ssl->flags & SSL_FLAGS_RESUMED) {
			psAssert(ssl->cipher != NULL);
			if (ssl->cipher->ident != cipher) {
				ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
				psTraceInfo("Can't support resumed cipher\n");
				return MATRIXSSL_ERROR;
			}
		} else {
			if ((ssl->cipher = sslGetCipherSpec(ssl, cipher)) == NULL) {
				ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
				psTraceIntInfo("Can't support requested cipher: %d\n", cipher);
				return MATRIXSSL_ERROR;
			}
		}
		matrixSslSetKexFlags(ssl);

/*
		Decode the compression parameters.
*/
		if (end - c < 1) {
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			psTraceInfo("Expected compression value\n");
			return MATRIXSSL_ERROR;
		}
		if (*c != 0 && *c == 1) {
#ifdef USE_ZLIB_COMPRESSION
			ssl->inflate.zalloc = NULL;
			ssl->inflate.zfree = NULL;
			ssl->inflate.opaque = NULL;
			ssl->inflate.avail_in = 0;
			ssl->inflate.next_in = NULL;
			if (inflateInit(&ssl->inflate) != Z_OK) {
				psTraceInfo("inflateInit fail.  No compression\n");
			} else {
				ssl->deflate.zalloc = Z_NULL;
				ssl->deflate.zfree = Z_NULL;
				ssl->deflate.opaque = Z_NULL;
				if (deflateInit(&ssl->deflate, Z_DEFAULT_COMPRESSION) != Z_OK) {
					psTraceInfo("deflateInit fail.  No compression\n");
					inflateEnd(&ssl->inflate);
				} else {
					ssl->compression = 1; /* Both contexts initialized */
				}
			}
#else
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("zlib compression not enabled.\n");
			return MATRIXSSL_ERROR;
#endif
		}
/*
		At this point, if we're resumed, we have all the required info
		to derive keys.  The next handshake message we expect is
		the Finished message.
*/
		c++;
	
/*
		If our sent ClientHello had an extension there could be extension data
		to parse here:  http://www.faqs.org/rfcs/rfc3546.html
		
		The explict test on hsLen is necessary for TLS 1.0 and 1.1 because
		there is no good way to tell if the remaining record data is the
		next handshake message or if it is extension data
*/
		renegotiationExt = 0;
		if (c != end && ((int32)hsLen > (c - extData))) {
			if (end - c < 2) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid extension header len\n");
				return MATRIXSSL_ERROR;
			}
			extLen = *c << 8; c++; /* Total length of list */
			extLen += *c; c++;
			if ((uint32)(end - c) < extLen) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid extension header len\n");
				return MATRIXSSL_ERROR;
			}	
			while ((int32)hsLen > (c - extData)) {
				extType = *c << 8; c++; /* Individual hello ext */
				extType += *c; c++;
				if (end - c < 2) {
					ssl->err = SSL_ALERT_DECODE_ERROR;
					psTraceInfo("Invalid extension header len\n");
					return MATRIXSSL_ERROR;
				}
				extLen = *c << 8; c++; /* length of one extension */
				extLen += *c; c++;
				if ((uint32)(end - c) < extLen) {
					ssl->err = SSL_ALERT_DECODE_ERROR;
					psTraceInfo("Invalid extension header len\n");
					return MATRIXSSL_ERROR;
				}
/*
				Deal with the server hello extensions we support
*/
				if (extType == EXT_RENEGOTIATION_INFO) {
#ifdef ENABLE_SECURE_REHANDSHAKES				
					renegotiationExt = 1;	
					if (ssl->secureRenegotiationFlag == PS_FALSE &&
							ssl->myVerifyDataLen == 0) {
						if (extLen == 1 && *c == '\0') {
							ssl->secureRenegotiationFlag = PS_TRUE;
						} else {
							ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
							psTraceInfo("Server sent bad renegotiationInfo\n");
							return MATRIXSSL_ERROR;
						}
					} else if (ssl->secureRenegotiationFlag == PS_TRUE &&
							extLen == ((ssl->myVerifyDataLen * 2) + 1)) {
						c++; extLen--;
						if (memcmp(c, ssl->myVerifyData,
								ssl->myVerifyDataLen) != 0) {
							ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
							psTraceInfo("Srv had bad my renegotiationInfo\n");
							return MATRIXSSL_ERROR;
						}
						if (memcmp(c + ssl->myVerifyDataLen,ssl->peerVerifyData,
								ssl->peerVerifyDataLen) != 0) {
							ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
							psTraceInfo("Srv had bad peer renegotiationInfo\n");
							return MATRIXSSL_ERROR;
						}
					} else {
						ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
						psTraceInfo("Server sent bad renegotiationInfo\n");
						return MATRIXSSL_ERROR;
					}
#endif /* ENABLE_SECURE_REHANDSHAKES */	
#ifdef USE_ECC_CIPHER_SUITE	
				} else if (extType == ELLIPTIC_POINTS_EXT) {
					if (*c++ != (extLen - 1)) {
						ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
						psTraceInfo("Server sent bad ECPointFormatList\n");
						return MATRIXSSL_ERROR;
					}
					extLen--; /* TODO: check that one of these bytes is 0
									(uncompressed point support) */
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef USE_STATELESS_SESSION_TICKETS
				} else if (extType == SESSION_TICKET_EXT && ssl->sid) {
					if (ssl->sid->sessionTicketFlag ==
								SESS_TICKET_FLAG_SENT_EMPTY) {
						ssl->sid->sessionTicketFlag =
							SESS_TICKET_FLAG_RECVD_EXT; /* expecting ticket */
					} else if (ssl->sid->sessionTicketFlag ==
								SESS_TICKET_FLAG_SENT_TICKET) {
						ssl->sid->sessionTicketFlag =
							SESS_TICKET_FLAG_RECVD_EXT; /* expecting ticket */
					} else {
						ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
						psTraceInfo("Server sent unexpected SESSION_TICKET\n");
						return MATRIXSSL_ERROR;
					}
#endif /* USE_STATELESS_SESSION_TICKETS */		
				} else if (extType == EXT_MAX_FRAGMENT_LEN) {
					if (ssl->maxPtFrag != 0xFF) {
						ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
						psTraceInfo("Server sent unexpected MAX_FRAG ext\n");
						return MATRIXSSL_ERROR;
					}
					if (*c == 0x01 &&
							(REQUESTED_MAX_PLAINTEXT_RECORD_LEN == 0x200)) {
						ssl->maxPtFrag = 0x200;
					} else if (*c == 0x02 && 
							(REQUESTED_MAX_PLAINTEXT_RECORD_LEN == 0x400)) {
						ssl->maxPtFrag = 0x400;
					} else if (*c == 0x03 && 
							(REQUESTED_MAX_PLAINTEXT_RECORD_LEN == 0x800)) {
						ssl->maxPtFrag = 0x800;
					} else if (*c == 0x04 && 
							(REQUESTED_MAX_PLAINTEXT_RECORD_LEN == 0x1000)) {
						ssl->maxPtFrag = 0x1000;
					} else {
						ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
						psTraceInfo("Server sent mismatched MAX_FRAG ext\n");
						return MATRIXSSL_ERROR;
					}
					c++; extLen--;
#ifdef USE_TRUNCATED_HMAC
				} else if (extType == EXT_TRUNCATED_HMAC) {
					if (extLen != 0) {
						ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
						psTraceInfo("Server sent bad truncated hmac ext\n");
						return MATRIXSSL_ERROR;
					}
					ssl->truncHmac = 1;
#endif
				} else {
					if (ssl->extCb) {
						if ((*ssl->extCb)(ssl, (unsigned short)extType,
								(unsigned short)extLen, c) < 0) {
							ssl->err = SSL_ALERT_UNSUPPORTED_EXTENSION;
							psTraceInfo("User didn't like extension\n");
							return MATRIXSSL_ERROR;
						}
					}
				}	
				c += extLen;
			}
		}
		if (ssl->maxPtFrag == 0xFF) {
			/* Server didn't respond to our MAX_FRAG request. Reset default */
			psTraceInfo("Server ignored max fragment length ext request\n");
			ssl->maxPtFrag = SSL_MAX_PLAINTEXT_LEN;
		}
		
#ifdef USE_STATELESS_SESSION_TICKETS
		if (ssl->sid &&
				ssl->sid->sessionTicketFlag == SESS_TICKET_FLAG_SENT_TICKET) {
			/* Server did not send an extension reply to our populated ticket.
			
				From the updated RFC 5077:
			
				"It is also permissible to have an exchange using the
				abbreviated handshake defined in Figure 2 of RFC 4346, where
				the	client uses the SessionTicket extension to resume the
				session, but the server does not wish to issue a new ticket,
				and therefore does not send a SessionTicket extension."
				
				Lame.  We don't get an indication that the server accepted or
				rejected our ticket until we see the next handshake message.
				If they accepted it we'll see a ChangeCipherSpec message and
				if they rejected it we'll see a Certificate message.  Let's
				flag this case of a non-response and handle it in the CCS parse
			*/
			ssl->sid->sessionTicketFlag = SESS_TICKET_FLAG_IN_LIMBO;
		}
#endif /* USE_STATELESS_SESSION_TICKETS	*/
		
		
#ifdef ENABLE_SECURE_REHANDSHAKES
		if (renegotiationExt == 0) {
#ifdef REQUIRE_SECURE_REHANDSHAKES		
			ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
			psTraceInfo("Srv doesn't support renegotiationInfo\n");
			return MATRIXSSL_ERROR;
#else
			if (ssl->secureRenegotiationFlag == PS_TRUE) {
				ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
				psTraceInfo("Srv didn't send renegotiationInfo on re-hndshk\n");
				return MATRIXSSL_ERROR;
			}
#ifndef ENABLE_INSECURE_REHANDSHAKES
/*
			This case can only be hit if ENABLE_SECURE is on because otherwise
			we wouldn't even have got this far because both would be off.
*/		
			if (ssl->secureRenegotiationFlag == PS_FALSE &&
					ssl->myVerifyDataLen > 0) {
				ssl->err = SSL_ALERT_HANDSHAKE_FAILURE;
				psTraceInfo("Srv attempting insecure renegotiation\n");
				return MATRIXSSL_ERROR;
			}
#endif /* !ENABLE_SECURE_REHANDSHAKES */				
#endif /* REQUIRE_SECURE_REHANDSHAKES */	
		}
#endif /* ENABLE_SECURE_REHANDSHAKES */		
		
						
		if (ssl->flags & SSL_FLAGS_RESUMED) {
			if (sslCreateKeys(ssl) < 0) {
				ssl->err = SSL_ALERT_INTERNAL_ERROR;
				return MATRIXSSL_ERROR;
			}
			ssl->hsState = SSL_HS_FINISHED;
		} else {
			ssl->hsState = SSL_HS_CERTIFICATE;
#ifdef USE_ANON_DH_CIPHER_SUITE
/*
			Anonymous DH uses SERVER_KEY_EXCHANGE message to send key params
*/
			if (ssl->flags & SSL_FLAGS_ANON_CIPHER) {
				ssl->hsState = SSL_HS_SERVER_KEY_EXCHANGE;
			}
#endif /* USE_ANON_DH_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
/*
			PSK ciphers never send a CERTIFICATE message.
*/
			if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
				ssl->hsState = SSL_HS_SERVER_KEY_EXCHANGE;
			}
#endif /* USE_PSK_CIPHER_SUITE */
		}
		break;
#endif /* USE_CLIENT_SIDE_SSL */

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	case SSL_HS_CERTIFICATE: 
		psTraceStrHs(">>> %s parsing CERTIFICATE message\n",
			(ssl->flags & SSL_FLAGS_SERVER) ? "Server" : "Client");
#ifdef USE_CERT_CHAIN_PARSING
		if (ssl->rec.partial) {
/*
			The test for a first pass is against the record header length
*/
			if (ssl->rec.hsBytesParsed == ssl->recordHeadLen) {
/*
				Account for the one-time header portion parsed above
				and the 3 byte cert chain length about to be parsed below.
				The minimum length tests have already been performed.
*/
				ssl->rec.hsBytesParsed += ssl->hshakeHeadLen + 3;
			} else {
				goto SKIP_CERT_CHAIN_INIT;
			}
		}
#endif
		if (end - c < 3) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Invalid Certificate message\n");
			return MATRIXSSL_ERROR;
		}
		certChainLen = *c << 16; c++;
		certChainLen |= *c << 8; c++;
		certChainLen |= *c; c++;
		if (certChainLen == 0) {
#ifdef SERVER_WILL_ACCEPT_EMPTY_CLIENT_CERT_MSG
			if (ssl->flags & SSL_FLAGS_SERVER) {
				ssl->err = SSL_ALERT_BAD_CERTIFICATE;
				ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
				goto STRAIGHT_TO_USER_CALLBACK;
			}
#endif
			if (ssl->majVer == SSL3_MAJ_VER && ssl->minVer == SSL3_MIN_VER) {
				ssl->err = SSL_ALERT_NO_CERTIFICATE;
			} else {
				ssl->err = SSL_ALERT_BAD_CERTIFICATE;
			}
			psTraceInfo("No certificate sent to verify\n");
			return MATRIXSSL_ERROR;
		}
		if (end - c < 3) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Invalid Certificate message\n");
			return MATRIXSSL_ERROR;
		}

#ifdef USE_CERT_CHAIN_PARSING
	SKIP_CERT_CHAIN_INIT:
		if (ssl->rec.partial) {
/*			It is possible to activate the CERT_STREAM_PARSE feature and not 
			receive a cert chain in multiple buffers.  If we are not flagged
			for 'partial' parsing, we can drop into the standard parse case
*/
			while (end - c > 0) { 
				certLen = *c << 16; c++;
				certLen |= *c << 8; c++;
				certLen |= *c; c++;
				if ((parseLen = parseSingleCert(ssl, c, end, certLen)) < 0 ) {
					return parseLen;
				}
				ssl->rec.hsBytesParsed += parseLen + 3; /* 3 for certLen */
				c += parseLen;
			}
			if (ssl->rec.hsBytesParsed < ssl->rec.trueLen) {
				return MATRIXSSL_SUCCESS;
			}

			psAssert(ssl->rec.hsBytesParsed == ssl->rec.trueLen);
/*
			Got it all.  Disable the stream mechanism.
*/
			ssl->rec.partial = 0x0;
			ssl->rec.hsBytesParsed = 0;
			ssl->rec.hsBytesHashed = 0;
		} else {
			psAssert(certChainLen > 0);
#endif /* USE_CERT_CHAIN_PARSING */
		i = 0;
		currentCert = NULL;

		/* Chain must be at least 3 b certLen */
		while (certChainLen >= 3) {
			certLen = *c << 16; c++;
			certLen |= *c << 8; c++;
			certLen |= *c; c++;
			certChainLen -= 3;

			if ((uint32)(end - c) < certLen || certLen > certChainLen) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid certificate length\n");
				return MATRIXSSL_ERROR;
			}
/*
			Extract the binary cert message into the cert structure
*/			
			if ((parseLen = psX509ParseCert(ssl->hsPool, c, certLen, &cert, 0))
					< 0) {
				psX509FreeCert(cert);
				if (parseLen == PS_MEM_FAIL) {
					ssl->err = SSL_ALERT_INTERNAL_ERROR;
				} else {
					ssl->err = SSL_ALERT_BAD_CERTIFICATE;
				}
				return MATRIXSSL_ERROR;
			}
			c += parseLen;

			if (i++ == 0) {
				ssl->sec.cert = cert;
				currentCert = ssl->sec.cert;
			} else {
				currentCert->next = cert;
				currentCert = currentCert->next;
			}
			certChainLen -= certLen;
		}
#ifdef USE_CERT_CHAIN_PARSING
		}
#endif /* USE_CERT_CHAIN_PARSING */

#ifdef USE_CLIENT_SIDE_SSL
/*
		Now want to test to see if supplied parent-most cert is the appropriate
		authenitcation algorithm for the chosen cipher suite.  Have seen test
		cases with OpenSSL where an RSA cert will be sent for an ECDHE_ECDSA
		suite, for example.  Just testing on the client side because client
		auth is a bit more flexible on the algorithm choices.
		
		'cert' is pointing to parent-most in chain
*/
		if (!(ssl->flags & SSL_FLAGS_SERVER)) {
			if (csCheckCertAgainstCipherSuite(cert->sigAlgorithm,
					ssl->cipher->type) == 0) {
				psTraceIntInfo("Server sent bad sig alg for cipher suite %d\n",
					cert->sigAlgorithm);
				ssl->err = SSL_ALERT_UNSUPPORTED_CERTIFICATE;
				return MATRIXSSL_ERROR;
			}
		}
#endif		
		
/*
		Time to authenticate the supplied cert against our CAs
*/
		rc = matrixValidateCerts(ssl->hsPool, ssl->sec.cert,
			ssl->keys == NULL ? NULL : ssl->keys->CAcerts, ssl->expectedName,
			&foundIssuer);

		if (rc == PS_MEM_FAIL) {
			ssl->err = SSL_ALERT_INTERNAL_ERROR;
			return MATRIXSSL_ERROR;
		}
/*
		Now walk the subject certs and convert any parse or authentication error 
		into an SSL alert.  The alerts SHOULD be read by the user callback
		to determine whether they are fatal or not.  If no user callback,
		the first alert will be considered fatal.
*/
		cert = ssl->sec.cert;
		while (cert) {	
			if (ssl->err != SSL_ALERT_NONE) {
				break; /* The first alert is the logical one to send */
			}
			switch (cert->authStatus) {

			case PS_CERT_AUTH_FAIL_SIG:
				ssl->err = SSL_ALERT_BAD_CERTIFICATE;
				break;
			case PS_CERT_AUTH_FAIL_REVOKED:
				ssl->err = SSL_ALERT_CERTIFICATE_REVOKED;
				break;
			case PS_CERT_AUTH_FAIL_AUTHKEY:
			case PS_CERT_AUTH_FAIL_PATH_LEN:
				ssl->err = SSL_ALERT_BAD_CERTIFICATE;
				break;
			case PS_CERT_AUTH_FAIL_EXTENSION:
				/* The math and basic constraints matched.  This case is
					for X.509 extension mayhem */
				if (cert->authFailFlags & PS_CERT_AUTH_FAIL_DATE_FLAG) {
					ssl->err = SSL_ALERT_CERTIFICATE_EXPIRED;
				} else if(cert->authFailFlags & PS_CERT_AUTH_FAIL_SUBJECT_FLAG){
					/* expectedName was giving to NewSession but couldn't
						match what the peer gave us */
					ssl->err = SSL_ALERT_CERTIFICATE_UNKNOWN;
				} else if (cert->next != NULL) {
					/* This is an extension problem in the chain.
						Even if it's minor, we are shutting it down */
					ssl->err = SSL_ALERT_BAD_CERTIFICATE;
				} else {
					/* This is the case where we did successfully find the
						correct CA to validate the cert and the math passed
						but the	extensions had a problem.  Give app a
						different message in this case */
					ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
				}
				break;
			case PS_CERT_AUTH_FAIL_BC:
			case PS_CERT_AUTH_FAIL_DN:
				/* These two are pre-math tests.  If this was a problem in the
					middle of the chain it means the chain couldn't even
					validate itself.  If it is at the end it means a matching
					CA could not be found */
				if (cert->next != NULL) {
					ssl->err = SSL_ALERT_BAD_CERTIFICATE;
				} else {
					ssl->err = SSL_ALERT_UNKNOWN_CA;
				}
				break;
							
			default:
				break;
			}
			cert = cert->next;
		}
/*
		The last thing we want to check before passing the certificates to
		the user callback is the case in which we don't have any
		CA files loaded but we were passed a valid chain that was
		terminated with a self-signed cert.  The fact that a CA on this
		peer has not validated the chain should result in an UNKNOWN_CA alert
		
		NOTE:  This case should only ever get hit if VALIDATE_KEY_MATERIAL
		has been disabled in matrixssllib.h
*/
		if (ssl->err == SSL_ALERT_NONE &&
				(ssl->keys == NULL || ssl->keys->CAcerts == NULL)) {
			ssl->err = SSL_ALERT_UNKNOWN_CA;
			psTraceInfo("WARNING: Valid self-signed cert or cert chain but no local authentication\n");
			rc = -1;  /* Force the check on existence of user callback */
		}
		
		if (rc < 0) {
			psTraceInfo("WARNING: cert did not pass internal validation test\n");
/*
			Cert auth failed.  If there is no user callback issue fatal alert
			because there will be no intervention to give it a second look.
*/
			if (ssl->sec.validateCert == NULL) {
/*
				ssl->err should have been set correctly above but catch
				any missed cases with the generic BAD_CERTIFICATE alert
*/
				if (ssl->err == SSL_ALERT_NONE) {
					ssl->err = SSL_ALERT_BAD_CERTIFICATE;
				}
				return MATRIXSSL_ERROR;
			}
		}

#ifdef SERVER_WILL_ACCEPT_EMPTY_CLIENT_CERT_MSG
STRAIGHT_TO_USER_CALLBACK:
#endif

/*
		Return from user validation space with knowledge that there is a fatal
		alert or that this is an ANONYMOUS connection.
*/
		rc = matrixUserCertValidator(ssl, ssl->err, ssl->sec.cert, 
				ssl->sec.validateCert);
/*
		Test what the user callback returned.
*/
		ssl->sec.anon = 0;
		if (rc == SSL_ALLOW_ANON_CONNECTION) {
			ssl->sec.anon = 1;
		} else if (rc > 0) {
/*
			User returned an alert.  May or may not be the alert that was
			determined above.
*/
			psTraceIntInfo("Certificate authentication alert %d\n", rc);
			ssl->err = rc;
			return MATRIXSSL_ERROR;
		} else if (rc < 0) {
			psTraceIntInfo("User certificate callback had an internal error\n",
				rc);
			ssl->err = SSL_ALERT_INTERNAL_ERROR;
			return MATRIXSSL_ERROR;
		}
				
		rc = MATRIXSSL_SUCCESS; /* done using rc as a temp */
/*
		User callback returned 0 (continue on).  Did they determine the alert
		was not fatal after all?
*/
		if (ssl->err != SSL_ALERT_NONE) {
			psTraceIntInfo("User certificate callback determined alert %d was NOT fatal\n",
				ssl->err);
			ssl->err = SSL_ALERT_NONE;
		}
				
/*
		Either a client or server could have been processing the cert as part of
		the authentication process.  If server, we move to the client key
		exchange state.
*/
		if (ssl->flags & SSL_FLAGS_SERVER) {
			ssl->hsState = SSL_HS_CLIENT_KEY_EXCHANGE;
		} else {
			ssl->hsState = SSL_HS_SERVER_HELLO_DONE;
#ifdef USE_DHE_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
				ssl->hsState = SSL_HS_SERVER_KEY_EXCHANGE;
			}
#endif /* USE_DHE_CIPHER_SUITE */
		}
		break;
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

#ifdef USE_CLIENT_SIDE_SSL
#ifdef USE_STATELESS_SESSION_TICKETS
	case SSL_HS_NEW_SESSION_TICKET:

		psTraceHs(">>> Client parsing NEW_SESSION_TICKET message\n");
		if (hsLen < 6) {
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			psTraceInfo("Invalid NewSessionTicket message\n");
			return MATRIXSSL_ERROR;
		}
		ssl->sid->sessionTicketLifetimeHint = *c << 24; c++;
		ssl->sid->sessionTicketLifetimeHint |= *c << 16; c++;
		ssl->sid->sessionTicketLifetimeHint |= *c << 8; c++;
		ssl->sid->sessionTicketLifetimeHint |= *c; c++;
		hsLen = *c << 8; c++;
		hsLen |= *c; c++;
		
		if (end - c < hsLen) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Invalid NewSessionTicket message\n");
			return MATRIXSSL_ERROR;
		}
		if (ssl->sid->sessionTicketLen == 0) {
			/* First time receiving a session ticket */
			ssl->sid->sessionTicketLen = hsLen;
			/* There is no obvious pool to allocate from.  If needed in the
				future, could probably use the KEY_POOL since that has a
				lifecycle outside the scope of SSL session contexts */
			if ((ssl->sid->sessionTicket = psMalloc(MATRIX_NO_POOL,
					ssl->sid->sessionTicketLen)) != NULL) {
				memcpy(ssl->sid->sessionTicket, c, ssl->sid->sessionTicketLen);
				c += ssl->sid->sessionTicketLen;
			} else {
				/* Don't fail on alloc error.  Just won't have the ticket for
					next time */
				c += ssl->sid->sessionTicketLen;
				ssl->sid->sessionTicketLen = 0;
			}
		} else {
			/* Updated (or duplicate) ticket */
			psAssert(ssl->sid->sessionTicket); /* exists from previous hs */
			if (hsLen == ssl->sid->sessionTicketLen &&
					(memcmp(c, ssl->sid->sessionTicket, hsLen) == 0)) {
				/* server not updating the ticket */
				c += ssl->sid->sessionTicketLen;
			} else {
				ssl->sid->sessionTicketLen = hsLen;
				psFree(ssl->sid->sessionTicket);
				if ((ssl->sid->sessionTicket = psMalloc(MATRIX_NO_POOL,
						ssl->sid->sessionTicketLen)) != NULL) {
					memcpy(ssl->sid->sessionTicket, c,
						ssl->sid->sessionTicketLen);
					c += ssl->sid->sessionTicketLen;
				} else {
					/* Don't fail on alloc error.  Just won't have the ticket
						for	next time */
					c += ssl->sid->sessionTicketLen;
					ssl->sid->sessionTicketLen = 0;
				}
			}
		}
		ssl->sid->sessionTicketFlag = 0; /* Reset ticket state */
		ssl->hsState = SSL_HS_FINISHED;
		break;
#endif /* USE_STATELESS_SESSION_TICKETS */
	case SSL_HS_SERVER_HELLO_DONE: 
		psTraceHs(">>> Client parsing SERVER_HELLO_DONE message\n");
		if (hsLen != 0) {
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			psTraceInfo("Invalid ServerHelloDone message\n");
			return MATRIXSSL_ERROR;
		}
#ifdef USE_DHE_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
#ifdef USE_ECC_CIPHER_SUITE

			if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
/*
				Set up our private side of the ECC key based on the agreed
				upon curve
*/
				if ((i = psEccMakeKeyEx(ssl->sec.eccDhKeyPool,
						&ssl->sec.eccKeyPriv, ssl->sec.eccKeyPub->dp, pkiData))
						< 0) {
					psEccFreeKey(&ssl->sec.eccKeyPriv);
					psTraceInfo("psEccMakeKeyEx failed\n");
					ssl->err = SSL_ALERT_INTERNAL_ERROR;
					return MATRIXSSL_ERROR;				   
				}
			} else {
#endif
#ifdef REQUIRE_DH_PARAMS		
/*
			Can safely set up our ssl->sec.dhKeyPriv with DH keys
			based on the parameters passed over from the server.
			Storing these in a client specific DH pool because at
			handshake pool creation, the size for PKI was not known
*/
			if (psDhKeyGen(ssl->sec.dhKeyPool, ssl->sec.dhKeyPub.size,
					ssl->sec.dhP, ssl->sec.dhPLen, ssl->sec.dhG,
					ssl->sec.dhGLen, &ssl->sec.dhKeyPriv, pkiData) < 0) {
				return MATRIXSSL_ERROR;
			}
/*
			Freeing as we go.  No more need for G
*/
			psFree(ssl->sec.dhG); ssl->sec.dhG = NULL;
#endif /* REQUIRE_DH_PARAMS */
#ifdef USE_ECC_CIPHER_SUITE
			}		
#endif /* USE_ECC_CIPHER_SUITE */	
		}
#endif /* USE_DHE_CIPHER_SUITE */
		ssl->hsState = SSL_HS_FINISHED;
		rc = SSL_PROCESS_DATA;
		break;

#ifndef USE_ONLY_PSK_CIPHER_SUITE
	case SSL_HS_CERTIFICATE_REQUEST: 
		psTraceHs(">>> Client parsing CERTIFICATE_REQUEST message\n");
		if (hsLen < 4) {
			ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
			psTraceInfo("Invalid Certificate Request message\n");
			return MATRIXSSL_ERROR;
		}
/*
		Currently ignoring the authentication type request because it was
		underspecified up to TLS 1.1 and TLS 1.2 is now taking care of this
		with the supported_signature_algorithms handling
*/
		certTypeLen = *c++;
		if (end - c < certTypeLen) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Invalid Certificate Request message\n");
			return MATRIXSSL_ERROR;
		}
		c += certTypeLen; /* Skipping (RSA_SIGN etc.) */
#ifdef USE_TLS_1_2
		sigAlgMatch = 0;
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			/* supported_signature_algorithms field
				enum {none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
					sha512(6), (255) } HashAlgorithm;

				enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) } SigAlg */
			if (end - c < 2) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid SigHash in Certificate Request message\n");
				return MATRIXSSL_ERROR;
			}
			certChainLen = *c << 8; c++; /* just borrowing this variable */
			certChainLen |= *c; c++;
			if (end - c < certChainLen) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid SigHash in Certificate Request message\n");
				return MATRIXSSL_ERROR;
			}
#ifdef USE_CLIENT_AUTH			
			/* Going to adhere to this supported_signataure_algorithm to
				be compliant with the spec.  This is now the first line
				of testing about what certificates the server will accept.
				If any of our certs do not use a signature algorithm
				that the server supports we will flag that here which will
				ultimately result in an empty CERTIFICATE message and
				no CERTIFICATE_VERIFY message.  We're going to convert
				MD5 to use SHA1 instead though.
				
				Start by building a bitmap of supported algs */
			hashSigAlg = 0;

			while (certChainLen >= 2) {
				i = *c << 8; c++; 
				i += *c; c++;
				certChainLen -= 2;

				if (i == HASH_SIG_1_RSA) {
					hashSigAlg |= HASH_SIG_1_RSA_BM;
				} else if (i == HASH_SIG_256_RSA) {
					hashSigAlg |= HASH_SIG_256_RSA_BM;
#ifdef USE_SHA384
				} else if (i == HASH_SIG_384_RSA) {
					hashSigAlg |= HASH_SIG_384_RSA_BM;
#endif
				}

#ifdef USE_ECC
				if (i == HASH_SIG_1_ECDSA) {
					hashSigAlg |= HASH_SIG_1_ECDSA_BM;
				} else if (i == HASH_SIG_256_ECDSA) {
					hashSigAlg |= HASH_SIG_256_ECDSA_BM;
#ifdef USE_SHA384
				} else if (i == HASH_SIG_384_ECDSA) {
					hashSigAlg |= HASH_SIG_384_ECDSA_BM;
#endif					
				}
#endif /* USE_ECC */
			}
			/* RFC: The end-entity certificate provided by the client MUST
				contain a key that is compatible with certificate_types.
				If the key is a signature key, it MUST be usable with some
				hash/signature algorithm pair in supported_signature_algorithms.
				
				So not only do we have to check the signature algorithm, we
				have to check the pub key type as well. */
			sigAlgMatch = 1; /* de-flag if we hit unsupported one */
			if (ssl->keys == NULL || ssl->keys->cert == NULL) {
				sigAlgMatch = 0;
			} else {
				cert = ssl->keys->cert;
				while (cert) {
					if (cert->pubKeyAlgorithm == OID_RSA_KEY_ALG) {
						if (!(hashSigAlg & HASH_SIG_1_RSA_BM) &&
#ifdef USE_SHA384
								!(hashSigAlg & HASH_SIG_384_RSA_BM) &&
#endif
								!(hashSigAlg & HASH_SIG_256_RSA_BM) &&
								!(hashSigAlg & HASH_SIG_5_RSA_BM)) {
							sigAlgMatch	= 0;
						}
					}
					if (cert->sigAlgorithm == OID_SHA1_RSA_SIG ||
							cert->sigAlgorithm == OID_MD5_RSA_SIG) {
						if (!(hashSigAlg & HASH_SIG_1_RSA_BM)) {
							sigAlgMatch = 0;
						}
					}
					if (cert->sigAlgorithm == OID_SHA256_RSA_SIG) {
						if (!(hashSigAlg & HASH_SIG_256_RSA_BM)) {
							sigAlgMatch = 0;
						}
					}
#ifdef USE_SHA384					
					if (cert->sigAlgorithm == OID_SHA384_RSA_SIG) {
						if (!(hashSigAlg & HASH_SIG_384_RSA_BM)) {
							sigAlgMatch = 0;
						}
					}
#endif					
#ifdef USE_ECC
					if (cert->pubKeyAlgorithm == OID_ECDSA_KEY_ALG) {
						if (!(hashSigAlg & HASH_SIG_1_ECDSA_BM) &&
#ifdef USE_SHA384
								!(hashSigAlg & HASH_SIG_384_ECDSA_BM) &&
#endif
								!(hashSigAlg & HASH_SIG_256_ECDSA_BM) &&
								!(hashSigAlg & HASH_SIG_1_ECDSA_BM)) {
							sigAlgMatch	= 0;
						}
					}
					if (cert->sigAlgorithm == OID_SHA1_ECDSA_SIG) {
						if (!(hashSigAlg & HASH_SIG_1_ECDSA_BM)) {
							sigAlgMatch = 0;
						}
					}
					if (cert->sigAlgorithm == OID_SHA256_ECDSA_SIG) {
						if (!(hashSigAlg & HASH_SIG_256_ECDSA_BM)) {
							sigAlgMatch = 0;
						}
					}
#ifdef USE_SHA384					
					if (cert->sigAlgorithm == OID_SHA384_ECDSA_SIG) {
						if (!(hashSigAlg & HASH_SIG_384_ECDSA_BM)) {
							sigAlgMatch = 0;
						}
					}
#endif
#endif /* USE_ECC */				
					cert = cert->next;
				}
			}
#endif /* USE_CLIENT_AUTH */			
			c += certChainLen;			
		}
#endif	/* TLS_1_2 */
	
		certChainLen = 0;
		if (end - c >= 2) {
			certChainLen = *c << 8; c++;
			certChainLen |= *c; c++;
        	if (end - c < certChainLen) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid Certificate Request message\n");
				return MATRIXSSL_ERROR;
			}
		}
/*
		Check the passed in DNs against our cert issuer to see if they match.
		Only supporting a single cert on the client side.
*/
		ssl->sec.certMatch = 0;
		
#ifdef USE_CLIENT_AUTH		
/*
		If the user has actually gone to the trouble to load a certificate
		to reply with, we flag that here so there is some flexibility as
		to whether we want to reply with something (even if it doesn't match)
		just in case the server is willing to do a custom test of the cert
*/
		if (ssl->keys != NULL && ssl->keys->cert) {
			ssl->sec.certMatch = SSL_ALLOW_ANON_CONNECTION;
		}
#endif /* USE_CLIENT_AUTH */
		
		while (certChainLen > 2) {
			certLen = *c << 8; c++;
			certLen |= *c; c++;
			if ((uint32)(end - c) < certLen || certLen <= 0 || 
					certLen > certChainLen) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid CertificateRequest message\n");
				return MATRIXSSL_ERROR;
			}
			certChainLen -= 2;
#ifdef USE_CLIENT_AUTH
/*
			Can parse the message, but will not look for a match.  The
			setting of certMatch to 1 will trigger the correct response
			in sslEncode
*/
			if (ssl->keys != NULL && ssl->keys->cert) {
/*				
				Flag a match if the hash of the DN issuer is identical
*/ 
				if (ssl->keys->cert->issuer.dnencLen == certLen) {
					if (memcmp(ssl->keys->cert->issuer.dnenc, c, certLen) == 0){
						ssl->sec.certMatch = 1;
					}
				}
			}
#endif /* USE_CLIENT_AUTH */
			c += certLen;
			certChainLen -= certLen;
		}	
#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			/* We let the DN parse complete but if we didn't get a sigAlgMatch
				from the previous test we're going to adhere to that for spec
				compliance.  So here goes */
			if (sigAlgMatch == 0) {
				ssl->sec.certMatch = 0;
			}
		}
#endif		
		ssl->hsState = SSL_HS_SERVER_HELLO_DONE;
		break;
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */
#endif /* USE_CLIENT_SIDE_SSL */

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_CLIENT_AUTH) && defined(USE_SERVER_SIDE_SSL)
	case SSL_HS_CERTIFICATE_VERIFY: 
		psTraceHs(">>> Server parsing CERTIFICATE_VERIFY message\n");
		
#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			hashSigAlg = *c << 8; c++;
			hashSigAlg |= *c; c++;
			if ((hashSigAlg >> 8) == 0x4) {
				certVerifyLen = SHA256_HASH_SIZE;
#ifdef USE_SHA384				
			} else if  ((hashSigAlg >> 8) == 0x5) {
				/* The one-off grab of SHA-384 handshake hash */
				sslSha384RetrieveHSHash(ssl, hsMsgHash);
				certVerifyLen = SHA384_HASH_SIZE;
#endif				
			} else if ((hashSigAlg >> 8) == 0x2) {
				/* The one-off grab of SHA-1 handshake hash */
				sslSha1RetrieveHSHash(ssl, hsMsgHash);
				certVerifyLen = SHA1_HASH_SIZE;
			} else {
				psTraceInfo("TODO: support other certVerify hash size\n");
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid Certificate Verify message\n");
				return MATRIXSSL_ERROR;
			}
		} else {
			certVerifyLen =  MD5_HASH_SIZE + SHA1_HASH_SIZE;
		}
#else
		certVerifyLen =  MD5_HASH_SIZE + SHA1_HASH_SIZE;
#endif /* USE_TLS_1_2 */
			
		pubKeyLen = *c << 8; c++;
		pubKeyLen |= *c; c++;
		if ((uint32)(end - c) < pubKeyLen) {
			ssl->err = SSL_ALERT_DECODE_ERROR;
			psTraceInfo("Invalid Certificate Verify message\n");
			return MATRIXSSL_ERROR;
		}
/*
		The server side verification of client identity.  If we can match
		the signature we know the client has possesion of the private key.
*/
#ifdef USE_ECC
/*
		Need to read sig algorithm type out of cert itself
*/
		if (ssl->sec.cert->pubKeyAlgorithm == OID_ECDSA_KEY_ALG) {
			rc = 0;
			
#ifdef USE_TLS_1_2
			if (ssl->flags & SSL_FLAGS_TLS_1_2) {
				if (psEcDsaValidateSignature(cvpkiPool,
						&ssl->sec.cert->publicKey.key->ecc, c, pubKeyLen,
						hsMsgHash, certVerifyLen, &rc, pkiData) != 0) {
					psTraceInfo("ECDSA signature validation failed\n");
					ssl->err = SSL_ALERT_BAD_CERTIFICATE;
					return MATRIXSSL_ERROR;						   
				}
			} else {
				certVerifyLen = SHA1_HASH_SIZE; /* per spec */
				if (psEcDsaValidateSignature(cvpkiPool,
						&ssl->sec.cert->publicKey.key->ecc, c, pubKeyLen,
						hsMsgHash + MD5_HASH_SIZE, certVerifyLen, &rc,
						pkiData) != 0) {
					psTraceInfo("ECDSA signature validation failed\n");
					ssl->err = SSL_ALERT_BAD_CERTIFICATE;
					return MATRIXSSL_ERROR;						   
				}
			}
#else
			certVerifyLen = SHA1_HASH_SIZE; /* per spec */
			if (psEcDsaValidateSignature(cvpkiPool,
					&ssl->sec.cert->publicKey.key->ecc, c, pubKeyLen,
					hsMsgHash + MD5_HASH_SIZE, certVerifyLen, &rc, pkiData)
					!= 0) {
				psTraceInfo("ECDSA signature validation failed\n");
				ssl->err = SSL_ALERT_BAD_CERTIFICATE;
				return MATRIXSSL_ERROR;						   
			}
#endif			
			if (rc != 1) {
				psTraceInfo("Can't verify certVerify sig\n");
				ssl->err = SSL_ALERT_BAD_CERTIFICATE;
				return MATRIXSSL_ERROR;
			}
			rc = MATRIXSSL_SUCCESS; /* done using rc as a temp */
		} else {
#endif /* USE_ECC */		
#ifdef USE_RSA
		


#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			if ((i = pubRsaDecryptSignedElement(cvpkiPool,
					&ssl->sec.cert->publicKey, c, pubKeyLen, certVerify,
					certVerifyLen, pkiData)) < 0) {
				psTraceInfo("Unable to decrypt CertVerify digital element\n");
				return MATRIXSSL_ERROR;
			}
		} else {
			if (csRsaDecryptPub(cvpkiPool, &ssl->sec.cert->publicKey, c,
					pubKeyLen, certVerify, certVerifyLen, pkiData) < 0) {
				psTraceInfo("Unable to publicly decrypt Certificate Verify message\n");
				return MATRIXSSL_ERROR;
			}		
		}
#else /* !USE_TLS_1_2 */
		if (csRsaDecryptPub(cvpkiPool, &ssl->sec.cert->publicKey, c,
				pubKeyLen, certVerify, certVerifyLen, pkiData) < 0) {
			psTraceInfo("Unable to publicly decrypt Certificate Verify message\n");
			return MATRIXSSL_ERROR;
		}
#endif /* USE_TLS_1_2 */		
		
		if (memcmp(certVerify, hsMsgHash, certVerifyLen) != 0) {
			psTraceInfo("Unable to verify client certificate signature\n");
			return MATRIXSSL_ERROR;
		}
#else /* RSA is 'default' so if that didn't get hit there is a problem */
		psTraceInfo("There is no handler for CertificateVerify parse. ERROR\n");
		return MATRIXSSL_ERROR;
#endif /* USE_RSA */	
#ifdef USE_ECC
		}
#endif /* USE_ECC*/			
		
		c += pubKeyLen;
		ssl->hsState = SSL_HS_FINISHED;
		break;
#endif /* USE_SERVER_SIDE_SSL && USE_CLIENT_AUTH */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

	case SSL_HS_SERVER_KEY_EXCHANGE:

#ifdef USE_CLIENT_SIDE_SSL
		psTraceHs(">>> Client parsing SERVER_KEY_EXCHANGE message\n");
#ifdef USE_DHE_CIPHER_SUITE
/*
		Check the DH status.  Could also be a PSK_DHE suite
*/
		if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {

#ifdef USE_ANON_DH_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_ANON_CIPHER) {
			}
#endif /* USE_ANON_DH_CIPHER_SUITE */

#ifdef USE_PSK_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
/*
 * 				Using the value of MAX_HINT_SIZE to know if the user is
 * 				expecting a hint.  The PSK specification ONLY allows these
 * 				hints if the "application profile specification" says to
 * 				include them.
 * 
 * 				Contact Inside if you require assistance here
 */ 
				if (SSL_PSK_MAX_HINT_SIZE > 0) {
					if ((end - c) < 2) {
						ssl->err = SSL_ALERT_DECODE_ERROR;
						psTraceInfo("Invalid PSK Hint Len\n");
						return MATRIXSSL_ERROR;
					}
					ssl->sec.hintLen = *c << 8; c++;
					ssl->sec.hintLen |= *c; c++;
					if (ssl->sec.hintLen > 0) {
						if ((unsigned short)(end - c) < ssl->sec.hintLen) {
							ssl->err = SSL_ALERT_DECODE_ERROR;
							psTraceInfo("Invalid PSK Hint\n");
							return MATRIXSSL_ERROR;
						}					
						ssl->sec.hint = psMalloc(ssl->hsPool, ssl->sec.hintLen);
						if (ssl->sec.hint == NULL) {
							return SSL_MEM_ERROR;
						}
						memcpy(ssl->sec.hint, c, ssl->sec.hintLen);
						c += ssl->sec.hintLen;
					}
				}
			}
#endif /* USE_PSK_CIPHER_SUITE */
#ifdef USE_ECC_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
/*
				Entry point for ECDHE SKE parsing
*/
				sigStart = c;
				if ((end - c) < 4) { /* ECCurveType, NamedCurve, ECPoint len */
					ssl->err = SSL_ALERT_DECODE_ERROR;
					psTraceInfo("Invalid ServerKeyExchange message\n");
					return MATRIXSSL_ERROR;
				}
/*
				Only named curves are currently supported
				
				enum { explicit_prime (1), explicit_char2 (2),
					named_curve (3), reserved(248..255) } ECCurveType;
*/
				if ((int32)*c != 3) {
					ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
					psTraceIntInfo("Unsupported ECCurveType message %d\n",
						(int32)*c);
					return MATRIXSSL_ERROR;
				}
				c++;
/*
				Next is curveId
*/
				i = *c << 8; c++;
				i |= *c; c++;

				ssl->sec.eccKeyPub = psMalloc(ssl->hsPool, sizeof(psEccKey_t));
				if (ssl->sec.eccKeyPub == NULL) {
					return SSL_MEM_ERROR;
				}
				memset(ssl->sec.eccKeyPub, 0, sizeof(psEccKey_t));
/*
				Return -1 if this isn't a curve we specified in client hello
*/
				if (getEccParamById(i, &ssl->sec.eccKeyPub->dp) < 0) {
					ssl->err = SSL_ALERT_ILLEGAL_PARAMETER;
					psTraceIntInfo("Error: Could not match EC curve: %d\n", i);
					return MATRIXSSL_ERROR;
				}
/*
				struct {
					opaque point <1..2^8-1>;
				} ECPoint;
				
				RFC4492
				This is the byte string representation of an elliptic curve
				point following the conversion routine in Section 4.3.6 of ANSI
				X9.62.  This byte string may represent an elliptic curve point
				in uncompressed or compressed format; it MUST conform to what 
				client has requested through a Supported Point Formats Extension
				if this extension was used.
*/
				i = *c; c++;
				if ((end - c) < i) {
					ssl->err = SSL_ALERT_DECODE_ERROR;
					psTraceInfo("Invalid ServerKeyExchange message\n");
					return MATRIXSSL_ERROR;
				}
				if (psEccX963ImportKey(ssl->hsPool, c, i,
						ssl->sec.eccKeyPub) < 0) {
					ssl->err = SSL_ALERT_DECODE_ERROR;
					return MATRIXSSL_ERROR;
				}
				c += i;
				sigStop = c;
 
			} else {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef REQUIRE_DH_PARAMS
/*
			Entry point for standard DH SKE parsing
*/
			if ((end - c) < 2) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid ServerKeyExchange message\n");
				return MATRIXSSL_ERROR;
			}
#ifndef USE_ONLY_PSK_CIPHER_SUITE
			sigStart = c;
#endif
			ssl->sec.dhPLen = *c << 8; c++;
			ssl->sec.dhPLen |= *c; c++;
			if ((uint32)(end - c) < ssl->sec.dhPLen) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid ServerKeyExchange message\n");
				return MATRIXSSL_ERROR;
			}
			ssl->sec.dhP = psMalloc(ssl->hsPool, ssl->sec.dhPLen);
			if (ssl->sec.dhP == NULL) {
				return SSL_MEM_ERROR;
			}
			memcpy(ssl->sec.dhP, c, ssl->sec.dhPLen);
			c += ssl->sec.dhPLen;

			ssl->sec.dhGLen = *c << 8; c++;
			ssl->sec.dhGLen |= *c; c++;
			if ((uint32)(end - c) < ssl->sec.dhGLen) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid ServerKeyExchange message\n");
				return MATRIXSSL_ERROR;
			}
			ssl->sec.dhG = psMalloc(ssl->hsPool, ssl->sec.dhGLen);
			if (ssl->sec.dhG == NULL) {
				return SSL_MEM_ERROR;
			}
			memcpy(ssl->sec.dhG, c, ssl->sec.dhGLen);
			c += ssl->sec.dhGLen;

			pubDhLen = *c << 8; c++;
			pubDhLen |= *c; c++;

			if ((uint32)(end - c) < pubDhLen) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid ServerKeyExchange message\n");
				return MATRIXSSL_ERROR;
			}
/*
			The next bit on the wire is the public key.  Assign to
			the session in structure format
*/
			if (psDhImportPubKey(ssl->hsPool, c, pubDhLen,
					&ssl->sec.dhKeyPub) < 0) {
				return MATRIXSSL_ERROR;
			}
			c += pubDhLen;
#ifndef USE_ONLY_PSK_CIPHER_SUITE
			sigStop = c;
#endif
/*
			Key size is now known for premaster storage.  The extra byte
			is to account for the cases where the pubkey length ends
			up being a byte less than the premaster.  The premaster size
			is adjusted accordingly when the actual secret is generated.
*/
			ssl->sec.premasterSize = pubDhLen + 1;
#ifdef USE_PSK_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
/*
				In the PSK case, the true premaster size is still unknown
				but didn't want to change the allocation logic so just
				make sure the size is large enough for the additional
				PSK and length bytes
*/
				ssl->sec.premasterSize += SSL_PSK_MAX_KEY_SIZE + 4;
			}
#endif /* USE_PSK_CIPHER_SUITE */
			ssl->sec.premaster = psMalloc(ssl->hsPool, ssl->sec.premasterSize);
			if (ssl->sec.premaster == NULL) {
				return SSL_MEM_ERROR;
			}
#ifdef USE_ANON_DH_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_ANON_CIPHER) {
/*
				In the anonymous case, there is no signature to follow
*/
				ssl->hsState = SSL_HS_SERVER_HELLO_DONE;
				break;
			}
#endif /* USE_ANON_DH_CIPHER_SUITE */
#endif /* REQUIRE_DH_PARAMS */
#ifdef USE_ECC_CIPHER_SUITE
			}
#endif /* USE_ECC_CIPHER_SUITE */
/*
			This layer of authentation is at the key exchange level.
			The server has sent a signature of the key material that
			the client can validate here.
*/
			if ((end - c) < 2) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid ServerKeyExchange message\n");
				return MATRIXSSL_ERROR;
			}
			
#ifdef USE_TLS_1_2
			hashSize = 0;
			if (ssl->flags & SSL_FLAGS_TLS_1_2) {
				skeHashSigAlg = *c << 8; c++;
				skeHashSigAlg += *c; c++;
				if ((skeHashSigAlg >> 8) == 0x4) {
					hashSize = SHA256_HASH_SIZE;
				} else if ((skeHashSigAlg >> 8) == 0x5) {
					hashSize = SHA384_HASH_SIZE;
				} else if ((skeHashSigAlg >> 8) == 0x2) {
					hashSize = SHA1_HASH_SIZE;
				} else {
					psTraceIntInfo("Unsupported hashAlg SKE parse: %d\n",
						skeHashSigAlg);
					return PS_UNSUPPORTED_FAIL;
				}
			}
#endif /* USE_TLS_1_2 */
			pubDhLen = *c << 8; c++; /* Reusing variable */
			pubDhLen |= *c; c++;
							
			if ((uint32)(end - c) < pubDhLen) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid ServerKeyExchange message\n");
				return MATRIXSSL_ERROR;
			}
			
#ifdef USE_RSA_CIPHER_SUITE			
			if (ssl->flags & SSL_FLAGS_DHE_WITH_RSA) {
/*
				We are using the public key provided by the server during the
				CERTIFICATE message.  That cert has already been authenticated
				by this point so this signature is to ensure that entity is also
				the one negotiating keys with us.
*/
#ifdef USE_TLS_1_2
				/* TLS 1.2 uses single hashes everywhere */
				if (ssl->flags & SSL_FLAGS_TLS_1_2) {
					if (hashSize == SHA256_HASH_SIZE) {
						psSha256Init(&digestCtx);
						psSha256Update(&digestCtx, ssl->sec.clientRandom,
							SSL_HS_RANDOM_SIZE);
						psSha256Update(&digestCtx, ssl->sec.serverRandom,
							SSL_HS_RANDOM_SIZE);
						psSha256Update(&digestCtx, sigStart,
							(uint32)(sigStop - sigStart));
						psSha256Final(&digestCtx, hsMsgHash);
#ifdef USE_SHA384
					} else if (hashSize == SHA384_HASH_SIZE) {
						psSha384Init(&digestCtx);
						psSha384Update(&digestCtx, ssl->sec.clientRandom,
							SSL_HS_RANDOM_SIZE);
						psSha384Update(&digestCtx, ssl->sec.serverRandom,
							SSL_HS_RANDOM_SIZE);
						psSha384Update(&digestCtx, sigStart,
							(uint32)(sigStop - sigStart));
						psSha384Final(&digestCtx, hsMsgHash);
#endif /* USE_SHA384 */
					} else {
						psSha1Init(&digestCtx);
						psSha1Update(&digestCtx, ssl->sec.clientRandom,
							SSL_HS_RANDOM_SIZE);
						psSha1Update(&digestCtx, ssl->sec.serverRandom,
							SSL_HS_RANDOM_SIZE);
						psSha1Update(&digestCtx, sigStart,
							(uint32)(sigStop - sigStart));
						psSha1Final(&digestCtx, hsMsgHash);
					}
				
				} else {
					psMd5Init(&digestCtx);
					psMd5Update(&digestCtx, ssl->sec.clientRandom,
						SSL_HS_RANDOM_SIZE);
					psMd5Update(&digestCtx, ssl->sec.serverRandom,
						SSL_HS_RANDOM_SIZE);
					psMd5Update(&digestCtx, sigStart,
						(uint32)(sigStop - sigStart));
					psMd5Final(&digestCtx, hsMsgHash);

					psSha1Init(&digestCtx);
					psSha1Update(&digestCtx, ssl->sec.clientRandom,
						SSL_HS_RANDOM_SIZE);
					psSha1Update(&digestCtx, ssl->sec.serverRandom,
						SSL_HS_RANDOM_SIZE);
					psSha1Update(&digestCtx, sigStart,
						(uint32)(sigStop - sigStart));
					psSha1Final(&digestCtx, hsMsgHash + MD5_HASH_SIZE);
				}
#else /* USE_TLS_1_2 */		
/*
				The signature portion is an MD5 and SHA1 concat of the randoms
				and the contents of this server key exchange message.
*/
				psMd5Init(&digestCtx);
				psMd5Update(&digestCtx, ssl->sec.clientRandom,
					SSL_HS_RANDOM_SIZE);
				psMd5Update(&digestCtx, ssl->sec.serverRandom,
					SSL_HS_RANDOM_SIZE);
				psMd5Update(&digestCtx, sigStart, (uint32)(sigStop - sigStart));
				psMd5Final(&digestCtx, hsMsgHash);

				psSha1Init(&digestCtx);
				psSha1Update(&digestCtx, ssl->sec.clientRandom,
					SSL_HS_RANDOM_SIZE);
				psSha1Update(&digestCtx, ssl->sec.serverRandom,
					SSL_HS_RANDOM_SIZE);
				psSha1Update(&digestCtx, sigStart,
					(uint32)(sigStop - sigStart));
				psSha1Final(&digestCtx, hsMsgHash + MD5_HASH_SIZE);
#endif /* USE_TLS_1_2 */





#ifdef USE_TLS_1_2
				if (ssl->flags & SSL_FLAGS_TLS_1_2) {
					/* TLS 1.2 doesn't just sign the straight hash so we can't
						pass it through the normal public decryption becuase
						that expects an output length of a known size. These
						signatures are done on elements with some ASN.1
						wrapping so a special decryption with parse is needed */
					
					if (pubRsaDecryptSignedElement(skepkiPool,
							&ssl->sec.cert->publicKey, c, pubDhLen, sigOut,
							hashSize, pkiData) < 0) {
						psTraceInfo("Can't decrypt serverKeyExchange sig\n");
						ssl->err = SSL_ALERT_BAD_CERTIFICATE;
						return MATRIXSSL_ERROR;
					}
					
				} else {
					hashSize = MD5_HASH_SIZE + SHA1_HASH_SIZE;
					
					if (csRsaDecryptPub(skepkiPool, &ssl->sec.cert->publicKey,
							c, pubDhLen, sigOut, hashSize, pkiData) < 0) {
						psTraceInfo("Can't decrypt server key exchange sig\n");
						ssl->err = SSL_ALERT_BAD_CERTIFICATE;
						return MATRIXSSL_ERROR;
					}
				}
#else /* ! USE_TLS_1_2 */
				hashSize = MD5_HASH_SIZE + SHA1_HASH_SIZE;
				if (csRsaDecryptPub(skepkiPool, &ssl->sec.cert->publicKey,
						c, pubDhLen, sigOut, hashSize, pkiData) < 0) {
					psTraceInfo("Unable to decrypt server key exchange sig\n");
					ssl->err = SSL_ALERT_BAD_CERTIFICATE;
					return MATRIXSSL_ERROR;
				}
#endif /* USE_TLS_1_2 */		
				
				/* Now have hash from the server. Create ours and check match */
				c += pubDhLen;

				if (memcmp(sigOut, hsMsgHash, hashSize) != 0) {
					psTraceInfo("Fail to verify serverKeyExchange sig\n");
					ssl->err = SSL_ALERT_BAD_CERTIFICATE;
					return MATRIXSSL_ERROR;
				}
			}
#endif /* USE_RSA_CIPHER_SUITE */
#ifdef USE_ECC_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_DHE_WITH_DSA) {
/*
				RFC4492: The default hash function is SHA-1, and sha_size is 20.
*/
#ifdef USE_TLS_1_2
				if (ssl->flags & SSL_FLAGS_TLS_1_2 &&
						(hashSize == SHA256_HASH_SIZE)) {
					psSha256Init(&digestCtx);
					psSha256Update(&digestCtx, ssl->sec.clientRandom,
						SSL_HS_RANDOM_SIZE);
					psSha256Update(&digestCtx, ssl->sec.serverRandom,
						SSL_HS_RANDOM_SIZE);
					psSha256Update(&digestCtx, sigStart,
						(int32)(sigStop - sigStart));
					psSha256Final(&digestCtx, hsMsgHash);
#ifdef USE_SHA384					
				} else if (ssl->flags & SSL_FLAGS_TLS_1_2 &&
						(hashSize == SHA384_HASH_SIZE)) {
					psSha384Init(&digestCtx);
					psSha384Update(&digestCtx, ssl->sec.clientRandom,
						SSL_HS_RANDOM_SIZE);
					psSha384Update(&digestCtx, ssl->sec.serverRandom,
						SSL_HS_RANDOM_SIZE);
					psSha384Update(&digestCtx, sigStart,
						(int32)(sigStop - sigStart));
					psSha384Final(&digestCtx, hsMsgHash);
#endif					
				} else {
					hashSize = SHA1_HASH_SIZE;
					psSha1Init(&digestCtx);
					psSha1Update(&digestCtx, ssl->sec.clientRandom,
						SSL_HS_RANDOM_SIZE);
					psSha1Update(&digestCtx, ssl->sec.serverRandom,
						SSL_HS_RANDOM_SIZE);
					psSha1Update(&digestCtx, sigStart,
						(int32)(sigStop - sigStart));
					psSha1Final(&digestCtx, hsMsgHash);
				}
#else /* USE_TLS_1_2 */
				hashSize = SHA1_HASH_SIZE;
				psSha1Init(&digestCtx);
				psSha1Update(&digestCtx, ssl->sec.clientRandom,
					SSL_HS_RANDOM_SIZE);
				psSha1Update(&digestCtx, ssl->sec.serverRandom,
					SSL_HS_RANDOM_SIZE);
				psSha1Update(&digestCtx, sigStart, (int32)(sigStop - sigStart));
				psSha1Final(&digestCtx, hsMsgHash);
#endif /* USE_TLS_1_2 */	
				i = 0;
				
				if (psEcDsaValidateSignature(skepkiPool,
						&ssl->sec.cert->publicKey.key->ecc, c, pubDhLen,
						hsMsgHash, hashSize, &i, pkiData) != 0) {
					psTraceInfo("ECDSA signature validation failed\n");
					ssl->err = SSL_ALERT_BAD_CERTIFICATE;
					return MATRIXSSL_ERROR;						   
				}
				c += pubDhLen;
/*
				The validation code comes out of the final parameter
*/
				if (i != 1) {
					psTraceInfo("Can't verify serverKeyExchange sig\n");
					ssl->err = SSL_ALERT_BAD_CERTIFICATE;
					return MATRIXSSL_ERROR;
					
				}
			}
#endif /* USE_ECC_CIPHER_SUITE */
			
			ssl->hsState = SSL_HS_SERVER_HELLO_DONE;
			
		}
#endif /* USE_DHE_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
/*
		Entry point for basic PSK ciphers (not DHE or RSA) parsing SKE message
*/
		if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
			if ((end - c) < 2) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid ServerKeyExchange message\n");
				return MATRIXSSL_ERROR;
			}
			ssl->sec.hintLen = *c << 8; c++;
			ssl->sec.hintLen |= *c; c++;
			if ((uint32)(end - c) < ssl->sec.hintLen) {
				ssl->err = SSL_ALERT_DECODE_ERROR;
				psTraceInfo("Invalid ServerKeyExchange message\n");
				return MATRIXSSL_ERROR;
			}
			if (ssl->sec.hintLen > 0) {
				ssl->sec.hint = psMalloc(ssl->hsPool, ssl->sec.hintLen);
				if (ssl->sec.hint == NULL) {
					return SSL_MEM_ERROR;
				}
				memcpy(ssl->sec.hint, c, ssl->sec.hintLen);
				c += ssl->sec.hintLen;
			}
			ssl->hsState = SSL_HS_SERVER_HELLO_DONE;
		}
#endif /* USE_PSK_CIPHER_SUITE */
#else /* USE_CLIENT_SIDE_SSL */
		ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
		return MATRIXSSL_ERROR;
#endif /* USE_CLIENT_SIDE_SSL */
		break;

	default:
		ssl->err = SSL_ALERT_UNEXPECTED_MESSAGE;
		return MATRIXSSL_ERROR;
	}
	
	
/*
	if we've got more data in the record, the sender has packed
	multiple handshake messages in one record.  Parse the next one.
*/
	if (c < end) {
		goto parseHandshake;
	}
	return rc;
}

/******************************************************************************/
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
#ifdef USE_CERT_CHAIN_PARSING
static int32 parseSingleCert(ssl_t *ssl, unsigned char *c, unsigned char *end, 
						   int32 certLen)
{
	int32			parseLen;
	psX509Cert_t	*cert, *p;

/*
	Extract the binary cert message into the cert structure
*/
	if ((parseLen = psX509ParseCert(ssl->hsPool, c, certLen, &cert, 0)) < 0) {
		psX509FreeCert(cert);
		if (parseLen == PS_MEM_FAIL) {
			ssl->err = SSL_ALERT_INTERNAL_ERROR;
		} else if (parseLen == PS_CERT_AUTH_FAIL_DATE) {
			ssl->err = SSL_ALERT_CERTIFICATE_EXPIRED;	
		} else {
			ssl->err = SSL_ALERT_BAD_CERTIFICATE;
		}
		return MATRIXSSL_ERROR;
	}
	if (ssl->sec.cert == NULL) {
		ssl->sec.cert = cert;
	} else {
		p = ssl->sec.cert;
		while (p->next != NULL) {
			p = p->next;
		}
		p->next = cert;
	}
	return parseLen;
}
#endif /* USE_CERT_CHAIN_PARSING */
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */

/******************************************************************************/
