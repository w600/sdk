 /*
 *	sslEncode.c
 *	Release $Name: MATRIXSSL-3-6-1-OPEN $
 *
 *	Secure Sockets Layer protocol message encoding portion of MatrixSSL
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

/******************************************************************************/

#ifndef USE_ONLY_PSK_CIPHER_SUITE
static int32 writeCertificate(ssl_t *ssl, sslBuf_t *out, int32 notEmpty);
#endif
static int32 writeChangeCipherSpec(ssl_t *ssl, sslBuf_t *out);
static int32 writeFinished(ssl_t *ssl, sslBuf_t *out);
static int32 writeAlert(ssl_t *ssl, unsigned char level, 
				unsigned char description, sslBuf_t *out, uint32 *requiredLen);
static int32 writeRecordHeader(ssl_t *ssl, int32 type, int32 hsType, 
				int32 *messageSize,	char *padLen, unsigned char **encryptStart,
							   unsigned char **end, unsigned char **c);

static int32 encryptRecord(ssl_t *ssl, int32 type, int32 messageSize,
				int32 padLen, unsigned char *pt, sslBuf_t *out,
				unsigned char **c);

#ifdef USE_CLIENT_SIDE_SSL
static int32 writeClientKeyExchange(ssl_t *ssl, sslBuf_t *out);
#endif /* USE_CLIENT_SIDE_SSL */

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
static int32 writeCertificateRequest(ssl_t *ssl, sslBuf_t *out, int32 certLen,
				int32 certCount);
static int32 writeMultiRecordCertRequest(ssl_t *ssl, sslBuf_t *out,
				int32 certLen, int32 certCount, int32 sigHashLen);
#endif
#if defined(USE_CLIENT_SIDE_SSL) && defined(USE_CLIENT_AUTH)
static int32 writeCertificateVerify(ssl_t *ssl, sslBuf_t *out);
static int32 nowDoCvPka(ssl_t *ssl);
#endif
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

#ifdef USE_SERVER_SIDE_SSL
static int32 writeServerHello(ssl_t *ssl, sslBuf_t *out);
static int32 writeServerHelloDone(ssl_t *ssl, sslBuf_t *out);
#ifdef USE_PSK_CIPHER_SUITE
static int32 writePskServerKeyExchange(ssl_t *ssl, sslBuf_t *out);
#endif /* USE_PSK_CIPHER_SUITE */
#ifdef USE_DHE_CIPHER_SUITE
static int32 writeServerKeyExchange(ssl_t *ssl, sslBuf_t *out, uint32 pLen,
					unsigned char *p, uint32 gLen, unsigned char *g);
#endif /* USE_DHE_CIPHER_SUITE */
#ifdef USE_STATELESS_SESSION_TICKETS /* Already inside a USE_SERVER_SIDE block */
static int32 writeNewSessionTicket(ssl_t *ssl, sslBuf_t *out);
#endif
#endif /* USE_SERVER_SIDE_SSL */

static int32 secureWriteAdditions(ssl_t *ssl, int32 numRecs);
static int32 encryptFlight(ssl_t *ssl, unsigned char **end);

#ifdef USE_ZLIB_COMPRESSION
#define MAX_ZLIB_COMPRESSED_OH	128 /* Only FINISHED message supported */
#endif
/******************************************************************************/
/*
	This works for both in-situ and external buf
	
	buf		in	Start of allocated buffer (header bytes beyond are overwritten)
			out	Start of encrypted data on function success
					
	size	in	Total size of the allocated buffer
	
	ptBuf	in	Pointer to front of the plain text data to be encrypted
	
	len		in	Length of incoming plain text
			out	Length of encypted text on function success
			out	Length of required 'size' on SSL_FULL
*/
int32 matrixSslEncode(ssl_t *ssl, unsigned char *buf, uint32 size,
		unsigned char *ptBuf, uint32 *len)
{
	unsigned char	*c, *end, *encryptStart;
	char			padLen;
	int32			messageSize, rc;
	psBuf_t			tmpout;
	
	/* If we've had a protocol error, don't allow further use of the session
		Also, don't allow a application data record to be encoded unless the
		handshake is complete.
	*/
	if (ssl->flags & SSL_FLAGS_ERROR || ssl->hsState != SSL_HS_DONE ||
			ssl->flags & SSL_FLAGS_CLOSED) {
		psTraceInfo("Bad SSL state for matrixSslEncode call attempt\n");
		return MATRIXSSL_ERROR;
	}

	c = buf;
	end = buf + size;
	
#ifdef USE_BEAST_WORKAROUND
	if (ssl->bFlags & BFLAG_STOP_BEAST) {
		messageSize = ssl->recordHeadLen + 1; /* single byte is the fix */
		if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_APPLICATION_DATA, 0,
				&messageSize, &padLen, &encryptStart, &end, &c)) < 0) {
			if (rc == SSL_FULL) {
				*len = messageSize;
			}
			return rc;
		}
		psAssert(encryptStart == buf + ssl->recordHeadLen);
		c += 1;
		*len -= 1;
			
		tmpout.buf = tmpout.start = tmpout.end = buf;
		tmpout.size = size;
		if ((rc = encryptRecord(ssl, SSL_RECORD_TYPE_APPLICATION_DATA,
				messageSize, padLen, ptBuf, &tmpout, &c)) < 0) {
			return rc;
		}
		ptBuf += 1;
		tmpout.end = tmpout.end + (c - buf);
		
	}
#endif
/*
	writeRecordHeader will determine SSL_FULL cases.  The expected
	messageSize to writeRecored header is the plain text length plus the
	record header length
 */
	messageSize = ssl->recordHeadLen + *len;
	
	if (messageSize > SSL_MAX_BUF_SIZE) {
		psTraceIntInfo("Message too large for matrixSslEncode: %d\n",
			messageSize);
		return PS_MEM_FAIL;
	}
	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_APPLICATION_DATA, 0,
			&messageSize, &padLen, &encryptStart, &end, &c)) < 0) {
		if (rc == SSL_FULL) {
			*len = messageSize;
		}
		return rc;
	}

	c += *len;
#ifdef USE_BEAST_WORKAROUND
	if (ssl->bFlags & BFLAG_STOP_BEAST) {
		/* The tmpout buf already contains the single byte record and has
			updated pointers for current location.  Disable at this time */
		ssl->bFlags &= ~BFLAG_STOP_BEAST;
	} else {
		tmpout.buf = tmpout.start = tmpout.end = buf;
		tmpout.size = size;
	}
#else
	tmpout.buf = tmpout.start = tmpout.end = buf;
	tmpout.size = size;
#endif	
			
	if ((rc = encryptRecord(ssl, SSL_RECORD_TYPE_APPLICATION_DATA,
			messageSize, padLen, ptBuf, &tmpout, &c)) < 0) {
		return rc;
	}
	*len = (int32)(c - buf);

#ifdef SSL_REHANDSHAKES_ENABLED
	ssl->rehandshakeBytes += *len;
	if (ssl->rehandshakeBytes >= BYTES_BEFORE_RH_CREDIT) {
		if (ssl->rehandshakeCount < 0x8000) {
			/* Don't increment if disabled (-1) */
			if (ssl->rehandshakeCount >= 0) {
				ssl->rehandshakeCount++;
			}
		}
		ssl->rehandshakeBytes = 0;
	}
#endif /* SSL_REHANDSHAKES_ENABLED */
	return *len;
}

/******************************************************************************/
/*
	A helper function for matrixSslGetWritebuf to determine the correct
	destination size before allocating an output buffer. 
 */
int32 matrixSslGetEncodedSize(ssl_t *ssl, uint32 len)
{	
	len += ssl->recordHeadLen;
	if (ssl->flags & SSL_FLAGS_WRITE_SECURE) {
		len += ssl->enMacSize;
#ifdef USE_TLS_1_1
/*
		If a block cipher is being used TLS 1.1 requires the use
		of an explicit IV.  This is an extra random block of data
		prepended to the plaintext before encryption.  Account for
		that extra length here.
*/
		if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
				(ssl->flags & SSL_FLAGS_TLS_1_1) &&	(ssl->enBlockSize > 1)) {
			len += ssl->enBlockSize;
		}

#if defined(USE_TLS_1_2) && defined(USE_AES_GCM)
		if ((ssl->flags & SSL_FLAGS_TLS_1_2) &&
				(ssl->flags & SSL_FLAGS_GMAC_W)) {
			len += TLS_GCM_TAG_LEN + ssl->nonceCtrLen;
		}
#endif /* USE_TLS_1_2 && AES_GCM */
#endif /* USE_TLS_1_1 */
		
#ifdef USE_BEAST_WORKAROUND
		if (ssl->bFlags & BFLAG_STOP_BEAST) {
			/* Original message less one */
			len += psPadLenPwr2(len - 1 - ssl->recordHeadLen, ssl->enBlockSize);
			/* The single byte record overhead */
			len += ssl->recordHeadLen + ssl->enMacSize;
			len += psPadLenPwr2(1 + ssl->enMacSize, ssl->enBlockSize);
		} else {
			len += psPadLenPwr2(len - ssl->recordHeadLen, ssl->enBlockSize);
		}
#else
		len += psPadLenPwr2(len - ssl->recordHeadLen, ssl->enBlockSize);
#endif		
	}
	return len;
}

#ifndef USE_ONLY_PSK_CIPHER_SUITE				
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
/* Second parameter includes handshake header length */
static int32 addCertFragOverhead(ssl_t *ssl, int32 totalCertLen)
{
	int32 oh = 0;
	
	/* For each additional record, we'll need a record header and
		secureWriteAdditions.  Borrowing ssl->fragIndex and ssl->fragTotal */
	ssl->fragTotal = totalCertLen;
	ssl->fragIndex = 0;
	while (ssl->fragTotal > 0) {
		if (ssl->fragIndex == 0) {
			/* First one is accounted for below as normal */
			ssl->fragTotal -= ssl->maxPtFrag;
			ssl->fragIndex++;
		} else {
			/* Remember this stage is simply for SSL_FULL test
			  so just incr totalCertLen to add overhead */
			oh += secureWriteAdditions(ssl, 1);
			oh += ssl->recordHeadLen;
			if (ssl->fragTotal > (uint32)ssl->maxPtFrag) {
				ssl->fragTotal -= ssl->maxPtFrag;
			} else {
				ssl->fragTotal = 0;
			}
		}
	}
	return oh;
}
#endif /* SERVER || CLIENT_AUTH */
#endif /* ! ONLY_PSK */

#ifdef USE_SERVER_SIDE_SSL
/* The ServerKeyExchange delayed PKA op */
static int32 nowDoSkePka(ssl_t *ssl)
{
	int32		rc = 0;
#ifndef USE_ONLY_PSK_CIPHER_SUITE
	pkaAfter_t	*pka;
#if defined(USE_ECC_CIPHER_SUITE) || defined(USE_RSA_CIPHER_SUITE)
	psPool_t	*pkiPool = NULL;
#endif /* USE_ECC_CIPHER_SUITE || USE_RSA_CIPHER_SUITE */
#ifdef USE_ECC_CIPHER_SUITE
	int32		err;
#endif
	
	pka = &ssl->pkaAfter;
	
#ifdef USE_RSA_CIPHER_SUITE
	if (pka->type == PKA_AFTER_RSA_SIG_GEN_ELEMENT ||
			pka->type == PKA_AFTER_RSA_SIG_GEN) {

#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			if ((rc = privRsaEncryptSignedElement(pkiPool, ssl->keys->privKey,
					pka->inbuf, pka->inlen, pka->outbuf,
					ssl->keys->privKey->keysize, pka->data)) !=
					(int32)ssl->keys->privKey->keysize) {
				if (rc != PS_PENDING) {
					psTraceIntInfo("Unable to sign SKE digital element %d\n",
						rc);
					return MATRIXSSL_ERROR;
				}
				ssl->flags |= SSL_FLAGS_PENDING_PKA_W;
				/* If the result is going directly inline to the output
					buffer we unflag 'type' so this function isn't called
					again on the way back around */ 
				pka->type = 0; 
				return PS_PENDING;
			}
		} else {
			if ((rc = csRsaEncryptPriv(pkiPool, ssl->keys->privKey, pka->inbuf,
					pka->inlen, pka->outbuf, ssl->keys->privKey->keysize,
					pka->data)) != (int32)ssl->keys->privKey->keysize) {
				if (rc != PS_PENDING) {
					psTraceInfo("Unable to sign SERVER_KEY_EXCHANGE message\n");
					return MATRIXSSL_ERROR;
				}
				ssl->flags |= SSL_FLAGS_PENDING_PKA_W;
				/* If the result is going directly inline to the output
					buffer we unflag 'type' so this function isn't called
					again on the way back around */ 
				pka->type = 0; 
				return PS_PENDING;
			}
		}
#else /* !USE_TLS_1_2 */
		if ((rc = csRsaEncryptPriv(pkiPool, ssl->keys->privKey, pka->inbuf,
				pka->inlen, pka->outbuf, ssl->keys->privKey->keysize,
				pka->data)) != (int32)ssl->keys->privKey->keysize) {
			if (rc != PS_PENDING) {
				psTraceInfo("Unable to sign SERVER_KEY_EXCHANGE message\n");
				return MATRIXSSL_ERROR;
			}
			ssl->flags |= SSL_FLAGS_PENDING_PKA_W;
			/* If the result is going directly inline to the output
				buffer we unflag 'type' so this function isn't called
				again on the way back around */ 
			pka->type = 0; 
			return PS_PENDING;
		}
#endif /* USE_TLS_1_2 */
	
		clearPkaAfter(ssl);
	}
#endif /* USE_RSA_CIPHER_SUITE */
	
#ifdef USE_ECC_CIPHER_SUITE
	if (pka->type == PKA_AFTER_ECDSA_SIG_GEN) {

		/* TODO: save real size to replace bogus 1024? */
		if ((err = psEccSignHash(pkiPool, pka->inbuf, pka->inlen, pka->outbuf,
				1024, &ssl->keys->privKey->key->ecc, &rc, 1,
				pka->data)) != 0) {
			if (err != PS_PENDING) {
				return MATRIXSSL_ERROR;
			}	
			ssl->flags |= SSL_FLAGS_PENDING_PKA_W;
			return PS_PENDING;
		}
		clearPkaAfter(ssl);
	}
#endif /* USE_ECC_CIPHER_SUITE */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */
	return rc;
}
#endif /* USE_SERVER_SIDE_SSL */

/******************************************************************************/
/*
	We indicate to the caller through return codes in sslDecode when we need
	to write internal data to the remote host.  The caller will call this 
	function to generate a message appropriate to our state.
*/
int32 sslEncodeResponse(ssl_t *ssl, psBuf_t *out, uint32 *requiredLen)
{
	int32			messageSize;
	int32			rc = MATRIXSSL_ERROR;
	uint32			alertReqLen;
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	int32			i;
#ifndef USE_ONLY_PSK_CIPHER_SUITE
	psX509Cert_t	*cert;
#endif /* USE_ONLY_PSK_CIPHER_SUITE */
#endif /* USE_SERVER_SIDE_SSL */

#if defined(USE_SERVER_SIDE_SSL)
	int32			extSize;
	int32			stotalCertLen;
#endif

#ifdef USE_CLIENT_SIDE_SSL
	int32			ckeSize;
#ifdef USE_CLIENT_AUTH
	int32			ctotalCertLen;
#endif
#endif /* USE_CLIENT_SIDE_SSL */

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
	psX509Cert_t	*CAcert;
	int32			certCount, certReqLen, CAcertLen;
#endif /* USE_SERVER_SIDE_SSL && USE_CLIENT_AUTH */
#endif /* USE_ONLY_PSK_CIPHER_SUITE */
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_DHE_CIPHER_SUITE)
	int32			srvKeyExLen;
#endif /* USE_SERVER_SIDE_SSL && USE_DHE_CIPHER_SUITE */

/*
	We may be trying to encode an alert response if there is an error marked
	on the connection.
*/
	if (ssl->err != SSL_ALERT_NONE) {
		rc = writeAlert(ssl, SSL_ALERT_LEVEL_FATAL, (unsigned char)ssl->err,
			out, requiredLen);
		if (rc == MATRIXSSL_ERROR) {
			/* We'll be returning an error code from this call so the typical
				alert SEND_RESPONSE handler will not be hit to set this error
				flag for us.  We do it ourself to prevent further session use
				and the result of this error will be that the connection is
				silently closed rather than this alert making it out */
			ssl->flags |= SSL_FLAGS_ERROR;
		}
#ifdef USE_SERVER_SIDE_SSL
/*
		Writing a fatal alert on this session.  Let's remove this client from
		the session table as a precaution.  Additionally, if this alert is
		happening mid-handshake the master secret might not even be valid
*/
		if (ssl->flags & SSL_FLAGS_SERVER) {
			matrixClearSession(ssl, 1);
		}
#endif /* USE_SERVER_SIDE_SSL */
		return rc;
	}



	
/*
	We encode a set of response messages based on our current state
	We have to pre-verify the size of the outgoing buffer against
	all the messages to make the routine transactional.  If the first
	write succeeds and the second fails because of size, we cannot
	rollback the state of the cipher and MAC.
*/
	switch (ssl->hsState) {
/*
	If we're waiting for the ClientKeyExchange message, then we need to
	send the messages that would prompt that result on the client
*/
#ifdef USE_SERVER_SIDE_SSL
	case SSL_HS_CLIENT_KEY_EXCHANGE:
#ifdef USE_CLIENT_AUTH
/*
		This message is also suitable for the client authentication case
		where the server is in the CERTIFICATE state.
*/
	case SSL_HS_CERTIFICATE:
/*
		Account for the certificateRequest message if client auth is on.
		First two bytes are the certificate_types member (rsa_sign (1) and
		ecdsa_sign (64) are supported).  Remainder of length is the
		list of BER encoded distinguished names this server is
		willing to accept children certificates of.  If there
		are no valid CAs to work with, client auth can't be done.
*/
#ifndef USE_ONLY_PSK_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
			CAcert = ssl->keys->CAcerts;
			certCount = certReqLen = CAcertLen = 0;
#ifdef USE_TLS_1_2
			if (ssl->flags & SSL_FLAGS_TLS_1_2) {
				/* TLS 1.2 has a SigAndHashAlgorithm member in certRequest */
				certReqLen += 2;
#ifdef USE_ECC
#ifdef USE_SHA384			
				certReqLen += 6;
#else
				certReqLen += 4;
#endif	/* USE_SHA */
#endif /* USE_ECC */
#ifdef USE_RSA
#ifdef USE_SHA384			
				certReqLen += 6;
#else
				certReqLen += 4;
#endif	/* USE_SHA */
#endif /* USE_RSA */
			}
#endif /* USE_TLS_1_2 */
			
			if (CAcert) {
				certReqLen += 4 + ssl->recordHeadLen + ssl->hshakeHeadLen;
#ifdef USE_ECC
				certReqLen += 1; /* Add on ECDSA_SIGN support */
#endif /* USE_ECC */				
				while (CAcert) {
					certReqLen += 2; /* 2 bytes for specifying each cert len */
					CAcertLen += CAcert->subject.dnencLen;
					CAcert = CAcert->next;
					certCount++;
				}
			} else {
#ifdef SERVER_CAN_SEND_EMPTY_CERT_REQUEST			
				certReqLen += 4 + ssl->recordHeadLen + ssl->hshakeHeadLen;
#ifdef USE_ECC
				certReqLen += 1; /* Add on ECDSA_SIGN support */
#endif /* USE_ECC */				
#else				
				psTraceInfo("No server CAs loaded for client authentication\n");
				return MATRIXSSL_ERROR;
#endif				
			}
		}
#endif /* USE_ONLY_PSK_CIPHER_SUITE */
#endif /* USE_CLIENT_AUTH */

#ifdef USE_DHE_CIPHER_SUITE
		srvKeyExLen = 0;
		if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
#ifdef USE_ECC_CIPHER_SUITE
			if (!(ssl->flags & SSL_FLAGS_ECC_CIPHER)) {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef REQUIRE_DH_PARAMS
/*
			Extract p and g parameters from key to session context.  Going
			to send these in the SERVER_KEY_EXCHANGE message.  This is
			wrapped in a test of whether or not the values have already
			been extracted because an SSL_FULL scenario below will cause
			this code to be executed again with a larger buffer.
*/
			if (ssl->sec.dhPLen == 0 && ssl->sec.dhP == NULL) {
				if (psDhExportParameters(ssl->hsPool, ssl->keys->dhParams,
						&ssl->sec.dhPLen, (unsigned char**)&ssl->sec.dhP,
						&ssl->sec.dhGLen, (unsigned char**)&ssl->sec.dhG) < 0) {
					return MATRIXSSL_ERROR;
				}
			}
#endif			
#ifdef USE_ECC_CIPHER_SUITE
			}
#endif /* USE_ECC_CIPHER_SUITE */			
#ifdef USE_ANON_DH_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_ANON_CIPHER) {
/*
				If we are an anonymous cipher, we don't send the certificate.
				The messages are simply SERVER_HELLO, SERVER_KEY_EXCHANGE,
				and SERVER_HELLO_DONE
*/
				stotalCertLen = 0;

				srvKeyExLen = ssl->sec.dhPLen + 2 + ssl->sec.dhGLen + 2 +
					ssl->sec.dhKeyPriv.size + 2;

#ifdef USE_PSK_CIPHER_SUITE
				if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
/*
 *					struct {
 *						select (KeyExchangeAlgorithm) {
 *							case diffie_hellman_psk:  * NEW *
 *							opaque psk_identity_hint<0..2^16-1>;
 *							ServerDHParams params;
 *						};
 *					} ServerKeyExchange;
 */
 					if (SSL_PSK_MAX_HINT_SIZE > 0) {
						srvKeyExLen += SSL_PSK_MAX_HINT_SIZE + 2;
 					}
				}
#endif /* USE_PSK_CIPHER_SUITE */

				messageSize =
					3 * ssl->recordHeadLen +
					3 * ssl->hshakeHeadLen +
					38 + SSL_MAX_SESSION_ID_SIZE +  /* server hello */
					srvKeyExLen; /* server key exchange */

				messageSize += secureWriteAdditions(ssl, 3);
			} else {
#endif /* USE_ANON_DH_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE
				if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
					if (ssl->flags & SSL_FLAGS_DHE_WITH_RSA) {
/*
						 Magic 7: 1byte ECCurveType named, 2bytes NamedCurve id
						 1 byte pub key len, 2 byte privkeysize len,
						 1 byte 0x04 inside the eccKey itself
*/					
						srvKeyExLen = (ssl->sec.eccKeyPriv->dp->size * 2) + 7 +
							ssl->keys->privKey->keysize;
					} else if (ssl->flags & SSL_FLAGS_DHE_WITH_DSA) {
						/* ExportKey plus signature */
						srvKeyExLen = (ssl->sec.eccKeyPriv->dp->size * 2) + 7 +
							6 + /* 6 = 2 ASN_SEQ, 4 ASN_BIG */
							ssl->keys->privKey->keysize;
						if (ssl->keys->privKey->keysize >= 128) {
							srvKeyExLen += 1; /* Extra len byte in ASN.1 sig */
						}
					}
#ifdef USE_TLS_1_2
					if (ssl->flags & SSL_FLAGS_TLS_1_2) {
						srvKeyExLen += 2; /* hashSigAlg */
					}
#endif /* USE_TLS_1_2 */							
				} else {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef REQUIRE_DH_PARAMS
/*
				The AUTH versions of the DHE cipher suites include a
				signature value in the SERVER_KEY_EXCHANGE message.
				Account for that length here.  Also, the CERTIFICATE
				message is sent in this flight as well for normal
				authentication.
*/
				srvKeyExLen = ssl->sec.dhPLen + 2 + ssl->sec.dhGLen + 2 +
					ssl->sec.dhKeyPriv.size + 2 +
					ssl->keys->privKey->keysize + 2;
#ifdef USE_TLS_1_2
				if (ssl->flags & SSL_FLAGS_TLS_1_2) {
					srvKeyExLen += 2; /* hashSigAlg */
				}
#endif /* USE_TLS_1_2 */
				
#endif /* REQUIRE_DH_PARAMS */					
#ifdef USE_ECC_CIPHER_SUITE
				}
#endif /* USE_ECC_CIPHER_SUITE */	
				stotalCertLen = i = 0;
#ifndef USE_ONLY_PSK_CIPHER_SUITE				
				cert = ssl->keys->cert;
				for (i = 0; cert != NULL; i++) {
					stotalCertLen += cert->binLen;
					cert = cert->next;
				}
				/* Are we going to have to fragment the CERTIFICATE message? */
				if ((stotalCertLen + 3 + (i * 3) + ssl->hshakeHeadLen) >
						ssl->maxPtFrag) {
					stotalCertLen += addCertFragOverhead(ssl,
						stotalCertLen + 3 + (i * 3) + ssl->hshakeHeadLen);
				}
#endif /* USE_ONLY_PSK_CIPHER_SUITE  */
				messageSize =
					4 * ssl->recordHeadLen +
					4 * ssl->hshakeHeadLen +
					38 + SSL_MAX_SESSION_ID_SIZE +  /* server hello */
					srvKeyExLen + /* server key exchange */
					3 + (i * 3) + stotalCertLen; /* certificate */
#ifdef USE_CLIENT_AUTH
#ifndef USE_ONLY_PSK_CIPHER_SUITE	
				if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
					/* Are we going to have to fragment the
						CERTIFICATE_REQUEST message? */
					if (certReqLen + CAcertLen > ssl->maxPtFrag) {
						certReqLen += addCertFragOverhead(ssl,
							certReqLen + CAcertLen);
					}
					/* Account for the CertificateRequest message */
					messageSize += certReqLen + CAcertLen;
					messageSize += secureWriteAdditions(ssl, 1);
				}
#endif /* USE_ONLY_PSK_CIPHER_SUITE */
#endif /* USE_CLIENT_AUTH */
				messageSize += secureWriteAdditions(ssl, 4);
#ifdef USE_ANON_DH_CIPHER_SUITE
			}
#endif /* USE_ANON_DH_CIPHER_SUITE */
		} else {
#endif /* USE_DHE_CIPHER_SUITE */
/*
			This is the entry point for a server encoding the first flight
			of a non-DH, non-client-auth handshake.
*/
			messageSize = stotalCertLen = 0;
#ifdef USE_PSK_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
/*
				Omit the CERTIFICATE message but (possibly) including the
				SERVER_KEY_EXCHANGE. 
*/
				messageSize =
					2 * ssl->recordHeadLen +
					2 * ssl->hshakeHeadLen +
					38 + SSL_MAX_SESSION_ID_SIZE;  /* server hello */
				if (SSL_PSK_MAX_HINT_SIZE > 0) {
					messageSize += 2 + SSL_PSK_MAX_HINT_SIZE +  /* SKE */
						ssl->recordHeadLen + ssl->hshakeHeadLen;
				} else {
/*
					Assuming 3 messages below when only two are going to exist 
*/
					messageSize -= secureWriteAdditions(ssl, 1);
				}
			} else {
#endif
#ifndef USE_ONLY_PSK_CIPHER_SUITE
				cert = ssl->keys->cert;
				for (i = 0; cert != NULL; i++) {
					psAssert(cert->unparsedBin != NULL);
					stotalCertLen += cert->binLen;
					cert = cert->next;
				}
				/* Are we going to have to fragment the CERTIFICATE message? */
				if ((stotalCertLen + 3 + (i * 3) + ssl->hshakeHeadLen) >
						ssl->maxPtFrag) {
					stotalCertLen += addCertFragOverhead(ssl,
						stotalCertLen + 3 + (i * 3) + ssl->hshakeHeadLen);
				}
				messageSize =
					3 * ssl->recordHeadLen +
					3 * ssl->hshakeHeadLen +
					38 + SSL_MAX_SESSION_ID_SIZE +  /* server hello */
					3 + (i * 3) + stotalCertLen; /* certificate */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */					
#ifdef USE_PSK_CIPHER_SUITE
			}
#endif /* USE_PSK_CIPHER_SUITE */

#ifdef USE_CLIENT_AUTH
#ifndef USE_ONLY_PSK_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
				/* Are we going to have to fragment the	CERTIFICATE_REQUEST
					message? This is the SSL fragment level */
				if (certReqLen + CAcertLen > ssl->maxPtFrag) {
					certReqLen += addCertFragOverhead(ssl,
						certReqLen + CAcertLen);
				}
				messageSize += certReqLen + CAcertLen; /* certificate request */
				messageSize += secureWriteAdditions(ssl, 1);
			}
#endif /* USE_ONLY_PSK_CIPHER_SUITE */			
#endif /* USE_CLIENT_AUTH */

			messageSize += secureWriteAdditions(ssl, 3);

#ifdef USE_DHE_CIPHER_SUITE
		}
#endif /* USE_DHE_CIPHER_SUITE */
		

/*
		Add extensions
*/
		extSize = 0; /* Two byte total length for all extensions */
		if (ssl->maxPtFrag < SSL_MAX_PLAINTEXT_LEN) {
			extSize = 2;
			messageSize += 5; /* 2 type, 2 length, 1 value */
		}
#ifdef USE_TRUNCATED_HMAC
		if (ssl->truncHmac) {
			extSize = 2;
			messageSize += 4; /* 2 type, 2 length, 0 value */
		}
#endif

#ifdef USE_STATELESS_SESSION_TICKETS
		if (ssl->sid &&
				ssl->sid->sessionTicketFlag == SESS_TICKET_FLAG_RECVD_EXT) {
			extSize = 2;
			messageSize += 4; /* 2 type, 2 length, 0 value */
		}
#endif
		if (ssl->sniUsed) {
			extSize = 2;
			messageSize += 4;
		}

#ifdef ENABLE_SECURE_REHANDSHAKES		
/*
		The RenegotiationInfo extension lengths are well known
*/	
		if (ssl->secureRenegotiationFlag == PS_TRUE &&
				ssl->myVerifyDataLen == 0) {
			extSize = 2;
			messageSize += 5; /* ff 01 00 01 00 */
		} else if (ssl->secureRenegotiationFlag == PS_TRUE &&
				ssl->myVerifyDataLen > 0) {
			extSize = 2;
			messageSize += 5 + ssl->myVerifyDataLen +
				ssl->peerVerifyDataLen; /* 2 for total len, 5 for type+len */
		}
#endif /* ENABLE_SECURE_REHANDSHAKES */

#ifdef USE_ECC_CIPHER_SUITE
/*
	Server Hello ECC extension
*/
		if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
			extSize = 2;
			/* ELLIPTIC_POINTS_EXT - hardcoded to 'uncompressed' support */
			messageSize += 6; /* 00 0B 00 02 01 00 */ 
		}
#endif /* USE_ECC_CIPHER_SUITE */
/*
		Done with extensions.  If had some, add the two byte total length
*/
		messageSize += extSize;

		if ((out->buf + out->size) - out->end < messageSize) {
			*requiredLen = messageSize;
			return SSL_FULL;
		}
/*
		Message size complete.  Begin the flight write
*/
		rc = writeServerHello(ssl, out);

#ifdef USE_DHE_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
#ifndef USE_ONLY_PSK_CIPHER_SUITE		
			if (ssl->flags & SSL_FLAGS_DHE_WITH_RSA ||
					ssl->flags & SSL_FLAGS_DHE_WITH_DSA) {
				if (rc == MATRIXSSL_SUCCESS) {				
					rc = writeCertificate(ssl, out, 1);
				}
			}
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */			
			if (rc == MATRIXSSL_SUCCESS) {
#ifdef USE_ECC_CIPHER_SUITE
				if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
					rc = writeServerKeyExchange(ssl, out, 0, NULL, 0, NULL);
				} else {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef REQUIRE_DH_PARAMS
				rc = writeServerKeyExchange(ssl, out, ssl->sec.dhPLen,
					ssl->sec.dhP, ssl->sec.dhGLen, ssl->sec.dhG);
#endif /* REQUIRE_DH_PARAMS */
#ifdef USE_ECC_CIPHER_SUITE
				}
#endif /* USE_ECC_CIPHER_SUITE */					
			}
		} else {
#endif /* USE_DHE_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
				if (rc == MATRIXSSL_SUCCESS) {
					rc = writePskServerKeyExchange(ssl, out);
				}
			} else {
#endif /* USE_PSK_CIPHER_SUITE */
#ifndef USE_ONLY_PSK_CIPHER_SUITE
				if (rc == MATRIXSSL_SUCCESS) {
					rc = writeCertificate(ssl, out, 1);
				}
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */				
#ifdef USE_PSK_CIPHER_SUITE
			}
#endif /* USE_PSK_CIPHER_SUITE */
#ifdef USE_DHE_CIPHER_SUITE
		}
#endif /* USE_DHE_CIPHER_SUITE */

#ifndef USE_ONLY_PSK_CIPHER_SUITE	
#ifdef USE_CLIENT_AUTH
		if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
			if (rc == MATRIXSSL_SUCCESS) {	
				rc = writeCertificateRequest(ssl, out, CAcertLen, certCount);
			}
		}
#endif /* USE_CLIENT_AUTH */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

		if (rc == MATRIXSSL_SUCCESS) {
			rc = writeServerHelloDone(ssl, out);
		}
		if (rc == SSL_FULL) {
			psTraceInfo("Bad flight messageSize calculation");
			ssl->err = SSL_ALERT_INTERNAL_ERROR;
			out->end = out->start;
			alertReqLen = out->size;
			/* Going recursive */
			return sslEncodeResponse(ssl, out, &alertReqLen);
		}
		break;

#endif /* USE_SERVER_SIDE_SSL */

/*
	If we're not waiting for any message from client, then we need to
	send our finished message
*/
	case SSL_HS_DONE:
		messageSize = 2 * ssl->recordHeadLen +
			ssl->hshakeHeadLen +
			1 + /* change cipher spec */
			MD5_HASH_SIZE + SHA1_HASH_SIZE; /* finished */
/*
		Account for possible overhead in CCS message with secureWriteAdditions
		then always account for the encryption overhead on FINISHED message.
		Correct to use ssl->cipher values for mac and block since those will
		be the ones used when encrypting FINISHED 
*/
		messageSize += secureWriteAdditions(ssl, 1);
		messageSize += ssl->cipher->macSize + ssl->cipher->blockSize;
		
#if defined(USE_STATELESS_SESSION_TICKETS) && defined(USE_SERVER_SIDE_SSL)
		if (ssl->flags & SSL_FLAGS_SERVER) {
			if (ssl->sid &&
				  (ssl->sid->sessionTicketFlag == SESS_TICKET_FLAG_RECVD_EXT)) {
				messageSize += ssl->recordHeadLen +
					ssl->hshakeHeadLen + matrixSessionTicketLen() + 6;
			}
		}
#endif
		
#ifdef USE_TLS
/*
		Account for the smaller finished message size for TLS.
*/
		if (ssl->flags & SSL_FLAGS_TLS) {
			messageSize += TLS_HS_FINISHED_SIZE -
				(MD5_HASH_SIZE + SHA1_HASH_SIZE);
		}
#endif /* USE_TLS */			
#ifdef USE_TLS_1_1
/*
		Adds explict IV overhead to the FINISHED message
*/
		if (ssl->flags & SSL_FLAGS_TLS_1_1) {
#ifdef USE_AES_GCM			
			if (ssl->flags & SSL_FLAGS_GMAC_W) {
				/* The magic 1 back into messageSize is because the
					macSize + blockSize above ends up subtracting one on GCM */
				messageSize += TLS_GCM_TAG_LEN + ssl->nonceCtrLen + 1;
			} else {
#endif				
				messageSize += ssl->cipher->blockSize;
#ifdef USE_AES_GCM			
			}
#endif				
		}
#endif /* USE_TLS_1_1 */

#ifdef USE_ZLIB_COMPRESSION
		/* Lastly, add the zlib overhead for the FINISHED message */
		if (ssl->compression) {
			messageSize += MAX_ZLIB_COMPRESSED_OH;
		}
#endif
		if ((out->buf + out->size) - out->end < messageSize) {
			*requiredLen = messageSize;
			return SSL_FULL;
		}
		rc = MATRIXSSL_SUCCESS;
		
#if defined(USE_STATELESS_SESSION_TICKETS) && defined(USE_SERVER_SIDE_SSL)
		if (ssl->flags & SSL_FLAGS_SERVER) {
			if (ssl->sid &&
				  (ssl->sid->sessionTicketFlag == SESS_TICKET_FLAG_RECVD_EXT)) {
				rc = writeNewSessionTicket(ssl, out);
			}
		}
#endif
		if (rc == MATRIXSSL_SUCCESS) {
			rc = writeChangeCipherSpec(ssl, out);
		}
		if (rc == MATRIXSSL_SUCCESS) {
			rc = writeFinished(ssl, out);
		} 

		if (rc == SSL_FULL) {
			psTraceInfo("Bad flight messageSize calculation");
			ssl->err = SSL_ALERT_INTERNAL_ERROR;
			out->end = out->start;
			alertReqLen = out->size;
			/* Going recursive */
			return sslEncodeResponse(ssl, out, &alertReqLen);
		}
		break;
/*
	If we're expecting a Finished message, as a server we're doing 
	session resumption.  As a client, we're completing a normal
	handshake
*/
	case SSL_HS_FINISHED:
#ifdef USE_SERVER_SIDE_SSL
		if (ssl->flags & SSL_FLAGS_SERVER) {
			messageSize =
				3 * ssl->recordHeadLen +
				2 * ssl->hshakeHeadLen +
				38 + SSL_MAX_SESSION_ID_SIZE + /* server hello */
				1 + /* change cipher spec */
				MD5_HASH_SIZE + SHA1_HASH_SIZE; /* finished */
/*
			Account for possible overhead with secureWriteAdditions
			then always account for the encrypted FINISHED message.  Correct
			to use the ssl->cipher values for mac and block since those will
			always be the values used to encrypt the FINISHED message
*/				
			messageSize += secureWriteAdditions(ssl, 2);
			messageSize += ssl->cipher->macSize + ssl->cipher->blockSize;
#ifdef ENABLE_SECURE_REHANDSHAKES		
/*
			The RenegotiationInfo extension lengths are well known
*/	
			if (ssl->secureRenegotiationFlag == PS_TRUE &&
					ssl->myVerifyDataLen == 0) {
				messageSize += 7; /* 00 05 ff 01 00 01 00 */
			} else if (ssl->secureRenegotiationFlag == PS_TRUE &&
					ssl->myVerifyDataLen > 0) {
				messageSize += 2 + 5 + ssl->myVerifyDataLen +
					ssl->peerVerifyDataLen; /* 2 for tot len, 5 for type+len */
			}
#endif /* ENABLE_SECURE_REHANDSHAKES */

#ifdef USE_ECC_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {	
#ifndef ENABLE_SECURE_REHANDSHAKES
				messageSize += 2; /* ext 2 byte len has not been included */
#endif /* ENABLE_SECURE_REHANDSHAKES */
				/* ELLIPTIC_POINTS_EXT - hardcoded to 'uncompressed' support */
				messageSize += 6; /* 00 0B 00 02 01 00 */ 
			}
#endif /* USE_ECC_CIPHER_SUITE */

#ifdef USE_TLS
/*
			Account for the smaller finished message size for TLS.
			The MD5+SHA1 is SSLv3.  TLS is 12 bytes.
*/
			if (ssl->flags & SSL_FLAGS_TLS) {
				messageSize += TLS_HS_FINISHED_SIZE -
					(MD5_HASH_SIZE + SHA1_HASH_SIZE);
			}
#endif /* USE_TLS */		
#ifdef USE_TLS_1_1 
/*
			Adds explict IV overhead to the FINISHED message.  Always added
			because FINISHED is never accounted for in secureWriteAdditions
*/
			if (ssl->flags & SSL_FLAGS_TLS_1_1) {
#ifdef USE_AES_GCM					
				if (ssl->cipher->flags & CRYPTO_FLAGS_GCM) {
					/* The magic 1 back into messageSize is because the
						blockSize -1 above ends up subtracting one on GCM */
					messageSize += TLS_GCM_TAG_LEN + ssl->nonceCtrLen + 1;
				} else {
#endif					
					messageSize += ssl->cipher->blockSize; /* explicitIV */
#ifdef USE_AES_GCM					
				}
#endif					
			}
#endif /* USE_TLS_1_1 */

#ifdef USE_ZLIB_COMPRESSION
			/* Lastly, add the zlib overhead for the FINISHED message */
			if (ssl->compression) {
				messageSize += MAX_ZLIB_COMPRESSED_OH;
			}
#endif
			if ((out->buf + out->size) - out->end < messageSize) {
				*requiredLen = messageSize;
				return SSL_FULL;
			}
			rc = writeServerHello(ssl, out);
			if (rc == MATRIXSSL_SUCCESS) {
				rc = writeChangeCipherSpec(ssl, out);
			}
			if (rc == MATRIXSSL_SUCCESS) {
				rc = writeFinished(ssl, out);
			}
		}
#endif /* USE_SERVER_SIDE_SSL */
#ifdef USE_CLIENT_SIDE_SSL
/*
		Encode entry point for client side final flight encodes.
		First task here is to find out size of ClientKeyExchange message
*/
		if (!(ssl->flags & SSL_FLAGS_SERVER)) {
			ckeSize = 0;
#ifdef USE_DHE_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
#ifdef USE_ECC_CIPHER_SUITE
				if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
					ckeSize = (ssl->sec.eccKeyPriv->dp->size * 2) + 2;
				} else {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef REQUIRE_DH_PARAMS
				ckeSize = ssl->sec.dhKeyPriv.size;
#endif /* REQUIRE_DH_PARAMS */
#ifdef USE_ECC_CIPHER_SUITE
				}
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
/*
				This is the DHE_PSK suite case.
				PSK suites add the key identity with uint16 size
*/
				if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
					ckeSize += SSL_PSK_MAX_ID_SIZE + 2;
				}
#endif /* USE_PSK_CIPHER_SUITE */
			} else {
#endif /* USE_DHE_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
/*
				This is the basic PSK case
				PSK suites add the key identity with uint16 size
*/
				if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
					ckeSize += SSL_PSK_MAX_ID_SIZE + 2;
				} else {
#endif /* USE_PSK_CIPHER_SUITE */
#ifndef USE_ONLY_PSK_CIPHER_SUITE
#ifdef USE_ECC_CIPHER_SUITE
					if (ssl->cipher->type == CS_ECDH_ECDSA ||
							ssl->cipher->type == CS_ECDH_RSA) {
						ckeSize = (ssl->sec.cert->publicKey.key->ecc.dp->size *
							2) + 2;
					} else {
#endif /* USE_ECC_CIPHER_SUITE */					
/*
					Normal RSA auth cipher suite case
*/
					if (ssl->sec.cert == NULL) {
						ssl->flags |= SSL_FLAGS_ERROR;
						return MATRIXSSL_ERROR;
					}
					ckeSize = ssl->sec.cert->publicKey.keysize;
					
#ifdef USE_ECC_CIPHER_SUITE
					}
#endif /* USE_ECC_CIPHER_SUITE */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */					
#ifdef USE_PSK_CIPHER_SUITE
				}
#endif /* USE_PSK_CIPHER_SUITE */
#ifdef USE_DHE_CIPHER_SUITE
			}
#endif /* USE_DHE_CIPHER_SUITE */

			messageSize = 0;
			
			if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
/*
			Client authentication requires the client to send a CERTIFICATE
			and CERTIFICATE_VERIFY message.  Account for the length.  It
			is possible the client didn't have a match for the requested cert.
			Send an empty certificate message in that case (or alert for SSLv3)
*/
#ifndef USE_ONLY_PSK_CIPHER_SUITE
#ifdef USE_CLIENT_AUTH
				if (ssl->sec.certMatch > 0) {
/*
					Account for the certificate and certificateVerify messages
*/
					cert = ssl->keys->cert;
					ctotalCertLen = 0;
					for (i = 0; cert != NULL; i++) {
						ctotalCertLen += cert->binLen;
						cert = cert->next;
					}
					/* Are we going to have to fragment the CERT message? */
					if ((ctotalCertLen + 3 + (i * 3) + ssl->hshakeHeadLen) >
							ssl->maxPtFrag) {
						ctotalCertLen += addCertFragOverhead(ssl,
							ctotalCertLen + 3 + (i * 3) + ssl->hshakeHeadLen);
					}
					messageSize += (2 * ssl->recordHeadLen) + 3 + (i * 3) +
						(2 * ssl->hshakeHeadLen) + ctotalCertLen +
						2 +	ssl->keys->privKey->keysize;

#ifdef USE_ECC
					/* Overhead ASN.1 in psEccSignHash */
					if (ssl->keys->cert->pubKeyAlgorithm == OID_ECDSA_KEY_ALG) {
						messageSize += 6;
						if (ssl->keys->privKey->keysize >= 128) {
							messageSize += 1; /* Extra len byte in ASN.1 sig */
						}						
					}
#endif /* USE_ECC */
				} else {			
#endif /* USE_CLIENT_AUTH */				
/*
					SSLv3 sends a no_certificate warning alert for no match
*/
					if (ssl->majVer == SSL3_MAJ_VER
							&& ssl->minVer == SSL3_MIN_VER) {
						messageSize += 2 + ssl->recordHeadLen;
					} else {
/*
						TLS just sends an empty certificate message
*/
						messageSize += 3 + ssl->recordHeadLen +
							ssl->hshakeHeadLen;
					}
#ifdef USE_CLIENT_AUTH					
				}
#endif /* USE_CLIENT_AUTH */
#endif /* USE_ONLY_PSK_CIPHER_SUITE */
			}
/*
			Account for the header and message size for all records.  The
			finished message will always be encrypted, so account for one
			largest possible MAC size and block size.  The finished message is
			not accounted for in the writeSecureAddition calls below since it
			is accounted for here.
*/
			messageSize +=
				3 * ssl->recordHeadLen +
				2 * ssl->hshakeHeadLen + /* change cipher has no hsHead */
				ckeSize + /* client key exchange */
				1 + /* change cipher spec */
				MD5_HASH_SIZE + SHA1_HASH_SIZE + /* SSLv3 finished payload */
				ssl->cipher->macSize +
				ssl->cipher->blockSize; /* finished overhead */
#ifdef USE_TLS
/*
			Must add the 2 bytes key size length to the client key exchange
			message. Also, at this time we can account for the smaller finished
			message size for TLS.  The MD5+SHA1 is SSLv3.  TLS is 12 bytes.
*/
			if (ssl->flags & SSL_FLAGS_TLS) {
				messageSize += 2 - MD5_HASH_SIZE - SHA1_HASH_SIZE +
					TLS_HS_FINISHED_SIZE;
			}
#endif /* USE_TLS */
			if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
/*
				Secure write for ClientKeyExchange, ChangeCipherSpec,
				Certificate, and CertificateVerify.  Don't account for
				Certificate and/or CertificateVerify message if no auth cert.
				This will also cover the NO_CERTIFICATE alert sent in
				replacement of the NULL certificate message in SSLv3.
*/
				if (ssl->sec.certMatch > 0) {
#ifdef USE_TLS_1_2
					if (ssl->flags & SSL_FLAGS_TLS_1_2) {
						messageSize += 2; /* hashSigAlg in CertificateVerify */
					}
#endif				
					messageSize += secureWriteAdditions(ssl, 4);
				} else {
					messageSize += secureWriteAdditions(ssl, 3);
				}
			} else {
				messageSize += secureWriteAdditions(ssl, 2);
			}
			
#ifdef USE_TLS_1_1 
/*
			Adds explict IV overhead to the FINISHED message.  Always added
			because FINISHED is never accounted for in secureWriteAdditions
*/
			if (ssl->flags & SSL_FLAGS_TLS_1_1) {
#ifdef USE_AES_GCM				
				if (ssl->cipher->flags & CRYPTO_FLAGS_GCM) {
					/* The magic 1 back into messageSize is because the
					 blockSize -1 above ends up subtracting one on GCM */
					messageSize += TLS_GCM_TAG_LEN + ssl->nonceCtrLen + 1;
				} else {
#endif					
					messageSize += ssl->cipher->blockSize; /* explicitIV */
#ifdef USE_AES_GCM				
				}
#endif					
			}
#endif /* USE_TLS_1_1 */
#ifdef USE_ZLIB_COMPRESSION
			/* Lastly, add the zlib overhead for the FINISHED message */
			if (ssl->compression) {
				messageSize += MAX_ZLIB_COMPRESSED_OH;
			}
#endif
/*
			The actual buffer size test to hold this flight
*/
			if ((out->buf + out->size) - out->end < messageSize) {
				*requiredLen = messageSize;
				return SSL_FULL;
			}
			rc = MATRIXSSL_SUCCESS;
			
#ifndef USE_ONLY_PSK_CIPHER_SUITE
			if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
/*
				The TLS RFC is fairly clear that an empty certificate message
				be sent if there is no certificate match.  SSLv3 tends to lean
				toward a NO_CERTIFIATE warning alert message 	
*/
				if (ssl->sec.certMatch == 0 && ssl->majVer == SSL3_MAJ_VER
							&& ssl->minVer == SSL3_MIN_VER) {
					rc = writeAlert(ssl, SSL_ALERT_LEVEL_WARNING,
						SSL_ALERT_NO_CERTIFICATE, out, requiredLen);
				} else {
					rc = writeCertificate(ssl, out, ssl->sec.certMatch);
				}
			}
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

			if (rc == MATRIXSSL_SUCCESS) {
				rc = writeClientKeyExchange(ssl, out);
			}
#ifndef USE_ONLY_PSK_CIPHER_SUITE			
#ifdef USE_CLIENT_AUTH
			if (ssl->flags & SSL_FLAGS_CLIENT_AUTH) {
				if (rc == MATRIXSSL_SUCCESS && ssl->sec.certMatch > 0) {
					rc = writeCertificateVerify(ssl, out);
				}
			}
#endif /* USE_CLIENT_AUTH */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

			if (rc == MATRIXSSL_SUCCESS) {
				rc = writeChangeCipherSpec(ssl, out);
			}
			if (rc == MATRIXSSL_SUCCESS) {
				rc = writeFinished(ssl, out);
			}
		}
#endif /* USE_CLIENT_SIDE_SSL */
		if (rc == SSL_FULL) {
			psTraceInfo("Bad flight messageSize calculation");
			ssl->err = SSL_ALERT_INTERNAL_ERROR;
			out->end = out->start;
			alertReqLen = out->size;
			/* Going recursive */
			return sslEncodeResponse(ssl, out, &alertReqLen);
		}
		break;
	}

	if (rc < MATRIXSSL_SUCCESS && rc != SSL_FULL) {
	/* Indication one of the message creations failed and setting the flag to
		prevent other API calls from working.  We want to send a fatal
		internal error alert in this case.  Make sure to write to front of
		buffer since we	can't trust the data in there due to the creation
		failure. */
		psTraceIntInfo("ERROR: Handshake flight creation failed %d", rc);
		ssl->err = SSL_ALERT_INTERNAL_ERROR;
		out->end = out->start;
		alertReqLen = out->size;
		/* Going recursive */
		return sslEncodeResponse(ssl, out, &alertReqLen);
	}


#ifdef USE_SERVER_SIDE_SSL
	/* Post-flight write PKA operation.  Current support is for the signature
		generation during ServerKeyExchange write.  */
	if (ssl->flags & SSL_FLAGS_SERVER) {
		if (ssl->pkaAfter.type > 0) {
			if ((rc = nowDoSkePka(ssl)) < 0) {
				return rc;
			}
		}
	}
#endif

	/* Encrypt Flight */
	if (ssl->flightEncode) {
		if ((rc = encryptFlight(ssl, &out->end)) < 0) {
			return rc;
		}
	}
	
	return rc;
}

void clearFlightList(ssl_t *ssl)
{
	flightEncode_t *msg, *next;
	
	next = msg = ssl->flightEncode;
	while (msg) {
		next = msg->next;
		psFree(msg);
		msg = next;
	}
	ssl->flightEncode = NULL;
}

static int32 encryptFlight(ssl_t *ssl, unsigned char **end)
{
	flightEncode_t *msg, *remove;
	sslBuf_t		out;
	unsigned char	*c;
	int32			rc;
#ifdef USE_UNIFIED_PKCS11
	CK_SESSION_INFO sesInfo;
#endif

	msg = ssl->flightEncode;
	while (msg) {
		c = msg->start + msg->len;
		if (msg->hsMsg == SSL_HS_FINISHED) {
			/* If it was just a ChangeCipherSpec message that was encoded we can
				activate the write cipher */
			sslActivateWriteCipher(ssl);	

			/* The finished message had to hold off snapshoting the handshake
				hash because those updates are done in the encryptRecord call
				below for each message.  THAT was done because of a possible
				delay in a PKA op */
			rc = sslSnapshotHSHash(ssl, ssl->delayHsHash,
				ssl->flags & SSL_FLAGS_SERVER);
#ifdef USE_UNIFIED_PKCS11
			if (ssl->flags & SSL_FLAGS_SERVER) {
				if (C_GetSessionInfo(ssl->sec.pkcs11Ses, &sesInfo) == CKR_OK) {
					if (ssl->sec.masterSecret != CK_INVALID_HANDLE) {
#ifdef PKCS11_STATS
						psTraceInfo("Freeing master after FINISHED write\n");
#endif
						if (pkcs11DestroyObject(ssl->sec.pkcs11Ses,
								ssl->sec.masterSecret) != CKR_OK) {
							psTraceInfo("Error destroying master obj\n");
						}
						ssl->sec.masterSecret = CK_INVALID_HANDLE;
					}
				}
			}
#endif /* UNIFIED_PKCS11 */
			if (rc < 0) {
				psTraceIntInfo("Error snapshotting HS hash flight %d\n", rc);
				clearFlightList(ssl);
				return rc;
			}
					
#ifdef ENABLE_SECURE_REHANDSHAKES
			/* The rehandshake verify data is the previous handshake msg hash */
			memcpy(ssl->myVerifyData, ssl->delayHsHash, rc);
			ssl->myVerifyDataLen = rc;
#endif /* ENABLE_SECURE_REHANDSHAKES */
		}

#if defined(USE_TLS_1_2) && defined(USE_AES_GCM)
		if (ssl->flags & SSL_FLAGS_GMAC_W) {
			out.start = out.buf = out.end = msg->start - ssl->recordHeadLen -
				ssl->nonceCtrLen;
			/* TODO: what about app data records?  delayed seq needed? */
			*msg->seqDelay = ssl->sec.seq[0]; msg->seqDelay++;
			*msg->seqDelay = ssl->sec.seq[1]; msg->seqDelay++;
			*msg->seqDelay = ssl->sec.seq[2]; msg->seqDelay++;
			*msg->seqDelay = ssl->sec.seq[3]; msg->seqDelay++;
			*msg->seqDelay = ssl->sec.seq[4]; msg->seqDelay++;
			*msg->seqDelay = ssl->sec.seq[5]; msg->seqDelay++;
			*msg->seqDelay = ssl->sec.seq[6]; msg->seqDelay++;
			*msg->seqDelay = ssl->sec.seq[7];
		} else {
			out.start = out.buf = out.end = msg->start - ssl->recordHeadLen;
		}
#else
		out.start = out.buf = out.end = msg->start - ssl->recordHeadLen;
#endif /* GCM */
		
#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_CLIENT_SIDE_SSL) && defined(USE_CLIENT_AUTH)		
		if (msg->hsMsg == SSL_HS_CERTIFICATE_VERIFY) {
			/* This delayed PKA op has to be done mid flight encode because
				the contents of the signature is the hash of the handshake
				messages.  This can theoretically return PENDING too */
			nowDoCvPka(ssl);
		}
#endif
#endif
		rc = encryptRecord(ssl, msg->type, msg->messageSize, msg->padLen,
			msg->start, &out, &c);
		*end = c;
		if (rc == PS_PENDING) {
			/* Eat this message from flight encode, moving next to the front */
			/* Save how far along we are to be picked up next time */
			*end = msg->start + msg->messageSize - ssl->recordHeadLen;
#if defined(USE_TLS_1_2) && defined(USE_AES_GCM)
			if (ssl->flags & SSL_FLAGS_GMAC_W) {
				*end -= ssl->nonceCtrLen;
			}
#endif
			ssl->flightEncode = msg->next;
			psFree(msg);
			return rc;
		}
		if (rc < 0) {
			psTraceIntInfo("Error encrypting record from flight %d\n", rc);
			clearFlightList(ssl);
			return rc;
		}
		remove = msg;
		ssl->flightEncode = msg = msg->next;
		psFree(remove);	
	}
	clearFlightList(ssl);
	return PS_SUCCESS;
}

void clearPkaAfter(ssl_t *ssl)
{
	ssl->pkaAfter.type = 0;
	if (ssl->pkaAfter.inbuf) {
		psFree(ssl->pkaAfter.inbuf);
		ssl->pkaAfter.inbuf = NULL;
	}
	ssl->pkaAfter.outbuf = NULL;
	ssl->pkaAfter.data = NULL;
	ssl->pkaAfter.inlen = 0;
}

/******************************************************************************/
/*
	Message size must account for any additional length a secure-write
	would add to the message.  It would be too late to check length in
	the writeRecordHeader call since some of the handshake hashing could
	have already taken place and we can't rewind those hashes.
*/
static int32 secureWriteAdditions(ssl_t *ssl, int32 numRecs)
{
	int32 add = 0;
/*
	There is a slim chance for a false FULL message due to the fact that
	the maximum padding is being calculated rather than the actual number.
	Caller must simply grow buffer and try again.  Not subtracting 1 for
	the padding overhead to support NULL ciphers that will have 0 enBlockSize
*/
	if (ssl->flags & SSL_FLAGS_WRITE_SECURE) {
		add += (numRecs * ssl->enMacSize) + /* handshake msg hash */
			(numRecs * (ssl->enBlockSize)); /* padding */
#ifdef USE_TLS_1_1
/*
		 Checks here for TLS1.1 with block cipher for explict IV additions.
 */
		if ((ssl->flags & SSL_FLAGS_TLS_1_1) &&	(ssl->enBlockSize > 1)) {
			add += (numRecs * ssl->enBlockSize); /* explicitIV */
		}
#endif /* USE_TLS_1_1 */
#if defined(USE_TLS_1_2) && defined(USE_AES_GCM)
		if (ssl->flags & SSL_FLAGS_GMAC_W) {
			add += (numRecs * (TLS_GCM_TAG_LEN + ssl->nonceCtrLen));
		}
#endif
	}
	return add;
}

/******************************************************************************/
/*
	Write out a closure alert message (the only user initiated alert message)
	The user would call this when about to initate a socket close
	NOTICE: This is the internal function, there is a similarly named public
		API called matrixSslEncodeClosureAlert
*/
int32 sslEncodeClosureAlert(ssl_t *ssl, sslBuf_t *out, uint32 *reqLen)
{
/*
	If we've had a protocol error, don't allow further use of the session
*/
	if (ssl->flags & SSL_FLAGS_ERROR) {
		return MATRIXSSL_ERROR;
	}
	return writeAlert(ssl, SSL_ALERT_LEVEL_WARNING, SSL_ALERT_CLOSE_NOTIFY,
		out, reqLen);
}

/******************************************************************************/
/*
	Generic record header construction for alerts, handshake messages, and
	change cipher spec.  Determines message length for encryption and
	writes out to buffer up to the real message data.
	
	The FINISHED message is given special treatment here to move through the
	encrypted stages because the postponed flight encoding mechanism will
	not have moved to the SECURE_WRITE state until the CHANGE_CIPHER_SPEC
	has been encoded.  This means we have to look at the hsType and the
	ssl->cipher profile to see what is needed. 
	
	Incomming messageSize is the plaintext message length plus the header
	lengths.
*/
static int32 writeRecordHeader(ssl_t *ssl, int32 type, int32 hsType, 
				int32 *messageSize,	char *padLen, unsigned char **encryptStart,
				unsigned char **end, unsigned char **c)
{
	int32	messageData, msn;

	messageData = *messageSize - ssl->recordHeadLen;
	if (type == SSL_RECORD_TYPE_HANDSHAKE) {
		 messageData -= ssl->hshakeHeadLen;
	}
	if (type == SSL_RECORD_TYPE_HANDSHAKE_FIRST_FRAG) {
		 messageData -= ssl->hshakeHeadLen;
		 *messageSize = ssl->maxPtFrag + ssl->recordHeadLen;
		 type = SSL_RECORD_TYPE_HANDSHAKE;
	}


#ifdef USE_TLS_1_1
/*
	If a block cipher is being used TLS 1.1 requires the use
	of an explicit IV.  This is an extra random block of data
	prepended to the plaintext before encryption.  Account for
	that extra length here. */
	if (hsType == SSL_HS_FINISHED && (ssl->flags & SSL_FLAGS_TLS_1_1)) {
		if (ssl->cipher->blockSize > 1) {
			*messageSize += ssl->cipher->blockSize;
		}
	} else if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
			(ssl->flags & SSL_FLAGS_TLS_1_1) && (ssl->enBlockSize > 1)) {
		*messageSize += ssl->enBlockSize;
	}
#if defined(USE_TLS_1_2) && defined(USE_AES_GCM)
	/* This is to catch the FINISHED write for the postponed encode */
	if (hsType == SSL_HS_FINISHED) {
		if (ssl->cipher->flags & CRYPTO_FLAGS_GCM) {
			*messageSize += TLS_GCM_TAG_LEN + ssl->nonceCtrLen;
		}
	} else if ((ssl->flags & SSL_FLAGS_TLS_1_2) && (ssl->flags & SSL_FLAGS_GMAC_W)) {
		*messageSize += TLS_GCM_TAG_LEN + ssl->nonceCtrLen;
	}
#endif
#endif /* USE_TLS_1_1 */

/*
	If this session is already in a secure-write state, determine padding.
	Again, the FINISHED message is explicitly checked due to the delay
	of the ActivateWriteCipher for flight encodings.  In this case, cipher
	sizes are taken from ssl->cipher rather than the active values
*/
	*padLen = 0;
	if (hsType == SSL_HS_FINISHED) {
		if (!(ssl->cipher->flags & CRYPTO_FLAGS_GCM)) {
#ifdef USE_TRUNCATED_HMAC
			if (ssl->truncHmac) {
				*messageSize += 10;
			} else {
				*messageSize += ssl->cipher->macSize;
			}
#else
			*messageSize += ssl->cipher->macSize;
#endif
		} else {
			*messageSize += ssl->cipher->macSize;
		}
		*padLen = psPadLenPwr2(*messageSize - ssl->recordHeadLen,
			ssl->cipher->blockSize);
		*messageSize += *padLen;
	} else if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
			!(ssl->flags & SSL_FLAGS_GMAC_W)) {
		*messageSize += ssl->enMacSize;
		*padLen = psPadLenPwr2(*messageSize - ssl->recordHeadLen,
			ssl->enBlockSize);
		*messageSize += *padLen;
	}

	if (*end - *c < *messageSize) {
/*
		Callers other than sslEncodeResponse do not necessarily check for
		FULL before calling.  We do it here for them.
*/
		return SSL_FULL;
	}


	*c += psWriteRecordInfo(ssl, (unsigned char)type,
		*messageSize - ssl->recordHeadLen, *c, hsType);

/*
	All data written after this point is to be encrypted (if secure-write)
*/
	*encryptStart = *c;
	msn = 0;

#ifdef USE_TLS_1_1
/*
	Explicit IV notes taken from TLS 1.1 ietf draft.

	Generate a cryptographically strong random number R of
	length CipherSpec.block_length and prepend it to the plaintext
	prior to encryption. In this case either:

	The CBC residue from the previous record may be used
	as the mask. This preserves maximum code compatibility
	with TLS 1.0 and SSL 3. It also has the advantage that
	it does not require the ability to quickly reset the IV,
	which is known to be a problem on some systems.

	The data (R || data) is fed into the encryption process.
	The first cipher block containing E(mask XOR R) is placed
	in the IV field. The first block of content contains
	E(IV XOR data)
*/

	if (hsType == SSL_HS_FINISHED) {
		if ((ssl->flags & SSL_FLAGS_TLS_1_1) && (ssl->cipher->blockSize > 1)) {
			if (matrixSslGetPrngData(*c, ssl->cipher->blockSize) < 0) {
				psTraceInfo("WARNING: matrixSslGetPrngData failed\n");
			}
			*c += ssl->cipher->blockSize;
		}
	} else if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
			(ssl->flags & SSL_FLAGS_TLS_1_1) &&
			(ssl->enBlockSize > 1)) {
		if (matrixSslGetPrngData(*c, ssl->enBlockSize) < 0) {
			psTraceInfo("WARNING: matrixSslGetPrngData failed\n");
		}
		*c += ssl->enBlockSize;	
	}
#endif /* USE_TLS_1_1 */

/*
	Handshake records have another header layer to write here
*/
	if (type == SSL_RECORD_TYPE_HANDSHAKE) {
		*c += psWriteHandshakeHeader(ssl, (unsigned char)hsType, messageData,
			msn, 0, messageData, *c);
	}

	return PS_SUCCESS;
}


#ifdef USE_ZLIB_COMPRESSION
static int32 encryptCompressedRecord(ssl_t *ssl, int32 type, int32 messageSize,
						   unsigned char *pt, sslBuf_t *out, unsigned char **c)
{
	unsigned char	*encryptStart, *dataToMacAndEncrypt;
	int32			rc, ptLen, divLen, modLen, dataToMacAndEncryptLen;
	int32			zret, ztmp;
	int32			padLen;

	
	encryptStart = out->end + ssl->recordHeadLen;
#if defined(USE_TLS_1_2) && defined(USE_AES_GCM)
	if (ssl->flags & SSL_FLAGS_GMAC_W) {
		encryptStart += ssl->nonceCtrLen; /* Move past the plaintext nonce */
		ssl->outRecType = (unsigned char) type;
	}
#endif
	ptLen = *c - encryptStart;
	
#ifdef USE_TLS_1_1
	if ((ssl->flags & SSL_FLAGS_TLS_1_1) &&	(ssl->enBlockSize > 1)) {
		/* Do not compress IV */
		if (type == SSL_RECORD_TYPE_APPLICATION_DATA) {
			/* FUTURE: Application data is passed in with real pt from user but
				with the length of the explict IV added already. Can just
				encrypt IV in-siture now since the rest of the encypts will be
				coming from zlibBuffer */
			rc = ssl->encrypt(ssl, encryptStart, encryptStart,
				ssl->enBlockSize);
			if (rc < 0) {
				psTraceIntInfo("Error encrypting IV: %d\n", rc);
				return MATRIXSSL_ERROR;
			}	
			ptLen -= ssl->enBlockSize;
			encryptStart += ssl->enBlockSize;
		}  else {
			/* Handshake messages have been passed in with plaintext that
				begins with the explicit IV and size included.  Can just
				encrypt IV in-situ now since the rest of the encypts will be
				coming from zlibBuffer */
			rc = ssl->encrypt(ssl, pt, pt, ssl->enBlockSize);
			if (rc < 0) {
				psTraceIntInfo("Error encrypting IV: %d\n", rc);
				return MATRIXSSL_ERROR;
			}	
			pt += ssl->enBlockSize;
			ptLen -= ssl->enBlockSize;
			encryptStart += ssl->enBlockSize;
		}
	}	
#endif
		
	/* Compression is done only on the data itself so the prior work that 
		was just put into message size calcuations and padding length will
		need to be done again after deflate */
	ssl->zlibBuffer = psMalloc(MATRIX_NO_POOL, ptLen + MAX_ZLIB_COMPRESSED_OH);
	memset(ssl->zlibBuffer, 0, ptLen + MAX_ZLIB_COMPRESSED_OH);
	if (ssl->zlibBuffer == NULL) {
		psTraceInfo("Error allocating compression buffer\n");
		return MATRIXSSL_ERROR;
	}
	dataToMacAndEncrypt = ssl->zlibBuffer;
	dataToMacAndEncryptLen = ssl->deflate.total_out; /* tmp for later */
	/* psTraceBytes("pre deflate", pt, ptLen); */
	ssl->deflate.avail_out = ptLen + MAX_ZLIB_COMPRESSED_OH;
	ssl->deflate.next_out = dataToMacAndEncrypt;
	ssl->deflate.avail_in = ztmp = ptLen;
	ssl->deflate.next_in = pt;
				
	/* FUTURE: Deflate would need to be in a smarter loop if large amounts
		of data are ever passed through here */
	if ((zret = deflate(&ssl->deflate, Z_SYNC_FLUSH)) != Z_OK) {
		psTraceIntInfo("ZLIB deflate error %d\n", zret);
		psFree(ssl->zlibBuffer); ssl->zlibBuffer = NULL;
		return MATRIXSSL_ERROR;
	}
	if (ssl->deflate.avail_in != 0) {
		psTraceIntInfo("ZLIB didn't deflate %d bytes in single pass\n", ptLen);
		psFree(ssl->zlibBuffer); ssl->zlibBuffer = NULL;
		deflateEnd(&ssl->deflate);
		return MATRIXSSL_ERROR;
	}
	
	dataToMacAndEncryptLen = ssl->deflate.total_out - dataToMacAndEncryptLen;
	/* psTraceBytes("post deflate", dataToMacAndEncrypt,
		dataToMacAndEncryptLen); */
	if (dataToMacAndEncryptLen > ztmp) {
		/* Case where compression grew the data.  Push out end */
		*c += dataToMacAndEncryptLen - ztmp;	
	} else {
		/* Compression did good job to shrink. Pull back in */
		*c -= ztmp - dataToMacAndEncryptLen; 
	}
	
	/* Can now calculate new padding length */
	padLen = psPadLenPwr2(dataToMacAndEncryptLen + ssl->enMacSize,
		ssl->enBlockSize);
		
	/* Now see how this has changed the data lengths */ 
	ztmp = dataToMacAndEncryptLen + ssl->recordHeadLen + ssl->enMacSize +padLen;	
		
#ifdef USE_TLS_1_1
	if ((ssl->flags & SSL_FLAGS_TLS_1_1) &&	(ssl->enBlockSize > 1)) {
		ztmp += ssl->enBlockSize;
	}
#endif 

#if defined(USE_TLS_1_2) && defined(USE_AES_GCM)
	if (ssl->flags & SSL_FLAGS_GMAC_W) {
		psAssert(padLen == 0);
		/* This += works fine because padLen will be zero because enBlockSize
			and enMacSize are 0 */
		ztmp += TLS_GCM_TAG_LEN	+ ssl->nonceCtrLen;
		
	}
#endif /* USE_TLS_1_2 */
					
	/* Possible the length hasn't changed if compression didn't do much */
	if (messageSize != ztmp) {
		messageSize = ztmp;
		ztmp -= ssl->recordHeadLen;
		out->end[3] = (ztmp & 0xFF00) >> 8;
		out->end[4] = ztmp & 0xFF;
	}

	if (type == SSL_RECORD_TYPE_HANDSHAKE) {
		sslUpdateHSHash(ssl, pt, ptLen);
	}

	if (ssl->generateMac) {
		*c += ssl->generateMac(ssl, (unsigned char)type,
			dataToMacAndEncrypt, dataToMacAndEncryptLen, *c);
	}
	
	*c += sslWritePad(*c, (unsigned char)padLen);
	
#ifdef USE_TLS_1_2
	if (ssl->flags & SSL_FLAGS_GMAC_W) {
		*c += TLS_GCM_TAG_LEN; /* c is tracking end of record here and the
									tag has not yet been accounted for */
	}
#endif /* USE_TLS_1_2 */		
	
	
	/* Will always be non-insitu since the compressed data is in zlibBuffer.
		Requres two encrypts, one for plaintext and one for the
		any < blockSize remainder of the plaintext and the mac and pad	*/
	if (ssl->cipher->blockSize > 1) {
		divLen = dataToMacAndEncryptLen & ~(ssl->cipher->blockSize - 1);
		modLen = dataToMacAndEncryptLen & (ssl->cipher->blockSize - 1);
	} else {
#ifdef USE_TLS_1_2		
		if (ssl->flags & SSL_FLAGS_GMAC_W) {
			divLen = dataToMacAndEncryptLen + TLS_GCM_TAG_LEN;
			modLen = 0;
		} else {
#endif /* USE_TLS_1_2 */				
			divLen = dataToMacAndEncryptLen;
			modLen = 0;
#ifdef USE_TLS_1_2					
		}
#endif /* USE_TLS_1_2 */				
	}
	if (divLen > 0) {
		rc = ssl->encrypt(ssl, dataToMacAndEncrypt, encryptStart,
			divLen);
		if (rc < 0) {
			psFree(ssl->zlibBuffer); ssl->zlibBuffer = NULL;
			deflateEnd(&ssl->deflate);
			psTraceIntInfo("Error encrypting 2: %d\n", rc);
			return MATRIXSSL_ERROR;
		}
	}
	if (modLen > 0) {
		memcpy(encryptStart + divLen, dataToMacAndEncrypt + divLen,
			modLen);
	}
	rc = ssl->encrypt(ssl, encryptStart + divLen,
		encryptStart + divLen, modLen + ssl->enMacSize + padLen);
	
	if (rc < 0 || (*c - out->end != messageSize)) {
		psFree(ssl->zlibBuffer); ssl->zlibBuffer = NULL;
		deflateEnd(&ssl->deflate);
		psTraceIntInfo("Error encrypting 3: %d\n", rc);
		return MATRIXSSL_ERROR;
	}
	psFree(ssl->zlibBuffer); ssl->zlibBuffer = NULL;
	/* Will not need the context any longer since FINISHED is the only
		supported message */
	deflateEnd(&ssl->deflate);


	return MATRIXSSL_SUCCESS;
}
#endif /* USE_ZLIB_COMPRESSION */


/******************************************************************************/
/*
	Flights are encypted after they are fully written so this function
	just moves the buffer forward to account for the encryption overhead that
	will be filled in later
*/
static int32 postponeEncryptRecord(ssl_t *ssl, int32 type, int32 hsMsg,
				int32 messageSize, int32 padLen, unsigned char *pt,
				sslBuf_t *out, unsigned char **c)
{
	flightEncode_t	*flight, *prev;
	unsigned char	*encryptStart;
	int32			ptLen;

	if ((flight = psMalloc(ssl->flightPool, sizeof(flightEncode_t))) == NULL) {
		return PS_MEM_FAIL;
	}
	memset(flight, 0x0, sizeof(flightEncode_t));
	if (ssl->flightEncode == NULL) {
		ssl->flightEncode = flight;
	} else {
		prev = ssl->flightEncode;
		while (prev->next) {
			prev = prev->next;
		}
		prev->next = flight;
	}
	encryptStart = out->end + ssl->recordHeadLen;
		
#if defined(USE_TLS_1_2) && defined(USE_AES_GCM)
	if (hsMsg == SSL_HS_FINISHED) {
		if (ssl->cipher->flags & CRYPTO_FLAGS_GCM) {
			encryptStart += ssl->nonceCtrLen;
		}
	} else if (ssl->flags & SSL_FLAGS_GMAC_W) {
		encryptStart += ssl->nonceCtrLen; /* Move past the plaintext nonce */
	}
#endif
	
	ptLen = (int32)(*c - encryptStart);

	flight->start = pt;
	flight->len = ptLen;
	flight->type = type;
	flight->padLen = padLen;
	flight->messageSize = messageSize;
	flight->hsMsg = hsMsg;
	flight->seqDelay = ssl->seqDelay;
	
	if (hsMsg == SSL_HS_FINISHED) {
		if (!(ssl->cipher->flags & CRYPTO_FLAGS_GCM)) {	
#ifdef USE_TRUNCATED_HMAC
			if (ssl->truncHmac) {
				*c += 10;
			} else {
				*c += ssl->cipher->macSize;
			}
#else
			*c += ssl->cipher->macSize;
#endif
		} else {
			*c += ssl->cipher->macSize;
		}
	} else {
		*c += ssl->enMacSize;
	}
	*c += padLen;

#if defined(USE_TLS_1_2) && defined(USE_AES_GCM)
	if (hsMsg == SSL_HS_FINISHED) {
		if (ssl->cipher->flags & CRYPTO_FLAGS_GCM) {
			*c += TLS_GCM_TAG_LEN;
		}
	} else if (ssl->flags & SSL_FLAGS_GMAC_W) {
		*c += TLS_GCM_TAG_LEN; /* c is tracking end of record here and the
									tag has not yet been accounted for */
	}
#endif /* USE_TLS_1_2 */

#ifdef USE_TLS_1_1
#endif /* USE_TLS_1_1 */

	if (*c - out->end != messageSize) {
		psTraceIntInfo("postponeEncryptRecord length sanity test failed %d\n",
			(int32)(*c - out->end));
		printf(" %d\n", messageSize);
		return MATRIXSSL_ERROR;
	}
	return MATRIXSSL_SUCCESS;
}

/******************************************************************************/
/*
	Encrypt the message using the current cipher.  This call is used in
	conjunction with the writeRecordHeader function above to finish writing
	an SSL record.  Updates handshake hash if necessary, generates message
	MAC, writes the padding, and does the encryption.

	messageSize is the final size, with header, mac and padding of the output
	messageSize - 5 = ssl.recLen
	*c - encryptStart = plaintext length
*/
static int32 encryptRecord(ssl_t *ssl, int32 type, int32 messageSize,
						   int32 padLen, unsigned char *pt,
						   sslBuf_t *out, unsigned char **c)
{
	unsigned char	*encryptStart;
	int32			rc, ptLen, divLen, modLen;

#ifdef USE_ZLIB_COMPRESSION
	/* In the current implementation, MatrixSSL will only internally handle
		the compression and decompression of the FINISHED message.  Application
		data will be compressed and decompressed by the caller.
		Re-handshakes are not supported and this would have been caught
		earlier in the state machine so if the record type is HANDSHAKE we
		can be sure this is the FINISHED message
		
		This should allow compatibility with SSL implementations that support
		ZLIB compression */
	if (ssl->flags & SSL_FLAGS_WRITE_SECURE && ssl->compression &&
			type == SSL_RECORD_TYPE_HANDSHAKE) {
		return encryptCompressedRecord(ssl, type, messageSize, pt, out, c);
	}
#endif

	encryptStart = out->end + ssl->recordHeadLen;

#if defined(USE_TLS_1_2) && defined(USE_AES_GCM)
	if (ssl->flags & SSL_FLAGS_GMAC_W) {
		encryptStart += ssl->nonceCtrLen; /* Move past the plaintext nonce */
		ssl->outRecType = (unsigned char) type;
	}
#endif	
	
	ptLen = (int32)(*c - encryptStart);
#ifdef USE_TLS
#ifdef USE_TLS_1_1
	if ((ssl->flags & SSL_FLAGS_WRITE_SECURE) &&
			(ssl->flags & SSL_FLAGS_TLS_1_1) &&	(ssl->enBlockSize > 1)) {
/*
		Don't add the random bytes into the hash of the message.  Makes
		things very easy on the other side to simply discard the randoms
*/
		if (type == SSL_RECORD_TYPE_HANDSHAKE) {
			sslUpdateHSHash(ssl, pt + ssl->enBlockSize,
				ptLen - ssl->enBlockSize);
		}
		if (type == SSL_RECORD_TYPE_APPLICATION_DATA) {
			/* Application data is passed in with real pt from user but
				with the length of the explict IV added already */
			*c += ssl->generateMac(ssl, (unsigned char)type,
				pt, ptLen - ssl->enBlockSize, *c);
			/* While we are in here, let's see if this is an in-situ case */
			if (encryptStart + ssl->enBlockSize == pt) {
				pt = encryptStart;
			} else {
				/* Not in-situ.  Encrypt the explict IV now */
				if ((rc = ssl->encrypt(ssl, encryptStart,
						encryptStart, ssl->enBlockSize)) < 0) {
					psTraceIntInfo("Error encrypting explicit IV: %d\n", rc);
					return MATRIXSSL_ERROR;
				}
				encryptStart += ssl->enBlockSize;
				ptLen -= ssl->enBlockSize;
			}
		} else {
			/* Handshake messages have been passed in with plaintext that
				begins with the explicit IV and size included */
			*c += ssl->generateMac(ssl, (unsigned char)type,
				pt + ssl->enBlockSize, ptLen - ssl->enBlockSize, *c);
		}
	} else {
#endif /* USE_TLS_1_1 */
		if (type == SSL_RECORD_TYPE_HANDSHAKE) {
			if ((rc = sslUpdateHSHash(ssl, pt, ptLen)) < 0) {
				return rc;
			}
		}
		if (ssl->generateMac) {
			*c += ssl->generateMac(ssl, (unsigned char)type, pt, ptLen, *c);
		}
#ifdef USE_TLS_1_1
	}
#endif /* USE_TLS_1_1 */
#else /* USE_TLS */
	if (type == SSL_RECORD_TYPE_HANDSHAKE) {
		sslUpdateHSHash(ssl, pt, ptLen);
	}
	*c += ssl->generateMac(ssl, (unsigned char)type, pt, 
		ptLen, *c);
#endif /* USE_TLS */
	
	*c += sslWritePad(*c, (unsigned char)padLen);

#ifdef USE_TLS_1_2
	if (ssl->flags & SSL_FLAGS_GMAC_W) {
		*c += TLS_GCM_TAG_LEN; /* c is tracking end of record here and the
									tag has not yet been accounted for */
	}
#endif /* USE_TLS_1_2 */	
	
	if (pt == encryptStart) {
		/* In-situ encode */
		if ((rc = ssl->encrypt(ssl, pt, encryptStart, 
				(uint32)(*c - encryptStart))) < 0 || 
				*c - out->end != messageSize) {
			psTraceIntInfo("Error encrypting 1: %d\n", rc);
			return MATRIXSSL_ERROR;
		}
	} else {
		/*
			Non-insitu requres two encrypts, one for plaintext and one for the
			any < blockSize remainder of the plaintext and the mac and pad
		*/
    	if (ssl->flags & SSL_FLAGS_WRITE_SECURE) {
			if (ssl->cipher->blockSize > 1) {
				divLen = ptLen & ~(ssl->cipher->blockSize - 1);
				modLen = ptLen & (ssl->cipher->blockSize - 1);
			} else {
#ifdef USE_TLS_1_2		
				if (ssl->flags & SSL_FLAGS_GMAC_W) {
					divLen = ptLen + TLS_GCM_TAG_LEN;
					modLen = 0;
				} else {
#endif /* USE_TLS_1_2 */				
					divLen = ptLen;
					modLen = 0;
#ifdef USE_TLS_1_2					
				}
#endif /* USE_TLS_1_2 */				
			}
			if (divLen > 0) {
				rc = ssl->encrypt(ssl, pt, encryptStart, divLen);
				if (rc < 0) {
					psTraceIntInfo("Error encrypting 2: %d\n", rc);
					return MATRIXSSL_ERROR;
				}
			}
			if (modLen > 0) {
				memcpy(encryptStart + divLen, pt + divLen, modLen);
			}
			rc = ssl->encrypt(ssl, encryptStart + divLen,
				encryptStart + divLen, modLen + ssl->enMacSize + padLen);
		} else {
			rc = ssl->encrypt(ssl, pt, encryptStart, 
				(uint32)(*c - encryptStart));
		}
		if (rc < 0 || (*c - out->end != messageSize)) {
			psTraceIntInfo("Error encrypting 3: %d\n", rc);
			return MATRIXSSL_ERROR;
		}
	}

	if (*c - out->end != messageSize) {
		psTraceInfo("encryptRecord length sanity test failed\n");
		return MATRIXSSL_ERROR;
	}
	return MATRIXSSL_SUCCESS;
}

#ifdef USE_SERVER_SIDE_SSL
/******************************************************************************/
/*
	Write out the ServerHello message
*/
static int32 writeServerHello(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char	*c, *end, *encryptStart;
	char			padLen;
	int32			messageSize, rc, t;
	psTime_t		pst;
	int32			extLen = 0;	

	psTraceHs("<<< Server creating SERVER_HELLO message\n");
	c = out->end;
	end = out->buf + out->size;
/*
	Calculate the size of the message up front, and verify we have room
	We assume there will be a sessionId in the message, and make adjustments
	below if there is no sessionId.
*/
	messageSize =
		ssl->recordHeadLen +
		ssl->hshakeHeadLen +
		38 + SSL_MAX_SESSION_ID_SIZE;

#ifdef ENABLE_SECURE_REHANDSHAKES		
/*
	The RenegotiationInfo extension lengths are well known
*/	
	if (ssl->secureRenegotiationFlag == PS_TRUE && ssl->myVerifyDataLen == 0) {
		extLen = 7; /* 00 05 ff 01 00 01 00 */
	} else if (ssl->secureRenegotiationFlag == PS_TRUE &&
			ssl->myVerifyDataLen > 0) {
		extLen = 2 + 5 + ssl->myVerifyDataLen + ssl->peerVerifyDataLen;
	}
#endif /* ENABLE_SECURE_REHANDSHAKES */

#ifdef USE_ECC_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
		if (extLen == 0) {
			extLen = 2; /* if first extension, add two byte total len */
		}
		/* ELLIPTIC_POINTS_EXT - hardcoded to 'uncompressed' support */
		extLen += 6; /* 00 0B 00 02 01 00 */ 
	}
#endif /* USE_ECC_CIPHER_SUITE */

	if (ssl->maxPtFrag < SSL_MAX_PLAINTEXT_LEN) {
		if (extLen == 0) {
			extLen = 2;
		}
		extLen += 5;
	}
#ifdef USE_TRUNCATED_HMAC
	if (ssl->truncHmac) {
		if (extLen == 0) {
			extLen = 2;
		}
		extLen += 4;
	}
#endif

#ifdef USE_STATELESS_SESSION_TICKETS
	if (ssl->sid &&	ssl->sid->sessionTicketFlag == SESS_TICKET_FLAG_RECVD_EXT) {
		if (extLen == 0) {
			extLen = 2;
		}
		extLen += 4;
	}
#endif

	if (ssl->sniUsed) {
		if (extLen == 0) {
			extLen = 2;
		}
		extLen += 4;
	}

	messageSize += extLen;
	
/*
	 First 4 bytes of the serverRandom are the unix time to prevent replay
	 attacks, the rest are random
*/	
	t = psGetTime(&pst);
	ssl->sec.serverRandom[0] = (unsigned char)((t & 0xFF000000) >> 24);
	ssl->sec.serverRandom[1] = (unsigned char)((t & 0xFF0000) >> 16);
	ssl->sec.serverRandom[2] = (unsigned char)((t & 0xFF00) >> 8);
	ssl->sec.serverRandom[3] = (unsigned char)(t & 0xFF);
	if (matrixSslGetPrngData(ssl->sec.serverRandom + 4,
			SSL_HS_RANDOM_SIZE - 4) < 0) {
		return MATRIXSSL_ERROR;
	}
/*
	We register session here because at this point the serverRandom value is
	populated.  If we are able to register the session, the sessionID and
	sessionIdLen fields will be non-NULL, otherwise the session couldn't
	be registered.
*/
	if (!(ssl->flags & SSL_FLAGS_RESUMED)) {
		matrixRegisterSession(ssl);
	}
	messageSize -= (SSL_MAX_SESSION_ID_SIZE - ssl->sessionIdLen);

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_SERVER_HELLO, &messageSize, &padLen, &encryptStart,
			&end, &c)) < 0) {
		return rc;
	}
/*
	First two fields in the ServerHello message are the major and minor
	SSL protocol versions we agree to talk with
*/
	*c = ssl->majVer; c++;
	*c = ssl->minVer; c++;
/*
	The next 32 bytes are the server's random value, to be combined with
	the client random and premaster for key generation later
*/
	memcpy(c, ssl->sec.serverRandom, SSL_HS_RANDOM_SIZE);
	c += SSL_HS_RANDOM_SIZE;
/*
	The next data is a single byte containing the session ID length,
	and up to 32 bytes containing the session id.
	First register the session, which will give us a session id and length
	if not all session slots in the table are used
*/
	*c = (unsigned char)ssl->sessionIdLen; c++;
	if (ssl->sessionIdLen > 0) {
        memcpy(c, ssl->sessionId, ssl->sessionIdLen);
		c += ssl->sessionIdLen;
	}
/*
	Two byte cipher suite we've chosen based on the list sent by the client
	and what we support.
	One byte compression method (always zero)
*/
	*c = (ssl->cipher->ident & 0xFF00) >> 8; c++;
	*c = ssl->cipher->ident & 0xFF; c++;
#ifdef USE_ZLIB_COMPRESSION
	if (ssl->compression) {
		*c = 1; c++;
	} else {
		*c = 0; c++;
	}
#else	
	*c = 0; c++;
#endif	
	
	if (extLen != 0) {
		extLen -= 2; /* Don't add self to total extension len */
		*c = (extLen & 0xFF00) >> 8; c++;
		*c = extLen & 0xFF; c++;
		
		if (ssl->maxPtFrag < SSL_MAX_PLAINTEXT_LEN) {
			*c = 0x0; c++;
			*c = 0x1; c++;
			*c = 0x0; c++;
			*c = 0x1; c++;
			
			if (ssl->maxPtFrag == 0x200) {
				*c = 0x1; c++;
			}
			if (ssl->maxPtFrag == 0x400) {
				*c = 0x2; c++;
			}
			if (ssl->maxPtFrag == 0x800) {
				*c = 0x3; c++;
			}
			if (ssl->maxPtFrag == 0x1000) {
				*c = 0x4; c++;
			}
		}
#ifdef USE_TRUNCATED_HMAC
		if (ssl->truncHmac) {
			*c = (EXT_TRUNCATED_HMAC & 0xFF00) >> 8; c++;
			*c = EXT_TRUNCATED_HMAC & 0xFF; c++;
			*c = 0; c++;
			*c = 0; c++;
		}
#endif /* USE_TRUNCATED_HMAC */

#ifdef USE_STATELESS_SESSION_TICKETS
		if (ssl->sid &&
				ssl->sid->sessionTicketFlag == SESS_TICKET_FLAG_RECVD_EXT) {
			/* This empty extension is ALWAYS an indication to the client that
				a NewSessionTicket handshake message will be sent */
			*c = (SESSION_TICKET_EXT & 0xFF00) >> 8; c++;
			*c = SESSION_TICKET_EXT & 0xFF; c++;
			*c = 0; c++;
			*c = 0; c++;
		}
#endif

		if (ssl->sniUsed) {
			*c = (EXT_SERVER_NAME & 0xFF00) >> 8; c++;
			*c = EXT_SERVER_NAME & 0xFF; c++;
			*c = 0; c++;
			*c = 0; c++;
		}

#ifdef ENABLE_SECURE_REHANDSHAKES
		if (ssl->secureRenegotiationFlag == PS_TRUE) {
			/* RenegotiationInfo*/
			*c = (EXT_RENEGOTIATION_INFO & 0xFF00) >> 8; c++;
			*c = EXT_RENEGOTIATION_INFO & 0xFF; c++;
			if (ssl->myVerifyDataLen == 0) {
				*c = 0; c++;
				*c = 1; c++;
				*c = 0; c++;
			} else {
				*c =((ssl->myVerifyDataLen+ssl->peerVerifyDataLen+1)&0xFF00)>>8;
				c++;
				*c = (ssl->myVerifyDataLen + ssl->peerVerifyDataLen + 1) & 0xFF;
				c++;
				*c = (ssl->myVerifyDataLen + ssl->peerVerifyDataLen) & 0xFF;c++;
				memcpy(c, ssl->peerVerifyData, ssl->peerVerifyDataLen);
				c += ssl->peerVerifyDataLen;
				memcpy(c, ssl->myVerifyData, ssl->myVerifyDataLen);
				c += ssl->myVerifyDataLen;
			}
		}
#endif /* ENABLE_SECURE_REHANDSHAKES */

#ifdef USE_ECC_CIPHER_SUITE	
		if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
			*c = (ELLIPTIC_POINTS_EXT & 0xFF00) >> 8; c++;
			*c = ELLIPTIC_POINTS_EXT & 0xFF; c++;
			*c = 0x00; c++;
			*c = 0x02; c++;
			*c = 0x01; c++;
			*c = 0x00; c++;
		}
#endif /* USE_ECC_CIPHER_SUITE */
	}

	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_SERVER_HELLO, messageSize, padLen, encryptStart, out, &c))
			< 0) {
		return rc;
	}
/*
	If we're resuming a session, we now have the clientRandom, master and 
	serverRandom, so we can derive keys which we'll be using shortly.
*/
	if (ssl->flags & SSL_FLAGS_RESUMED) {
		if ((rc = sslCreateKeys(ssl)) < 0) {
			return rc;
		}
	}
	out->end = c;
	
#ifdef USE_MATRIXSSL_STATS
	matrixsslUpdateStat(ssl, SH_SENT_STAT, 1);
#endif
	
	return MATRIXSSL_SUCCESS;
}

/******************************************************************************/
/*
	ServerHelloDone message is a blank handshake message
*/
static int32 writeServerHelloDone(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char	*c, *end, *encryptStart;
	char			padLen;
	int32				messageSize, rc;

	psTraceHs("<<< Server creating SERVER_HELLO_DONE message\n");
	c = out->end;
	end = out->buf + out->size;
	messageSize =
		ssl->recordHeadLen +
		ssl->hshakeHeadLen;

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_SERVER_HELLO_DONE, &messageSize, &padLen,
			&encryptStart, &end, &c)) < 0) {
		return rc;
	}

	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_SERVER_HELLO_DONE, messageSize, padLen, encryptStart, out,
			&c)) < 0) {
		return rc;
	}
	out->end = c;
	return MATRIXSSL_SUCCESS;
}
#ifdef USE_PSK_CIPHER_SUITE
/******************************************************************************/
/*
	The PSK cipher version of ServerKeyExchange.  Was able to single this
	message out with a dedicated write simply due to the flight
	logic of DH ciphers.  The ClientKeyExchange message for PSK was rolled
	into the generic function, for example.
*/
static int32 writePskServerKeyExchange(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char	*c, *end, *encryptStart;
	char			*hint;
	char			padLen;
	int32			messageSize, rc;
	uint32			hintLen;

	psTraceHs("<<< Server creating SERVER_KEY_EXCHANGE message\n");
#ifdef USE_DHE_CIPHER_SUITE
/*
	This test prevents a second ServerKeyExchange from being written if a
	PSK_DHE cipher was choosen.  This is an ugly side-effect of the many
	combinations of cipher suites being supported in the 'flight' based 
	state machine model
*/
	if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
		return MATRIXSSL_SUCCESS;
	}
#endif /* USE_DHE_CIPHER_SUITE */

	if (matrixPskGetHint(ssl, &hint, &hintLen) < 0) {
		return MATRIXSSL_ERROR;
	}
	if (hint == NULL || hintLen == 0) {
		return MATRIXSSL_SUCCESS;
	}

	c = out->end;
	end = out->buf + out->size;

	messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen + hintLen + 2;

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_SERVER_KEY_EXCHANGE, &messageSize, &padLen,
			&encryptStart, &end, &c)) < 0) {
		return rc;
	}

	*c = (hintLen & 0xFF00) >> 8; c++;
	*c = (hintLen & 0xFF); c++;
	memcpy(c, hint, hintLen);
	c += hintLen;

	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_SERVER_KEY_EXCHANGE, messageSize, padLen, encryptStart,
			out, &c)) < 0) {
		return rc;
	}
	out->end = c;
	return MATRIXSSL_SUCCESS;
}
#endif /* USE_PSK_CIPHER_SUITE */

#ifdef USE_STATELESS_SESSION_TICKETS /* Already inside a USE_SERVER_SIDE block */
static int32 writeNewSessionTicket(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char		*c, *end, *encryptStart;
	char				padLen;
	int32				messageSize, rc;
	
	psTraceHs("<<< Server creating NEW_SESSION_TICKET message\n");
	c = out->end;
	end = out->buf + out->size;

	/* magic 6 is 4 bytes lifetime hint and 2 bytes len */
	messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
		matrixSessionTicketLen() + 6;
	
	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_NEW_SESSION_TICKET, &messageSize, &padLen,
			&encryptStart, &end, &c)) < 0) {
		return rc;
	}
	
	rc = (int32)(end - c);
	if (matrixCreateSessionTicket(ssl, c, &rc) < 0) {
		psTraceInfo("Error generating session ticket\n");
		return MATRIXSSL_ERROR;
	}
	c += rc;
	
	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_NEW_SESSION_TICKET, messageSize, padLen, encryptStart, out,
			&c)) < 0) {
		return rc;
	}
	out->end = c;
		
	return PS_SUCCESS;
}
#endif /* USE_STATELESS_SESSION_TICKETS */

#ifdef USE_DHE_CIPHER_SUITE /* Already inside a USE_SERVER_SIDE block */
/******************************************************************************/
/*
	Write out the ServerKeyExchange message. 
*/
static int32 writeServerKeyExchange(ssl_t *ssl, sslBuf_t *out, uint32 pLen,
					unsigned char *p, uint32 gLen, unsigned char *g)
{
	unsigned char		*c, *end, *encryptStart;
	char				padLen;
	int32				messageSize, rc;
#ifndef USE_ONLY_PSK_CIPHER_SUITE
	int32				hashSize;
	unsigned char		*hsMsgHash, *sigStart;
	psDigestContext_t	digestCtx;
#endif	
	void				*pkiData = NULL;

#if defined(USE_PSK_CIPHER_SUITE) && defined(USE_ANON_DH_CIPHER_SUITE)
	char			*hint;
	uint32			hintLen;
#endif /* USE_PSK_CIPHER_SUITE && USE_ANON_DH_CIPHER_SUITE */
#ifdef USE_ECC_CIPHER_SUITE
	uint32			eccPubKeyLen;
#endif /* USE_ECC_CIPHER_SUITE */

	psTraceHs("<<< Server creating SERVER_KEY_EXCHANGE message\n");
	c = out->end;
	end = out->buf + out->size;

/*
	Calculate the size of the message up front, and verify we have room
*/
#ifdef USE_ANON_DH_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_ANON_CIPHER) {
		messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
			6 + pLen + gLen + ssl->sec.dhKeyPriv.size;
#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			messageSize -= 2; /* hashSigAlg not going to be needed */
		}
#endif			
			
#ifdef USE_PSK_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
			if (matrixPskGetHint(ssl, &hint, &hintLen) < 0) {
				return MATRIXSSL_ERROR;
			}
/*
 * 			RFC4279: In the absence of an application profile specification
 * 			specifying otherwise, servers SHOULD NOT provide an identity hint
 * 			and clients MUST ignore the identity hint field.  Applications that
 * 			do use this field MUST specify its contents, how the value is
 * 			chosen by the TLS server, and what the TLS client is expected to do
 * 			with the value.
 */
 			if (hintLen != 0 && hint != NULL) {
				messageSize += 2 + hintLen;
 			}
		}
#endif /* USE_PSK_CIPHER_SUITE */
	} else {
#endif /* USE_ANON_DH_CIPHER_SUITE */
#ifdef USE_ECC_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
			/* ExportKey portion */
			eccPubKeyLen = (ssl->sec.eccKeyPriv->dp->size * 2) + 1;
		
			if (ssl->flags & SSL_FLAGS_DHE_WITH_RSA) {
				messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
					eccPubKeyLen + 4 + ssl->keys->privKey->keysize + 2;
			} else if (ssl->flags & SSL_FLAGS_DHE_WITH_DSA) {
				messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen + 6 +
					eccPubKeyLen;				   
				messageSize += ssl->keys->privKey->keysize;
				/* Signature portion */
				messageSize += 6; /* 6 = 2 ASN_SEQ, 4 ASN_BIG */
				if (ssl->keys->privKey->keysize >= 128) {
					messageSize++; /* Extra byte for 'long' asn.1 encode */
				}
			}
		} else {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef REQUIRE_DH_PARAMS
		messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
			8 + pLen + gLen + ssl->sec.dhKeyPriv.size +
			ssl->keys->privKey->keysize;
#endif /* REQUIRE_DH_PARAMS */			
#ifdef USE_ECC_CIPHER_SUITE
		}
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef USE_ANON_DH_CIPHER_SUITE
	}
#endif /* USE_ANON_DH_CIPHER_SUITE */

#ifdef USE_TLS_1_2
	if (ssl->flags & SSL_FLAGS_TLS_1_2) {
		messageSize += 2; /* hashSigAlg */
	}
#endif
	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_SERVER_KEY_EXCHANGE, &messageSize, &padLen,
			&encryptStart, &end, &c)) < 0) {
		return rc;
	}
#ifndef USE_ONLY_PSK_CIPHER_SUITE
	sigStart = c;
#endif

#if defined(USE_PSK_CIPHER_SUITE) && defined(USE_ANON_DH_CIPHER_SUITE)
/*
		PSK suites have an optional leading PSK identity hint
*/
	if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
 		if (hintLen != 0 && hint != NULL) {
			*c = (hintLen & 0xFF00) >> 8; c++;
			*c = (hintLen & 0xFF); c++;
			memcpy(c, hint, hintLen);
			c += hintLen;
		}
	}
#endif /* USE_PSK_CIPHER_SUITE && USE_ANON_DH_CIPHER_SUITE */

#ifdef USE_ECC_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
/*
		1 byte - ECCurveType (NamedCurve enum is 3)
		 2 byte - NamedCurve id
*/
		*c = 3; c++; /* NamedCurve enum */
		*c = (ssl->sec.eccKeyPriv->dp->curveId & 0xFF00) >> 8; c++;
		*c = (ssl->sec.eccKeyPriv->dp->curveId & 0xFF); c++; 
		*c = eccPubKeyLen & 0xFF; c++;
		if (psEccX963ExportKey(ssl->hsPool, ssl->sec.eccKeyPriv, c,
				&eccPubKeyLen) != 0) {
			return MATRIXSSL_ERROR;
		}
		c += eccPubKeyLen;
	
	} else {
#endif
#ifdef REQUIRE_DH_PARAMS
/*
	The message itself;
		2 bytes p len, p, 2 bytes g len, g, 2 bytes pubKeyLen, pubKey

	Size tests have all ready been taken care of a level up from this
*/
	*c = (pLen & 0xFF00) >> 8; c++;
	*c = pLen & 0xFF; c++;
	memcpy(c, p, pLen);
	c += pLen;
	*c = (gLen & 0xFF00) >> 8; c++;
	*c = gLen & 0xFF; c++;
	memcpy(c, g, gLen);
	c += gLen;
	*c = (ssl->sec.dhKeyPriv.size & 0xFF00) >> 8; c++;
	*c = ssl->sec.dhKeyPriv.size & 0xFF; c++;

	if (psDhExportPubKey(ssl->hsPool, &ssl->sec.dhKeyPriv, &c) < 0) {
		return MATRIXSSL_ERROR;
	}
	c += ssl->sec.dhKeyPriv.size;
#endif /* REQUIRE_DH_PARAMS */
#ifdef USE_ECC_CIPHER_SUITE
	}
#endif /* USE_ECC_CIPHER_SUITE */
	


#ifdef USE_RSA_CIPHER_SUITE
/*
	RSA authentication requires an additional signature portion to the message
*/
	if (ssl->flags & SSL_FLAGS_DHE_WITH_RSA) {
#ifndef USE_ONLY_PSK_CIPHER_SUITE
		/* Saved aside for pkaAfter_t */
		if ((hsMsgHash = psMalloc(ssl->hsPool, SHA384_HASH_SIZE)) == NULL) {
			return PS_MEM_FAIL;
		}
#endif
#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			/* Using the algorithm from the certificate */
			if (ssl->keys->cert->sigAlgorithm == OID_SHA256_RSA_SIG) {
				hashSize = SHA256_HASH_SIZE;
				psSha256Init(&digestCtx);
				psSha256Update(&digestCtx, ssl->sec.clientRandom,
					SSL_HS_RANDOM_SIZE);
				psSha256Update(&digestCtx, ssl->sec.serverRandom,
					SSL_HS_RANDOM_SIZE);
				psSha256Update(&digestCtx, sigStart, (uint32)(c - sigStart));
				psSha256Final(&digestCtx, hsMsgHash);
				*c++ = 0x4;
				*c++ = 0x1;
#ifdef USE_SHA384
			} else if (ssl->keys->cert->sigAlgorithm == OID_SHA384_RSA_SIG) {
				hashSize = SHA384_HASH_SIZE;
				psSha384Init(&digestCtx);
				psSha384Update(&digestCtx, ssl->sec.clientRandom,
					SSL_HS_RANDOM_SIZE);
				psSha384Update(&digestCtx, ssl->sec.serverRandom,
					SSL_HS_RANDOM_SIZE);
				psSha384Update(&digestCtx, sigStart, (uint32)(c - sigStart));
				psSha384Final(&digestCtx, hsMsgHash);
				*c++ = 0x5;
				*c++ = 0x1;
#endif /* USE_SHA384 */
			/* If MD5, just send a SHA1.  Don't want to contribute to any 
				longevity of MD5 */
			} else if (ssl->keys->cert->sigAlgorithm == OID_SHA1_RSA_SIG ||
					ssl->keys->cert->sigAlgorithm == OID_MD5_RSA_SIG) {
				hashSize = SHA1_HASH_SIZE;
				psSha1Init(&digestCtx);
				psSha1Update(&digestCtx, ssl->sec.clientRandom,
					SSL_HS_RANDOM_SIZE);
				psSha1Update(&digestCtx, ssl->sec.serverRandom,
					SSL_HS_RANDOM_SIZE);
				psSha1Update(&digestCtx, sigStart, (uint32)(c - sigStart));
				psSha1Final(&digestCtx, hsMsgHash);
				*c++ = 0x2;
				*c++ = 0x1;
			} else {
				psTraceIntInfo("Unsupported sigAlgorithm for SKE write: %d\n",
					ssl->keys->cert->sigAlgorithm);
				psFree(hsMsgHash);
				return PS_UNSUPPORTED_FAIL;
			}
		} else {
			hashSize = MD5_HASH_SIZE + SHA1_HASH_SIZE;
			psMd5Init(&digestCtx);
			psMd5Update(&digestCtx, ssl->sec.clientRandom, SSL_HS_RANDOM_SIZE);
			psMd5Update(&digestCtx, ssl->sec.serverRandom, SSL_HS_RANDOM_SIZE);
			psMd5Update(&digestCtx, sigStart, (uint32)(c - sigStart));
			psMd5Final(&digestCtx, hsMsgHash);

			psSha1Init(&digestCtx);
			psSha1Update(&digestCtx, ssl->sec.clientRandom, SSL_HS_RANDOM_SIZE);
			psSha1Update(&digestCtx, ssl->sec.serverRandom, SSL_HS_RANDOM_SIZE);
			psSha1Update(&digestCtx, sigStart, (uint32)(c - sigStart));
			psSha1Final(&digestCtx, hsMsgHash + MD5_HASH_SIZE);
		}		
#else /* USE_TLS_1_2 */
		hashSize = MD5_HASH_SIZE + SHA1_HASH_SIZE;
		psMd5Init(&digestCtx);
		psMd5Update(&digestCtx, ssl->sec.clientRandom, SSL_HS_RANDOM_SIZE);
		psMd5Update(&digestCtx, ssl->sec.serverRandom, SSL_HS_RANDOM_SIZE);
		psMd5Update(&digestCtx, sigStart, (uint32)(c - sigStart));
		psMd5Final(&digestCtx, hsMsgHash);

		psSha1Init(&digestCtx);
		psSha1Update(&digestCtx, ssl->sec.clientRandom, SSL_HS_RANDOM_SIZE);
		psSha1Update(&digestCtx, ssl->sec.serverRandom, SSL_HS_RANDOM_SIZE);
		psSha1Update(&digestCtx, sigStart, (uint32)(c - sigStart));
		psSha1Final(&digestCtx, hsMsgHash + MD5_HASH_SIZE);
#endif /* USE_TLS_1_2 */

		*c = (ssl->keys->privKey->keysize & 0xFF00) >> 8; c++;
		*c = ssl->keys->privKey->keysize & 0xFF; c++;


#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			ssl->pkaAfter.type = PKA_AFTER_RSA_SIG_GEN_ELEMENT;
		} else {
			ssl->pkaAfter.type = PKA_AFTER_RSA_SIG_GEN;
		}
#else /* !USE_TLS_1_2 */
		ssl->pkaAfter.type = PKA_AFTER_RSA_SIG_GEN;
#endif /* USE_TLS_1_2 */		
		
		ssl->pkaAfter.inbuf = hsMsgHash;
		ssl->pkaAfter.outbuf = c;
		ssl->pkaAfter.data = pkiData;
		ssl->pkaAfter.inlen = hashSize;
		c += ssl->keys->privKey->keysize;
	}
#endif /* USE_RSA_CIPHER_SUITE */
	
#ifdef USE_ECC_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_DHE_WITH_DSA) {
#ifndef USE_ONLY_PSK_CIPHER_SUITE
		/* Saved aside for pkaAfter_t */
		if ((hsMsgHash = psMalloc(ssl->hsPool, SHA384_HASH_SIZE)) == NULL) {
			return PS_MEM_FAIL;
		}
#endif	
#ifdef USE_TLS_1_2
		if ((ssl->flags & SSL_FLAGS_TLS_1_2) &&
				(ssl->keys->cert->sigAlgorithm == OID_SHA256_ECDSA_SIG)) {
			hashSize = SHA256_HASH_SIZE;
			psSha256Init(&digestCtx);
			psSha256Update(&digestCtx, ssl->sec.clientRandom,
				SSL_HS_RANDOM_SIZE);
			psSha256Update(&digestCtx, ssl->sec.serverRandom,
				SSL_HS_RANDOM_SIZE);
			psSha256Update(&digestCtx, sigStart, (int32)(c - sigStart));
			psSha256Final(&digestCtx, hsMsgHash);
			*c++ = 0x4; /* SHA256 */
			*c++ = 0x3; /* ECDSA */
#ifdef USE_SHA384			
		} else if ((ssl->flags & SSL_FLAGS_TLS_1_2) &&
				(ssl->keys->cert->sigAlgorithm == OID_SHA384_ECDSA_SIG)) {
			hashSize = SHA384_HASH_SIZE;
			psSha384Init(&digestCtx);
			psSha384Update(&digestCtx, ssl->sec.clientRandom,
				SSL_HS_RANDOM_SIZE);
			psSha384Update(&digestCtx, ssl->sec.serverRandom,
				SSL_HS_RANDOM_SIZE);
			psSha384Update(&digestCtx, sigStart, (int32)(c - sigStart));
			psSha384Final(&digestCtx, hsMsgHash);
			*c++ = 0x5; /* SHA384 */
			*c++ = 0x3; /* ECDSA */
#endif			
		} else {
			hashSize = SHA1_HASH_SIZE;
			psSha1Init(&digestCtx);
			psSha1Update(&digestCtx, ssl->sec.clientRandom, SSL_HS_RANDOM_SIZE);
			psSha1Update(&digestCtx, ssl->sec.serverRandom, SSL_HS_RANDOM_SIZE);
			psSha1Update(&digestCtx, sigStart, (int32)(c - sigStart));
			psSha1Final(&digestCtx, hsMsgHash);
			if (ssl->flags & SSL_FLAGS_TLS_1_2) {
				*c++ = 0x2; /* SHA1 */
				*c++ = 0x3; /* ECDSA */
			}
		}
#else
		hashSize = SHA1_HASH_SIZE;
		psSha1Init(&digestCtx);
		psSha1Update(&digestCtx, ssl->sec.clientRandom, SSL_HS_RANDOM_SIZE);
		psSha1Update(&digestCtx, ssl->sec.serverRandom, SSL_HS_RANDOM_SIZE);
		psSha1Update(&digestCtx, sigStart, (int32)(c - sigStart));
		psSha1Final(&digestCtx, hsMsgHash);
#endif		

		ssl->pkaAfter.inbuf = hsMsgHash;
		ssl->pkaAfter.outbuf = c;
		ssl->pkaAfter.data = pkiData;
		ssl->pkaAfter.inlen = hashSize;
		ssl->pkaAfter.type = PKA_AFTER_ECDSA_SIG_GEN;
		rc = ssl->keys->privKey->keysize + 8;
		if (ssl->keys->privKey->keysize - 3 >= 128) {
			rc++;
		}
		c += rc;
	}
#endif /* USE_ECC_CIPHER_SUITE */

	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_SERVER_KEY_EXCHANGE, messageSize, padLen, encryptStart, out,
			&c)) < 0) {
		return rc;
	}
	out->end = c;
	return MATRIXSSL_SUCCESS;
}
#endif /* USE_DHE_CIPHER_SUITE */

/******************************************************************************/
/*
	Server initiated rehandshake public API call.
*/
int32 matrixSslEncodeHelloRequest(ssl_t *ssl, sslBuf_t *out, 
								  uint32 *requiredLen)
{
	unsigned char	*c, *end, *encryptStart;
	char			padLen;
	int32				messageSize, rc;

	*requiredLen = 0;
	psTraceHs("<<< Server creating HELLO_REQUEST message\n");
	if (ssl->flags & SSL_FLAGS_ERROR || ssl->flags & SSL_FLAGS_CLOSED) {
		psTraceInfo("SSL flag error in matrixSslEncodeHelloRequest\n");
		return MATRIXSSL_ERROR;
	}
	if (!(ssl->flags & SSL_FLAGS_SERVER) || (ssl->hsState != SSL_HS_DONE)) {
		psTraceInfo("SSL state error in matrixSslEncodeHelloRequest\n");
		return MATRIXSSL_ERROR;
	}

	c = out->end;
	end = out->buf + out->size;
	messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen;
	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_HELLO_REQUEST, &messageSize, &padLen,
			&encryptStart, &end, &c)) < 0) {
		*requiredLen = messageSize;
		return rc;
	}

	if ((rc = encryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE, messageSize,
			padLen, encryptStart, out, &c)) < 0) {
		return rc;
	}
	out->end = c;

	return MATRIXSSL_SUCCESS;
}
#else /* USE_SERVER_SIDE_SSL */
int32 matrixSslEncodeHelloRequest(ssl_t *ssl, sslBuf_t *out, 
								  uint32 *requiredLen)
{
		psTraceInfo("Library not built with USE_SERVER_SIDE_SSL\n");
		return PS_UNSUPPORTED_FAIL;
}
#endif /* USE_SERVER_SIDE_SSL */


#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
/*
	A fragmented write of the CERTIFICATE handhshake message.  This is the
	only handshake message that supports fragmentation because it is the only
	message where the 512byte plaintext max of the max_fragment extension can
	be exceeded.
*/
static int32 writeMultiRecordCertificate(ssl_t *ssl, sslBuf_t *out,
				int32 notEmpty, int32 totalClen, int32 lsize)
{
	psX509Cert_t	*cert = NULL, *future = NULL;
	unsigned char	*c, *end, *encryptStart;
	char			padLen;
	int32			messageSize, rc, certLen =0;
	int32			midWrite, midSizeWrite, countDown, firstOne = 1;
	
	c = out->end;
	end = out->buf + out->size;
	
	midSizeWrite = midWrite = 0;
	
	while (totalClen > 0) {
		if (firstOne) {
			firstOne = 0;
			countDown = ssl->maxPtFrag;
			messageSize = totalClen + lsize + ssl->recordHeadLen + ssl->hshakeHeadLen;
			if ((rc = writeRecordHeader(ssl,
					SSL_RECORD_TYPE_HANDSHAKE_FIRST_FRAG, SSL_HS_CERTIFICATE,
					&messageSize, &padLen, &encryptStart, &end, &c)) < 0) {
				return rc;
			}
			/*	Write out the certs	*/
			*c = (unsigned char)(((totalClen + (lsize - 3)) & 0xFF0000) >> 16);
			c++;
			*c = ((totalClen + (lsize - 3)) & 0xFF00) >> 8; c++;
			*c = ((totalClen + (lsize - 3)) & 0xFF); c++;
			countDown -= ssl->hshakeHeadLen + 3;
			
			if (notEmpty) {
				cert = ssl->keys->cert;
				while (cert) {
					psAssert(cert->unparsedBin != NULL);
					certLen = cert->binLen;
					midWrite = 0;
					if (certLen > 0) {
						if (countDown < 3) {
							/* Fragment falls right on cert len write.  Has
								to be at least one byte or countDown would have
								been 0 and got us out of here already*/
							*c = (unsigned char)((certLen & 0xFF0000) >> 16);
							c++; countDown--;
							midSizeWrite = 2;
							if (countDown != 0) {
								*c = (certLen & 0xFF00) >> 8; c++; countDown--;
								midSizeWrite = 1;
								if (countDown != 0) {
									*c = (certLen & 0xFF); c++; countDown--;
									midSizeWrite = 0;
								}
							}
							break;
						} else {
							*c = (unsigned char)((certLen & 0xFF0000) >> 16);
							c++;
							*c = (certLen & 0xFF00) >> 8; c++;
							*c = (certLen & 0xFF); c++;
							countDown -= 3;
						}
						midWrite = min(certLen, countDown);
						memcpy(c, cert->unparsedBin, midWrite);
						certLen -= midWrite;
						c += midWrite;
						totalClen -= midWrite;
						countDown -= midWrite;
						if (countDown == 0) {
							break;
						}
					}
					cert = cert->next;
				}
			}
			if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
					SSL_HS_CERTIFICATE, messageSize, padLen, encryptStart, out,
					&c)) < 0) {
				return rc;
			}
			out->end = c;
		} else {
/*
			Not-first fragments
*/
			if (midSizeWrite > 0) {
				messageSize = midSizeWrite;
			} else {
				messageSize = 0;
			}
			if ((certLen + messageSize) > ssl->maxPtFrag) {
				messageSize += ssl->maxPtFrag;
			} else {			
				messageSize += certLen;
				if (cert->next != NULL) {
					future = cert->next;
					while (future != NULL) {
						if (messageSize + future->binLen + 3 >
								(uint32)ssl->maxPtFrag) {
							messageSize = ssl->maxPtFrag;
							future = NULL;
						} else {
							messageSize += 3 + future->binLen;
							future = future->next;
						}
						
					}
				}			
			}

			countDown = messageSize;
			messageSize += ssl->recordHeadLen;
			/* Second, etc... */
			if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE_FRAG,
					SSL_HS_CERTIFICATE, &messageSize, &padLen, &encryptStart,
					&end, &c)) < 0) {
				return rc;
			}
			
			if (midSizeWrite > 0) {
				if (midSizeWrite == 2) {
					*c = (certLen & 0xFF00) >> 8; c++;
					*c = (certLen & 0xFF); c++;
					countDown -= 2;
				} else {
					*c = (certLen & 0xFF); c++;
					countDown -= 1;
				}
				midSizeWrite = 0;
			}
			
			if (countDown < certLen) {
				memcpy(c, cert->unparsedBin + midWrite, countDown);
				certLen -= countDown;
				c += countDown;
				totalClen -= countDown;
				midWrite += countDown;
				countDown = 0;
			} else {
				memcpy(c, cert->unparsedBin + midWrite, certLen);
				c += certLen;
				totalClen -= certLen;
				countDown -= certLen;
				certLen -= certLen;
			}
				
			while (countDown > 0) {				
				cert = cert->next;
				certLen = cert->binLen;
				midWrite = 0;
				if (countDown < 3) {
					/* Fragment falls right on cert len write */
					*c = (unsigned char)((certLen & 0xFF0000) >> 16);
					c++; countDown--;
					midSizeWrite = 2;
					if (countDown != 0) {
						*c = (certLen & 0xFF00) >> 8; c++; countDown--;
						midSizeWrite = 1;
						if (countDown != 0) {
							*c = (certLen & 0xFF); c++; countDown--;
							midSizeWrite = 0;
						}
					}
					break;
				} else {
					*c = (unsigned char)((certLen & 0xFF0000) >> 16);
					c++;
					*c = (certLen & 0xFF00) >> 8; c++;
					*c = (certLen & 0xFF); c++;
					countDown -= 3;
				}
				midWrite = min(certLen, countDown);
				memcpy(c, cert->unparsedBin, midWrite);
				certLen -= midWrite;
				c += midWrite;
				totalClen -= midWrite;
				countDown -= midWrite;
				if (countDown == 0) {
					break;
				}			
			
			}
			if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
					SSL_HS_CERTIFICATE, messageSize, padLen, encryptStart, out,
					&c)) < 0) {
				return rc;
			}
			out->end = c;
		}
	}
	
	out->end = c;
	return MATRIXSSL_SUCCESS;
}
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */	

/******************************************************************************/
/*
	Write a Certificate message.
	The encoding of the message is as follows:
		3 byte length of certificate data (network byte order)
		If there is no certificate,
			3 bytes of 0
		If there is one certificate,
			3 byte length of certificate + 3
			3 byte length of certificate
			certificate data
		For more than one certificate:
			3 byte length of all certificate data
			3 byte length of first certificate
			first certificate data
			3 byte length of second certificate
			second certificate data
	Certificate data is the base64 section of an X.509 certificate file
	in PEM format decoded to binary.  No additional interpretation is required.
*/
static int32 writeCertificate(ssl_t *ssl, sslBuf_t *out, int32 notEmpty)
{
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	psX509Cert_t	*cert;
	uint32			certLen;
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */

	unsigned char	*c, *end, *encryptStart;
	char			padLen;
	int32			totalCertLen, lsize, messageSize, i, rc;

	psTraceStrHs("<<< %s creating CERTIFICATE  message\n",
		(ssl->flags & SSL_FLAGS_SERVER) ? "Server" : "Client");

#ifdef USE_PSK_CIPHER_SUITE
/*
	Easier to exclude this message internally rather than futher muddy the
	numerous #ifdef and ssl->flags tests for DH, CLIENT_AUTH, and PSK states.
	A PSK or DHE_PSK cipher will never send this message
*/
	if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
		return MATRIXSSL_SUCCESS;
	}
#endif /* USE_PSK_CIPHER_SUITE */

	c = out->end;
	end = out->buf + out->size;

/*
	Determine total length of certs
*/
	totalCertLen = i = 0;
	if (notEmpty) {
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)	
		cert = ssl->keys->cert;
		for (; cert != NULL; i++) {
			psAssert(cert->unparsedBin != NULL);
			totalCertLen += cert->binLen;
			cert = cert->next;
		}
#else 
		return PS_DISABLED_FEATURE_FAIL;
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
	}
	
/*
	Account for the 3 bytes of certChain len for each cert and get messageSize
*/
	lsize = 3 + (i * 3);
	
	/* TODO DTLS: Make sure this maxPtFrag is consistent with the fragment
		extension and is not interfering with DTLS notions of fragmentation */
	if ((totalCertLen + lsize + ssl->hshakeHeadLen) > ssl->maxPtFrag) {
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)	
		return writeMultiRecordCertificate(ssl, out, notEmpty,
				totalCertLen, lsize);
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */				
	} else {
		messageSize =
			ssl->recordHeadLen +
			ssl->hshakeHeadLen +
			lsize + totalCertLen;

		if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
				SSL_HS_CERTIFICATE, &messageSize, &padLen, &encryptStart,
				&end, &c)) < 0) {
			return rc;
		}

/*
		Write out the certs
*/
		*c = (unsigned char)(((totalCertLen + (lsize - 3)) & 0xFF0000) >> 16);
		c++;
		*c = ((totalCertLen + (lsize - 3)) & 0xFF00) >> 8; c++;
		*c = ((totalCertLen + (lsize - 3)) & 0xFF); c++;

#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
		if (notEmpty) {
			cert = ssl->keys->cert;
			while (cert) {
				psAssert(cert->unparsedBin != NULL);
				certLen = cert->binLen;
				if (certLen > 0) {
					*c = (unsigned char)((certLen & 0xFF0000) >> 16); c++;
					*c = (certLen & 0xFF00) >> 8; c++;
					*c = (certLen & 0xFF); c++;
					memcpy(c, cert->unparsedBin, certLen);
					c += certLen;
				}
				cert = cert->next;
			}
		}
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
	
		if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
				SSL_HS_CERTIFICATE, messageSize, padLen, encryptStart, out,
				&c)) < 0) {
			return rc;
		}
		out->end = c;
	}
	return MATRIXSSL_SUCCESS;
}
#endif /* USE_ONLY_PSK_CIPHER_SUITE */

/******************************************************************************/
/*
	Write the ChangeCipherSpec message.  It has its own message type
	and contains just one byte of value one.  It is not a handshake 
	message, so it isn't included in the handshake hash.
*/
static int32 writeChangeCipherSpec(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char	*c, *end, *encryptStart;
	char			padLen;
	int32				messageSize, rc;

	psTraceStrHs("<<< %s creating CHANGE_CIPHER_SPEC message\n",
		(ssl->flags & SSL_FLAGS_SERVER) ? "Server" : "Client");

	c = out->end;
	end = out->buf + out->size;
	messageSize = ssl->recordHeadLen + 1;

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC, 0,
			&messageSize, &padLen, &encryptStart, &end, &c)) < 0) {
		return rc;
	}
	*c = 1; c++;

	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC,
			0, messageSize, padLen, encryptStart, out, &c)) < 0) {
		return rc;
	}
	out->end = c;

	return MATRIXSSL_SUCCESS;
}

static int32 postponeSnapshotHSHash(ssl_t *ssl, unsigned char *c, int32 sender)
{
	ssl->delayHsHash = c;
#ifdef USE_TLS
	if (ssl->flags & SSL_FLAGS_TLS) {
		return TLS_HS_FINISHED_SIZE;
	} else {
#endif /* USE_TLS */
		return MD5_HASH_SIZE + SHA1_HASH_SIZE;
#ifdef USE_TLS
	}
#endif /* USE_TLS */
	
}

/******************************************************************************/
/*
	Write the Finished message
	The message contains the 36 bytes, the 16 byte MD5 and 20 byte SHA1 hash
	of all the handshake messages so far (excluding this one!)
*/
static int32 writeFinished(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char	*c, *end, *encryptStart;
	char			padLen;
	int32			messageSize, verifyLen, rc;

	psTraceStrHs("<<< %s creating FINISHED message\n",
		(ssl->flags & SSL_FLAGS_SERVER) ? "Server" : "Client");

	c = out->end;
	end = out->buf + out->size;

	verifyLen = MD5_HASH_SIZE + SHA1_HASH_SIZE;
#ifdef USE_TLS
	if (ssl->flags & SSL_FLAGS_TLS) {
		verifyLen = TLS_HS_FINISHED_SIZE;
	}
#endif /* USE_TLS */
	messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen + verifyLen;

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE, SSL_HS_FINISHED,
			&messageSize, &padLen, &encryptStart, &end, &c)) < 0) {
		return rc;
	}
/*
	Output the hash of messages we've been collecting so far into the buffer
*/
	c += postponeSnapshotHSHash(ssl, c, ssl->flags & SSL_FLAGS_SERVER);
	
	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_FINISHED, messageSize, padLen, encryptStart, out, &c)) < 0) {
		return rc;
	}
	out->end = c;
	


#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	if (ssl->sec.cert) {
		psX509FreeCert(ssl->sec.cert);
		ssl->sec.cert = NULL;
	}
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

	return MATRIXSSL_SUCCESS;
}

/******************************************************************************/
/*
	Write an Alert message
	The message contains two bytes: AlertLevel and AlertDescription
*/
static int32 writeAlert(ssl_t *ssl, unsigned char level, 
						unsigned char description, sslBuf_t *out, 
						uint32 *requiredLen)
{
	unsigned char	*c, *end, *encryptStart;
	char			padLen;
	int32				messageSize, rc;

	c = out->end;
	end = out->buf + out->size;
	messageSize = 2 + ssl->recordHeadLen;
	
	/* Force the alert to WARNING if the spec says the alert MUST be that */
	if (description == (unsigned char)SSL_ALERT_NO_RENEGOTIATION) {
		level = (unsigned char)SSL_ALERT_LEVEL_WARNING;
		ssl->err = SSL_ALERT_NONE;
	}

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_ALERT, 0, &messageSize,
			&padLen, &encryptStart, &end, &c)) < 0) {
		*requiredLen = messageSize;
		return rc;
	}
	*c = level; c++;
	*c = description; c++;

	if ((rc = encryptRecord(ssl, SSL_RECORD_TYPE_ALERT, messageSize,
			padLen, encryptStart, out, &c)) < 0) {
		*requiredLen = messageSize;
		return rc;
	}
	out->end = c;
#ifdef USE_MATRIXSSL_STATS
	matrixsslUpdateStat(ssl, ALERT_SENT_STAT, (int32)(description));
#endif	
	return MATRIXSSL_SUCCESS;
}

#ifdef USE_CLIENT_SIDE_SSL
/******************************************************************************/
/*
	Write out the ClientHello message to a buffer
*/
int32 matrixSslEncodeClientHello(ssl_t *ssl, sslBuf_t *out,
		uint32 cipherSpecs[], uint16 cipherSpecLen, uint32 *requiredLen,
		tlsExtension_t *userExt)
{
	unsigned char	*c, *end, *encryptStart;
	char			padLen;
	int32			messageSize, rc, cipherLen, cookieLen, addScsv, t;
	psTime_t		pst;
	tlsExtension_t	*ext;
	uint32			extLen, populateRand;
	sslCipherSpec_t	*cipherDetails;
	short			i;
#ifdef USE_TLS_1_2
	short			sigHashLen, sigHashCount, j;
	unsigned char	sigHash[18];
#endif		
#ifdef USE_ECC_CIPHER_SUITE
	char			eccCurveList[32];
	uint32			curveListLen;
#endif /* USE_ECC_CIPHER_SUITE */

	psTraceHs("<<< Client creating CLIENT_HELLO  message\n");
	*requiredLen = 0;
	if (out == NULL || out->buf == NULL || ssl == NULL) {
		return PS_ARG_FAIL;
	}
	if (cipherSpecLen > 0 && (cipherSpecs == NULL || cipherSpecs[0] == 0)) {
		return PS_ARG_FAIL;
	}
	if (ssl->flags & SSL_FLAGS_ERROR || ssl->flags & SSL_FLAGS_CLOSED) {
		psTraceInfo("SSL flag error in matrixSslEncodeClientHello\n");
		return MATRIXSSL_ERROR;
	}
	if (ssl->flags & SSL_FLAGS_SERVER || (ssl->hsState != SSL_HS_SERVER_HELLO &&
			ssl->hsState != SSL_HS_DONE &&
			ssl->hsState != SSL_HS_HELLO_REQUEST )) {
		psTraceInfo("SSL state error in matrixSslEncodeClientHello\n");	
		return MATRIXSSL_ERROR;
	}
	
	sslInitHSHash(ssl);

	cookieLen = 0;
	/* If no resumption, clear the RESUMED flag in case the caller is
		attempting to bypass matrixSslEncodeRehandshake. */
	if (ssl->sessionIdLen <= 0) {
		ssl->flags &= ~SSL_FLAGS_RESUMED;
	}

	if (cipherSpecLen == 0 || cipherSpecs == NULL || cipherSpecs[0] == 0) {
		if ((cipherLen = sslGetCipherSpecListLen(ssl)) == 2) {
			psTraceInfo("No cipher suites enabled (or no key material)\n");
			return MATRIXSSL_ERROR;
		}
	} else {
		/* If ciphers are specified it is two bytes length and two bytes data */
		cipherLen = 2;
		for (i = 0; i < cipherSpecLen; i++) {
		    cipherDetails = sslGetCipherSpec(ssl, cipherSpecs[i]);
			if (NULL == cipherDetails) {
				psTraceIntInfo("Cipher suite not supported: %d\n",
					cipherSpecs[i]);
				return PS_UNSUPPORTED_FAIL;
			}
			cipherLen += 2;
		}
	}
	
	addScsv = 0;
#ifdef ENABLE_SECURE_REHANDSHAKES
/*
	Initial CLIENT_HELLO will use the SCSV mechanism for greatest compat
*/
	if (ssl->myVerifyDataLen == 0) {
		cipherLen += 2; /* cipher id 0x00FF */
		addScsv = 1;
	}
#endif

/*
	Calculate the size of the message up front, and write header
*/
	messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
		5 + SSL_HS_RANDOM_SIZE + ssl->sessionIdLen + cipherLen + cookieLen;
	
#ifdef USE_ZLIB_COMPRESSION
	messageSize += 1;
#endif
	
/*
	Extension lengths
*/
	extLen = 0;
	
/*
	Max Fragment extension request
*/
	ssl->maxPtFrag = SSL_MAX_PLAINTEXT_LEN;
	if (ssl->minVer > 0 &&
			(REQUESTED_MAX_PLAINTEXT_RECORD_LEN < SSL_MAX_PLAINTEXT_LEN)) {
		if (REQUESTED_MAX_PLAINTEXT_RECORD_LEN == 0x200 ||
				REQUESTED_MAX_PLAINTEXT_RECORD_LEN == 0x400 ||
				REQUESTED_MAX_PLAINTEXT_RECORD_LEN == 0x800 ||
				REQUESTED_MAX_PLAINTEXT_RECORD_LEN == 0x1000) {
			extLen = 2 + 5; /* 2 for total ext len + 5 for ourselves */
			/* Also indicate that we're requesting a different plaintext size */
			ssl->maxPtFrag = 0XFF;
		}			
	}
#ifdef USE_TRUNCATED_HMAC 
	if (extLen == 0) {
		extLen = 2; /* First extension found so total len */
	}
	extLen += 4; /* empty "extension_data" */
#endif

#ifdef ENABLE_SECURE_REHANDSHAKES
/*
	Subsequent CLIENT_HELLOs must use a populated RenegotiationInfo extension
*/	
	if (ssl->myVerifyDataLen != 0) {
		if (extLen == 0) {
			extLen = 2; /* First extension found so total len */
		}
		extLen += ssl->myVerifyDataLen + 5; /* 5 type/len/len */
	}
#endif /* ENABLE_SECURE_REHANDSHAKES */

#ifdef USE_ECC_CIPHER_SUITE
	curveListLen = 0;
	if (eccSuitesSupported(ssl, cipherSpecLen, cipherSpecs)) {
		/*	Getting the curve list from crypto directly */
		curveListLen = sizeof(eccCurveList);
		psGetEccCurveIdList(eccCurveList, &curveListLen);
		if (curveListLen > 0) {
			if (extLen == 0) {
				extLen = 2; /* First extension found so total len */
			}
			/* ELLIPTIC_CURVE_EXT */
			extLen += curveListLen + 6; /* 2 id, 2 for ext len, 2 len */
			/* ELLIPTIC_POINTS_EXT - hardcoded to 'uncompressed' support */
			extLen += 6; /* 00 0B 00 02 01 00 */
		}
	}
#endif /* USE_ECC_CIPHER_SUITE */

#ifdef USE_STATELESS_SESSION_TICKETS
	if (ssl->sid) {
		if (extLen == 0) {
			extLen = 2;  /* First extension found so total len */
		}
		extLen += 4; /* 2 type, 2 length */
		if (ssl->sid->sessionTicketLen > 0 &&
				ssl->sid->sessionTicketFlag == SESS_TICKET_FLAG_USING_TICKET) {
			extLen += ssl->sid->sessionTicketLen;
		}
	}
#endif

#ifdef USE_TLS_1_2
	/* TLS 1.2 clients must add the SignatureAndHashAlgorithm extension.
		Sending all the algorithms that are enabled.
		
		enum {
          none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
          sha512(6), (255)
		} HashAlgorithm;

		enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) } SigAlgorithm;
	*/
	sigHashLen = 2;		/* start with 2 byte length */
	sigHash[0] = 0x0;	/* First byte of two byte length is never needed */	
#ifdef USE_SHA384
	sigHashCount = 4;
	sigHashLen += 4;
	sigHash[2] = 0x5;	/* SHA384 */
	sigHash[4] = 0x4;	/* SHA256 */
	sigHash[6] = 0x2;	/* SHA1 */
	sigHash[8] = 0x1;	/* MD5 */
	/* Repeat in case a second pub key alg is there.  No harm to fill in */
	sigHash[10] = 0x5;	/* SHA384 */
	sigHash[12] = 0x4;	/* SHA256 */
	sigHash[14] = 0x2;	/* SHA1 */
	sigHash[16] = 0x1;	/* MD5 */
#else
	sigHashCount = 3;
	sigHashLen += 3;
	sigHash[2] = 0x4;	/* SHA256 */
	sigHash[4] = 0x2;	/* SHA1 */
	sigHash[6] = 0x1;	/* MD5 */
	/* Repeat in case a second pub key alg is there.  No harm to fill in */
	sigHash[8] = 0x4;	/* SHA256 */
	sigHash[10] = 0x2;	/* SHA1 */
	sigHash[12] = 0x1;	/* MD5 */
#endif	

	/* Now fill in pub key algorithms */
#ifdef USE_ECC
	j = sigHashCount;
	for (i = 3; j > 0; i += 2) {
		sigHashLen += 1;
		sigHash[i] = 0x3; /* ECDSA */
		j--;
	}
#ifdef USE_RSA
	/* Both ECC and RSA are supported */
	j = sigHashCount;
	for (; j > 0; i += 2) {
		sigHashLen += 2; /* Account now for the repeat hash */
		sigHash[i] = 0x1; /* RSA */
		j--;
	}
#endif
#else
	/* RSA-only build */
	j = sigHashCount;
	for (i = 3; j > 0; i += 2) {
		sigHashLen += 1;
		sigHash[i] = 0x1; /* ECDSA */
		j--;
	}
#endif
	sigHash[1] = sigHashLen - 2; /* Total minus 2 byte length */
	
	if (extLen == 0) {
		extLen = 2;  /* First extension found so total len */
	}
	extLen += 4 + sigHashLen; /* 2 type, 2 length */
#endif /* USE_TLS_1_2 */


/*
	Add any user-provided extensions
*/
	ext = userExt;
	if (ext && extLen == 0) {
		extLen = 2; /* Start with the initial len */
	}	
	while (ext) {		
		extLen += ext->extLen + 4; /* +4 for type and length of each */ 
		ext = ext->next;
	}

	messageSize += extLen;

	c = out->end;
	end = out->buf + out->size;

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_CLIENT_HELLO, &messageSize, &padLen, &encryptStart,
			&end, &c)) < 0) {
		*requiredLen = messageSize;
		return rc;
	}

	populateRand = 1;

	if (populateRand) {
		/*	First 4 bytes of the serverRandom are the unix time to prevent
			replay attacks, the rest are random */
		t = psGetTime(&pst);
		ssl->sec.clientRandom[0] = (unsigned char)((t & 0xFF000000) >> 24);
		ssl->sec.clientRandom[1] = (unsigned char)((t & 0xFF0000) >> 16);
		ssl->sec.clientRandom[2] = (unsigned char)((t & 0xFF00) >> 8);
		ssl->sec.clientRandom[3] = (unsigned char)(t & 0xFF);
		if ((rc = matrixSslGetPrngData(ssl->sec.clientRandom + 4,
				SSL_HS_RANDOM_SIZE - 4)) < PS_SUCCESS) {
			return rc;
		}	
	}
/*
	First two fields in the ClientHello message are the maximum major 
	and minor SSL protocol versions we support
*/
	*c = ssl->majVer; c++;
	*c = ssl->minVer; c++;
/*
	The next 32 bytes are the server's random value, to be combined with
	the client random and premaster for key generation later
*/
	memcpy(c, ssl->sec.clientRandom, SSL_HS_RANDOM_SIZE);
	c += SSL_HS_RANDOM_SIZE;
/*
	The next data is a single byte containing the session ID length,
	and up to 32 bytes containing the session id.
	If we are asking to resume a session, then the sessionId would have
	been set at session creation time.
*/
	*c = (unsigned char)ssl->sessionIdLen; c++;
	if (ssl->sessionIdLen > 0) {
        memcpy(c, ssl->sessionId, ssl->sessionIdLen);
		c += ssl->sessionIdLen;
#ifdef USE_MATRIXSSL_STATS
		matrixsslUpdateStat(ssl, RESUMPTIONS_STAT, 1);
#endif			
	}
/*
	Write out the length and ciphers we support
	Client can request a single specific cipher in the cipherSpec param
*/
	if (cipherSpecLen == 0 || cipherSpecs == NULL || cipherSpecs[0] == 0) {
		if ((rc = sslGetCipherSpecList(ssl, c, (int32)(end - c), addScsv)) < 0){
			return SSL_FULL;
		}
		c += rc;
	} else {
		if ((int32)(end - c) < cipherLen) {
			return SSL_FULL;
		}
		cipherLen -= 2; /* don't include yourself */
		*c = (cipherLen & 0xFF00) >> 8; c++;
		*c = cipherLen & 0xFF; c++;
		/* Safe to include all cipher suites in the list because they were
			checked above */
		for (i = 0; i < cipherSpecLen; i++) {
			*c = (cipherSpecs[i] & 0xFF00) >> 8; c++;
			*c = cipherSpecs[i] & 0xFF; c++;
		}
#ifdef ENABLE_SECURE_REHANDSHAKES
		if (addScsv == 1) {
			*c = ((TLS_EMPTY_RENEGOTIATION_INFO_SCSV & 0xFF00) >> 8); c++;
			*c = TLS_EMPTY_RENEGOTIATION_INFO_SCSV  & 0xFF; c++;
		}
#endif			
	}	
/*
	Compression.  Length byte and 0 for 'none' and possibly 1 for zlib
*/
#ifdef USE_ZLIB_COMPRESSION
	*c = 2; c++;
	*c = 0; c++;
	*c = 1; c++;
#else
	*c = 1; c++;
	*c = 0; c++;
#endif	
	
/*
	Extensions
*/
	if (extLen > 0) {
		extLen -= 2; /* Don't include yourself in the length */
		*c = (extLen & 0xFF00) >> 8; c++; /* Total list length */
		*c = extLen & 0xFF; c++;

		/*	User-provided extensions.  Do them first in case something
			like a ServerNameIndication is here that will influence a
			later extension such as the sigHashAlgs */
		if (userExt) {
			ext = userExt;
			while (ext) {
				*c = (ext->extType & 0xFF00) >> 8; c++;
				*c = ext->extType & 0xFF; c++;
			
				*c = (ext->extLen & 0xFF00) >> 8; c++;
				*c = ext->extLen & 0xFF; c++;
				if (ext->extLen == 1 && ext->extData == NULL) {
					memset(c, 0x0, 1);
				} else {
					memcpy(c, ext->extData, ext->extLen);
				}
				c += ext->extLen;
				ext = ext->next;
			}
		}
		
		/* Max fragment extension */
		if (ssl->maxPtFrag == 0XFF) {
			*c = 0x00; c++;
			*c = 0x01; c++;
			*c = 0x00; c++;
			*c = 0x01; c++;
			if (REQUESTED_MAX_PLAINTEXT_RECORD_LEN == 0x200) {
				*c = 0x01; c++;
			} else if (REQUESTED_MAX_PLAINTEXT_RECORD_LEN == 0x400) {
				*c = 0x02; c++;
			} else if (REQUESTED_MAX_PLAINTEXT_RECORD_LEN == 0x800) {
				*c = 0x03; c++;
			} else if (REQUESTED_MAX_PLAINTEXT_RECORD_LEN == 0x1000) {
				*c = 0x04; c++;
			}
		}
#ifdef ENABLE_SECURE_REHANDSHAKES	
/*
		Populated RenegotiationInfo extension
*/
		if (ssl->myVerifyDataLen > 0) {
			*c = (EXT_RENEGOTIATION_INFO & 0xFF00) >> 8; c++;
			*c = EXT_RENEGOTIATION_INFO & 0xFF; c++;
			*c = ((ssl->myVerifyDataLen + 1) & 0xFF00) >> 8; c++;
			*c = (ssl->myVerifyDataLen + 1) & 0xFF; c++;
			*c = ssl->myVerifyDataLen & 0xFF; c++;
			memcpy(c, ssl->myVerifyData, ssl->myVerifyDataLen);
			c += ssl->myVerifyDataLen;
		}
#endif /* ENABLE_SECURE_REHANDSHAKES */	

#ifdef USE_ECC_CIPHER_SUITE
		if (curveListLen > 0) {
			*c = (ELLIPTIC_CURVE_EXT & 0xFF00) >> 8; c++;
			*c = ELLIPTIC_CURVE_EXT & 0xFF; c++;
			*c = ((curveListLen + 2) & 0xFF00) >> 8; c++;
			*c = (curveListLen + 2) & 0xFF; c++;
			*c = (curveListLen & 0xFF00) >> 8; c++;
			*c = curveListLen & 0xFF; c++;
			memcpy(c, eccCurveList, curveListLen);
			c += curveListLen;
			
			*c = (ELLIPTIC_POINTS_EXT & 0xFF00) >> 8; c++;
			*c = ELLIPTIC_POINTS_EXT & 0xFF; c++;
			*c = 0x00; c++;
			*c = 0x02; c++;
			*c = 0x01; c++;
			*c = 0x00; c++;
		}
#endif /* USE_ECC_CIPHER_SUITE */

#ifdef USE_TLS_1_2
		/* Will always exist in some form if TLS 1.2 is enabled */
		*c = (EXT_SIGNATURE_ALGORITHMS & 0xFF00) >> 8; c++;
		*c = EXT_SIGNATURE_ALGORITHMS & 0xFF; c++;
		*c = (sigHashLen & 0xFF00) >> 8; c++;
		*c = sigHashLen & 0xFF; c++;
		memcpy(c, sigHash, sigHashLen);
		c += sigHashLen;
#endif

#ifdef USE_STATELESS_SESSION_TICKETS
		/* If ticket exists and is marked "USING" then it can be used */
		if (ssl->sid) {
			if (ssl->sid->sessionTicketLen == 0 ||
				ssl->sid->sessionTicketFlag != SESS_TICKET_FLAG_USING_TICKET) {
				
				*c = (SESSION_TICKET_EXT & 0xFF00) >> 8; c++;
				*c = SESSION_TICKET_EXT & 0xFF; c++;
				*c = 0x00; c++;
				*c = 0x00; c++;
				ssl->sid->sessionTicketFlag = SESS_TICKET_FLAG_SENT_EMPTY;
			} else {
				*c = (SESSION_TICKET_EXT & 0xFF00) >> 8; c++;
				*c = SESSION_TICKET_EXT & 0xFF; c++;
				*c = (ssl->sid->sessionTicketLen & 0xFF00) >> 8; c++;
				*c = ssl->sid->sessionTicketLen & 0xFF; c++;
				memcpy(c, ssl->sid->sessionTicket, ssl->sid->sessionTicketLen);
				c += ssl->sid->sessionTicketLen;
				ssl->sid->sessionTicketFlag = SESS_TICKET_FLAG_SENT_TICKET;
#ifdef USE_MATRIXSSL_STATS
				matrixsslUpdateStat(ssl, RESUMPTIONS_STAT, 1);
#endif
			}
		}
#endif /* USE_STATELESS_SESSION_TICKETS	*/

#ifdef USE_TRUNCATED_HMAC
		*c = (EXT_TRUNCATED_HMAC & 0xFF00) >> 8; c++;
		*c = EXT_TRUNCATED_HMAC & 0xFF; c++;
		*c = 0x00; c++;
		*c = 0x00; c++;
#endif

	}
	

	if ((rc = encryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE, messageSize,
			padLen, encryptStart, out, &c)) < 0) {
		return rc;
	}
	out->end = c;

/*
	Could be a rehandshake so clean	up old context if necessary.
	Always explicitly set state to beginning.  
*/
	if (ssl->hsState == SSL_HS_DONE) {
		sslResetContext(ssl);
	}

/*
	Could be a rehandshake on a previous connection that used client auth.
	Reset our local client auth state as the server is always the one
	responsible for initiating it.
*/
	ssl->flags &= ~SSL_FLAGS_CLIENT_AUTH;
	ssl->hsState = SSL_HS_SERVER_HELLO;
	
#ifdef USE_MATRIXSSL_STATS
	matrixsslUpdateStat(ssl, CH_SENT_STAT, 1);
#endif
	return MATRIXSSL_SUCCESS;
}

/******************************************************************************/
/*
	Write a ClientKeyExchange message.
*/
static int32 writeClientKeyExchange(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char	*c, *end, *encryptStart;
	char			padLen;
	int32			messageSize, explicitLen, rc;
	uint32			keyLen;
#ifdef USE_PSK_CIPHER_SUITE
	unsigned char	*pskId, *pskKey;
	uint32			pskIdLen;
#endif /* USE_PSK_CIPHER_SUITE */
	void			*pkiData = NULL;
#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_ECC_CIPHER_SUITE) || defined(USE_RSA_CIPHER_SUITE)
	psPool_t		*pkiPool = NULL;
#endif /* USE_ECC_CIPHER_SUITE || USE_RSA_CIPHER_SUITE */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

	psTraceHs("<<< Client creating CLIENT_KEY_EXCHANGE message\n");

	c = out->end;
	end = out->buf + out->size;
	messageSize = keyLen = 0;


#ifdef USE_PSK_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
/*
		Get the key id to send in the clientKeyExchange message.
*/
		if (matrixSslPskGetKeyId(ssl, &pskId, &pskIdLen,
				ssl->sec.hint, ssl->sec.hintLen) < 0) {
			psFree(ssl->sec.hint); ssl->sec.hint = NULL;
			return MATRIXSSL_ERROR;
		}
		psFree(ssl->sec.hint); ssl->sec.hint = NULL;

	}
#endif /* USE_PSK_CIPHER_SUITE */

/*
	Determine messageSize for the record header
*/
#ifdef USE_DHE_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
#ifdef USE_ECC_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
			keyLen = (ssl->sec.eccKeyPriv->dp->size * 2) + 2;
		} else {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef REQUIRE_DH_PARAMS
			keyLen += ssl->sec.dhKeyPriv.size;
#endif /* REQUIRE_DH_PARAMS */
#ifdef USE_ECC_CIPHER_SUITE
		}
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
/*
		Leave keyLen as the native DH or RSA key to keep the write
		logic untouched below.  Just directly increment the messageSize
		for the PSK id information
*/
		/* DHE_PSK suites */
		if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
			messageSize += pskIdLen + 2;
		}
#endif /* USE_PSK_CIPHER_SUITE */
	} else {
#endif /* USE_DHE_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
		/* basic PSK suites */
		if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
			messageSize += pskIdLen; /* don't need the +2 */
		} else {
#endif /* USE_PSK_CIPHER_SUITE */
#ifndef USE_ONLY_PSK_CIPHER_SUITE
#ifdef USE_ECC_CIPHER_SUITE
		if (ssl->cipher->type == CS_ECDH_ECDSA ||
				ssl->cipher->type == CS_ECDH_RSA) {
			keyLen = (ssl->sec.cert->publicKey.key->ecc.dp->size * 2) + 2;
		} else {
#endif /* USE_ECC_CIPHER_SUITE */		
			/* Standard RSA auth suites */
			keyLen = ssl->sec.cert->publicKey.keysize;
#ifdef USE_ECC_CIPHER_SUITE
		}
#endif /* USE_ECC_CIPHER_SUITE */				
#endif /* !USE_PSK_CIPHER_SUITE */			
#ifdef USE_PSK_CIPHER_SUITE
		}
#endif /* USE_PSK_CIPHER_SUITE */
#ifdef USE_DHE_CIPHER_SUITE
	}
#endif /* USE_DHE_CIPHER_SUITE */

	messageSize += ssl->recordHeadLen + ssl->hshakeHeadLen + keyLen;
	explicitLen = 0;
#ifdef USE_TLS
	/*	Must always add the key size length to the message */
	if (ssl->flags & SSL_FLAGS_TLS) {
		messageSize += 2;
		explicitLen = 1;		
	}
#endif /* USE_TLS */

#ifdef USE_DHE_CIPHER_SUITE
	/*	DHE must include the explicit key size regardless of protocol */
	if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {
		if (explicitLen == 0) {
			messageSize += 2;
			explicitLen = 1;
		}
	}
#endif /* USE_DHE_CIPHER_SUITE */

#ifdef USE_PSK_CIPHER_SUITE
	/* Standard PSK suite in SSLv3 will not have accounted for +2 yet */
	if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
		if (explicitLen == 0) {
			messageSize += 2;
			explicitLen = 1;
		}
	}
#endif

#ifdef USE_ECC_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
		if (explicitLen == 1) { 
			messageSize -= 2; /* For some reason, ECC CKE doesn't use 2 len */
			explicitLen = 0;
		}
	}
#endif /* USE_ECC_CIPHER_SUITE */

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_CLIENT_KEY_EXCHANGE, &messageSize, &padLen,
			&encryptStart, &end, &c)) < 0) {
		return rc;
	}
		
/*
	ClientKeyExchange message contains the encrypted premaster secret.
	The base premaster is the original SSL protocol version we asked for
	followed by 46 bytes of random data.
	These 48 bytes are padded to the current RSA key length and encrypted
	with the RSA key.
*/
	if (explicitLen == 1) {
#ifdef USE_PSK_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
			*c = (pskIdLen & 0xFF00) >> 8; c++;
			*c = (pskIdLen & 0xFF); c++;
/*
			The cke message begins with the ID of the desired key
*/
			memcpy(c, pskId, pskIdLen);
			c += pskIdLen;
		}
#endif /* USE_PSK_CIPHER_SUITE */
/*
		Add the two bytes of key length
*/
		if (keyLen > 0) {
			*c = (keyLen & 0xFF00) >> 8; c++;
			*c = (keyLen & 0xFF); c++;
		}
	}



#ifdef USE_DHE_CIPHER_SUITE
	if (ssl->flags & SSL_FLAGS_DHE_KEY_EXCH) {

#ifdef USE_ECC_CIPHER_SUITE
		if (ssl->flags & SSL_FLAGS_ECC_CIPHER) {
			keyLen--;
			*c = keyLen & 0xFF; c++;
			if (psEccX963ExportKey(ssl->hsPool, ssl->sec.eccKeyPriv, c,
					&keyLen) < 0) {
				return MATRIXSSL_ERROR;	
			}
			psAssert(keyLen == (uint32)*(c - 1));
			c += keyLen;
/*
			Generate premaster and free ECC key material
*/
			ssl->sec.premasterSize = ssl->sec.eccKeyPriv->dp->size;
			ssl->sec.premaster = psMalloc(ssl->hsPool, ssl->sec.premasterSize);
			if (ssl->sec.premaster == NULL) {
				return SSL_MEM_ERROR;
			}
			if (psEccGenSharedSecret(ssl->sec.eccDhKeyPool, ssl->sec.eccKeyPriv,
					ssl->sec.eccKeyPub, ssl->sec.premaster,
					&ssl->sec.premasterSize, pkiData) < 0) {
				psFree(ssl->sec.premaster);
				ssl->sec.premaster = NULL;
				return MATRIXSSL_ERROR;				  
			}
			psEccFreeKey(&ssl->sec.eccKeyPub);
			psEccFreeKey(&ssl->sec.eccKeyPriv);
		} else {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef REQUIRE_DH_PARAMS
/*
		For DH, the clientKeyExchange message is simply the public
		key for this client.  No public/private encryption here
		because there is no authentication (so not necessary or
		meaningful to activate public cipher).
			 
		Pull the public portion of our key into the message
*/
		if (psDhExportPubKey(ssl->hsPool, &ssl->sec.dhKeyPriv, &c) < 0) {
			return MATRIXSSL_ERROR;
		}
		c += keyLen;
/*
		Finished with our portion of the key exchange now.  Go ahead
		and generate the premaster secret and free the key material
		we no longer need to access
*/
		if (psDhGenSecret(ssl->sec.dhKeyPool, &ssl->sec.dhKeyPriv,
				&ssl->sec.dhKeyPub,	ssl->sec.dhP, ssl->sec.dhPLen,
				ssl->sec.premaster, &ssl->sec.premasterSize, pkiData) < 0) {
			return MATRIXSSL_ERROR;
		}
		psFree(ssl->sec.dhP); ssl->sec.dhP = NULL; ssl->sec.dhPLen = 0;
		psDhFreeKey(&ssl->sec.dhKeyPub);
		psDhFreeKey(&ssl->sec.dhKeyPriv);

#endif /* REQUIRE_DH_PARAMS	*/
#ifdef USE_ECC_CIPHER_SUITE
		}
#endif /* USE_ECC_CIPHER_SUITE */

#ifdef USE_PSK_CIPHER_SUITE
/*
		Create the premaster secret for DHE_PSK ciphers
*/
		if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
/*
			RFC4279: The premaster secret is formed as follows. 
			First, perform the Diffie-Hellman computation in the same way
			as for other Diffie-Hellman-based ciphersuites.  Let Z be the
			value produced by this computation.  Concatenate a uint16
			containing the length of Z (in octets), Z itself, a uint16
			containing the length of the PSK (in octets), and the PSK itself.
*/
			matrixSslPskGetKey(ssl, pskId, pskIdLen, &pskKey, &pskIdLen);
			if (pskKey == NULL) {
				psFree(ssl->sec.premaster); ssl->sec.premaster = NULL;
				return MATRIXSSL_ERROR;
			}
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
				(pskIdLen & 0xFF00) >> 8;
			ssl->sec.premaster[ssl->sec.premasterSize + 3] = (pskIdLen & 0xFF);
			memcpy(&ssl->sec.premaster[ssl->sec.premasterSize + 4], pskKey,
				pskIdLen);
/*
			Lastly, adjust the premasterSize
*/
			ssl->sec.premasterSize += pskIdLen + 4;
		}
#endif /* USE_PSK_CIPHER_SUITE */

	} else {
#endif /* USE_DHE_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
/*
		Create the premaster for basic PSK suites
*/
		if (ssl->flags & SSL_FLAGS_PSK_CIPHER) {
/*
			RFC4279: The premaster secret is formed as follows: if the PSK is
			N octets long, concatenate a uint16 with the value N, N zero octets,
			a second uint16 with the value N, and the PSK itself.
*/
			matrixSslPskGetKey(ssl, pskId, pskIdLen, &pskKey, &pskIdLen);
			if (pskKey == NULL) {
				return MATRIXSSL_ERROR;
			}
			ssl->sec.premasterSize = (pskIdLen * 2) + 4;
			ssl->sec.premaster = psMalloc(ssl->hsPool, ssl->sec.premasterSize);
			if (ssl->sec.premaster == NULL) {
				return SSL_MEM_ERROR;
			}
			memset(ssl->sec.premaster, 0, ssl->sec.premasterSize);
			ssl->sec.premaster[0] = (pskIdLen & 0xFF00) >> 8;
			ssl->sec.premaster[1] = (pskIdLen & 0xFF);
			/* memset to 0 handled middle portion */
			ssl->sec.premaster[2 + pskIdLen] = (pskIdLen & 0xFF00) >> 8;
			ssl->sec.premaster[3 + pskIdLen] = (pskIdLen & 0xFF);
			memcpy(&ssl->sec.premaster[4 + pskIdLen], pskKey, pskIdLen); 

		} else {
#endif /* USE_PSK_CIPHER_SUITE */
#ifndef USE_ONLY_PSK_CIPHER_SUITE
#ifdef USE_ECC_CIPHER_SUITE
			if (ssl->cipher->type == CS_ECDH_ECDSA ||
					ssl->cipher->type == CS_ECDH_RSA) {
					
				if (psEccMakeKeyEx(pkiPool, &ssl->sec.eccKeyPriv, 
						ssl->sec.cert->publicKey.key->ecc.dp, pkiData) < 0) {
					psEccFreeKey(&ssl->sec.eccKeyPriv);
					psTraceInfo("psEccMakeKeyEx failed\n");
					ssl->err = SSL_ALERT_INTERNAL_ERROR;
					return MATRIXSSL_ERROR;				   
				}
			
				keyLen--;
				*c = keyLen & 0xFF; c++;
				if (psEccX963ExportKey(ssl->hsPool, ssl->sec.eccKeyPriv, c,
						&keyLen) < 0) {
					psEccFreeKey(&ssl->sec.eccKeyPriv);
					return MATRIXSSL_ERROR;	
				}
				psAssert(keyLen == (uint32)*(c - 1));
				c += keyLen;
/*
				Generate premaster and free ECC key material
*/
				ssl->sec.premasterSize = ssl->sec.eccKeyPriv->dp->size;
				ssl->sec.premaster = psMalloc(ssl->hsPool,
					ssl->sec.premasterSize);
				if (ssl->sec.premaster == NULL) {
					psEccFreeKey(&ssl->sec.eccKeyPriv);
					return SSL_MEM_ERROR;
				}
				if (psEccGenSharedSecret(pkiPool, ssl->sec.eccKeyPriv,
						&ssl->sec.cert->publicKey.key->ecc, ssl->sec.premaster,
						&ssl->sec.premasterSize, pkiData) < 0) {
					psFree(ssl->sec.premaster);
					ssl->sec.premaster = NULL;
					psEccFreeKey(&ssl->sec.eccKeyPriv);
					return MATRIXSSL_ERROR;				  
				}
				psEccFreeKey(&ssl->sec.eccKeyPriv);
			} else {
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef USE_RSA_CIPHER_SUITE		
/*
			Standard RSA suite
*/
			ssl->sec.premasterSize = SSL_HS_RSA_PREMASTER_SIZE;
			ssl->sec.premaster = psMalloc(ssl->hsPool,
										  SSL_HS_RSA_PREMASTER_SIZE);
			if (ssl->sec.premaster == NULL) {
				return SSL_MEM_ERROR;
			}							  
/* #define FAKE_CLIENT_KEY_EXCHANGE */
			ssl->sec.premaster[0] = ssl->reqMajVer;
			ssl->sec.premaster[1] = ssl->reqMinVer;
			if (matrixSslGetPrngData(ssl->sec.premaster + 2,
					SSL_HS_RSA_PREMASTER_SIZE - 2) < 0) {
				return MATRIXSSL_ERROR;
			}
			if (csRsaEncryptPub(pkiPool, &ssl->sec.cert->publicKey,
					ssl->sec.premaster, ssl->sec.premasterSize, c,
					(uint32)(end - c), pkiData) != (int32)keyLen) {
				return MATRIXSSL_ERROR;
			}
			c += keyLen;
#else /* RSA is the 'default' so if that didn't get hit there is a problem */
		psTraceInfo("There is no handler for writeClientKeyExchange.  ERROR\n");
		return MATRIXSSL_ERROR;
#endif /* USE_RSA_CIPHER_SUITE */		
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */
		
#ifdef USE_ECC_CIPHER_SUITE
			}
#endif /* USE_ECC_CIPHER_SUITE */
#ifdef USE_PSK_CIPHER_SUITE
		}
#endif /* USE_PSK_CIPHER_SUITE */
#ifdef USE_DHE_CIPHER_SUITE
	}
#endif /* USE_DHE_CIPHER_SUITE */

	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_CLIENT_KEY_EXCHANGE, messageSize, padLen, encryptStart, out,
			&c)) < 0) {
		return rc;
	}

/*
	Now that we've got the premaster secret, derive the various symmetric
	keys using it and the client and server random values
*/
	if ((rc = sslCreateKeys(ssl)) < 0) {
		return rc;
	}

	out->end = c;
	return MATRIXSSL_SUCCESS;
}

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#ifdef USE_CLIENT_AUTH
/******************************************************************************/
/*	Postponed CERTIFICATE_VERIFY PKA operation */
static int32 nowDoCvPka(ssl_t *ssl)
{
	pkaAfter_t		*pka;
	unsigned char	msgHash[SHA384_HASH_SIZE];
#ifdef USE_ECC
	int32			rc;
#endif
	psPool_t	*pkiPool = NULL;

	pka = &ssl->pkaAfter;


	/* Does a smart default hash automatically for us */
	sslSnapshotHSHash(ssl, msgHash, -1);
	
#ifdef USE_ECC
	if (pka->type == PKA_AFTER_ECDSA_SIG_GEN) {
		
		
#ifdef USE_TLS_1_2
		/* Tweak if needed */
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			if (pka->inlen == SHA1_HASH_SIZE) {
				sslSha1SnapshotHSHash(ssl, msgHash);
			} else if (pka->inlen == SHA384_HASH_SIZE) {
				sslSha384SnapshotHSHash(ssl, msgHash);
			}
			
			/* TODO: save aside a real 'size' instead of fake 1024? */
			if (psEccSignHash(pkiPool, msgHash, pka->inlen, pka->outbuf,
					1024, &ssl->keys->privKey->key->ecc, &rc, 1,
					pka->data) != 0) {
				return MATRIXSSL_ERROR;
			}
				
		} else {
			if (psEccSignHash(pkiPool, msgHash + MD5_HASH_SIZE,
					SHA1_HASH_SIZE, pka->outbuf, 1024,
					&ssl->keys->privKey->key->ecc, &rc, 1, pka->data) != 0) {
				return MATRIXSSL_ERROR;
			}
		}
#else /* USE_TLS_1_2 */		
			/* The ECDSA signature is always done over a SHA1 hash so we need
			to skip over the first 16 bytes of MD5 that the SSL hash stores */		
			if (psEccSignHash(pkiPool, msgHash + MD5_HASH_SIZE,
					SHA1_HASH_SIZE, pka->outbuf, 1024,
					&ssl->keys->privKey->key->ecc, &rc, 1, pka->data) != 0) {
				return MATRIXSSL_ERROR;
			}
#endif /* USE_TLS_1_2 */
	} else {
#endif /* USE_ECC */		

#ifdef USE_RSA
#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			/*	RFC:  "The hash and signature algorithms used in the
				signature MUST be one of those present in the
				supported_signature_algorithms field of the
				CertificateRequest message.  In addition, the hash and
				signature algorithms MUST be compatible with the key in the
				client's end-entity certificate.
						  
				We've done the above tests in the parse of the
				CertificateRequest message and wouldn't be here if our
				certs didn't match the sigAlgs.  However, we do have
				to test for both sig algorithm types here to find the
				hash strength because the sig alg might not match the
				pubkey alg.  This was also already confirmed in
				CertRequest parse so wouldn't be here if not allowed */
			if (pka->inlen == SHA1_HASH_SIZE) {
				sslSha1SnapshotHSHash(ssl, msgHash);
			} else if (pka->inlen == SHA256_HASH_SIZE) {
#ifdef USE_SHA384
			} else if (pka->inlen == SHA384_HASH_SIZE) {
				sslSha384SnapshotHSHash(ssl, msgHash);
#endif /* USE_SHA384 */
			} 
			
			/* The signed element is not the straight hash */
			if (privRsaEncryptSignedElement(pkiPool, ssl->keys->privKey,
					msgHash, pka->inlen, pka->outbuf,
					ssl->keys->privKey->keysize, pka->data) < 0) {
				return MATRIXSSL_ERROR;
			}

		} else {
			if (csRsaEncryptPriv(pkiPool, ssl->keys->privKey, msgHash,
					pka->inlen, pka->outbuf, ssl->keys->privKey->keysize,
					pka->data) < 0) {
				return MATRIXSSL_ERROR;

			}
		}
#else /* ! USE_TLS_1_2 */
		if (csRsaEncryptPriv(pkiPool, ssl->keys->privKey, msgHash,
				pka->inlen, pka->outbuf, ssl->keys->privKey->keysize,
				pka->data) < 0) {
			return MATRIXSSL_ERROR;
		}
#endif /* USE_TLS_1_2 */



#else /* RSA is the 'default' so if that didn't get hit there is a problem */
		psTraceInfo("There is no handler for writeCertificateVerify.  ERROR\n");
		return MATRIXSSL_ERROR;
#endif /* USE_RSA */
#ifdef USE_ECC
	} /* Closing type test */
#endif /* USE_ECC */
	
	
	return PS_SUCCESS;
}

/******************************************************************************/
/*
	Write the CertificateVerify message (client auth only)
	The message contains the signed hash of the handshake messages.
	
	The PKA operation is delayed
*/
static int32 writeCertificateVerify(ssl_t *ssl, sslBuf_t *out)
{
	unsigned char	*c, *end, *encryptStart;
	char			padLen;
	int32			messageSize, hashSize, rc;
	void			*pkiData = NULL;

	psTraceHs("<<< Client creating CERTIFICATE_VERIFY  message\n");
	c = out->end;
	end = out->buf + out->size;


	messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
		2 + ssl->keys->privKey->keysize;
		
#ifdef USE_ECC
	/* Additional ASN.1 overhead from psEccSignHash */
	if (ssl->keys->cert->pubKeyAlgorithm == OID_ECDSA_KEY_ALG) {
		messageSize += 6;
		if (ssl->keys->privKey->keysize >= 128) {
			messageSize++; /* Extra byte for 'long' asn.1 encode */
		}
	}
#endif /* USE_ECC */

#ifdef USE_TLS_1_2
/*	RFC: "This is the concatenation of all the
	Handshake structures (as defined in Section 7.4) exchanged thus
	far.  Note that this requires both sides to either buffer the
	messages or compute running hashes for all potential hash
	algorithms up to the time of the CertificateVerify computation.
	Servers can minimize this computation cost by offering a
	restricted set of digest algorithms in the CertificateRequest
	message."
				
	We're certainly not	going to buffer the messages so the
	handshake hash update and snapshot functions have to keep the
	running total.  Not a huge deal for the updating but
	the current snapshot framework didn't support this so there
	are one-off algorithm specific snapshots where needed. */
	if (ssl->flags & SSL_FLAGS_TLS_1_2) {
		messageSize += 2; /* hashSigAlg */
	}
#endif	
	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_CERTIFICATE_VERIFY, &messageSize, &padLen,
			&encryptStart, &end, &c)) < 0) {
		return rc;
	}
	
/*
	Correct to be looking at the child-most cert here because that is the
	one associated with the private key.  
*/
#ifdef USE_ECC
	if (ssl->keys->cert->pubKeyAlgorithm == OID_ECDSA_KEY_ALG) {
		hashSize = MD5_HASH_SIZE + SHA1_HASH_SIZE;
#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			/*	RFC:  "The hash and signature algorithms used in the
				signature MUST be one of those present in the
				supported_signature_algorithms field of the
				CertificateRequest message.  In addition, the hash and
				signature algorithms MUST be compatible with the key in the
				client's end-entity certificate."
						  
				We've done the above tests in the parse of the
				CertificateRequest message and wouldn't be here if our
				certs didn't match the sigAlgs.  However, we do have
				to test for both sig algorithm types here to find the
				hash strength because the sig alg might not match the
				pubkey alg.  This was also already confirmed in
				CertRequest parse so wouldn't be here if not allowed */
			if ((ssl->keys->cert->sigAlgorithm == OID_SHA1_ECDSA_SIG) ||
					(ssl->keys->cert->sigAlgorithm == OID_SHA1_RSA_SIG)) {
				*c = 0x2; c++; /* SHA1 */
				*c = 0x3; c++; /* ECDSA */
				hashSize = SHA1_HASH_SIZE;
			} else if ((ssl->keys->cert->sigAlgorithm ==
					OID_SHA256_ECDSA_SIG) || (ssl->keys->cert->sigAlgorithm
					== OID_SHA256_RSA_SIG)) {
				*c = 0x4; c++; /* SHA256 */
				*c = 0x3; c++; /* ECDSA */
				hashSize = SHA256_HASH_SIZE;
#ifdef USE_SHA384					
			} else if ((ssl->keys->cert->sigAlgorithm ==
					OID_SHA384_ECDSA_SIG) || (ssl->keys->cert->sigAlgorithm
					== OID_SHA384_RSA_SIG)) {
				*c = 0x5; c++; /* SHA384 */
				*c = 0x3; c++; /* ECDSA */
				hashSize = SHA384_HASH_SIZE;
#endif					
			} else {
				psTraceInfo("Need more hash support for certVerify\n");
				return MATRIXSSL_ERROR;
			}
		}
#endif /* USE_TLS_1_2 */

		ssl->pkaAfter.inlen = hashSize;
		ssl->pkaAfter.type = PKA_AFTER_ECDSA_SIG_GEN;
		ssl->pkaAfter.data = pkiData;
		ssl->pkaAfter.outbuf = c;
		rc = ssl->keys->privKey->keysize + 8;
		if (ssl->keys->privKey->keysize - 3 >= 128) {
			rc++;
		}
		c += rc;
	} else {
#endif /* USE_ECC */		

#ifdef USE_RSA
		hashSize = MD5_HASH_SIZE + SHA1_HASH_SIZE;
#ifdef USE_TLS_1_2
		if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			/*	RFC:  "The hash and signature algorithms used in the
				signature MUST be one of those present in the
				supported_signature_algorithms field of the
				CertificateRequest message.  In addition, the hash and
				signature algorithms MUST be compatible with the key in the
				client's end-entity certificate.
						  
				We've done the above tests in the parse of the
				CertificateRequest message and wouldn't be here if our
				certs didn't match the sigAlgs.  However, we do have
				to test for both sig algorithm types here to find the
				hash strength because the sig alg might not match the
				pubkey alg.  This was also already confirmed in
				CertRequest parse so wouldn't be here if not allowed */
			if (ssl->keys->cert->sigAlgorithm == OID_SHA1_RSA_SIG ||
					ssl->keys->cert->sigAlgorithm == OID_MD5_RSA_SIG ||
					ssl->keys->cert->sigAlgorithm == OID_SHA1_ECDSA_SIG) {
				*c = 0x2; c++; /* SHA1 */
				*c = 0x1; c++; /* RSA */
				hashSize = SHA1_HASH_SIZE;
			} else if (ssl->keys->cert->sigAlgorithm == OID_SHA256_RSA_SIG ||
					ssl->keys->cert->sigAlgorithm == OID_SHA256_ECDSA_SIG) {
				*c = 0x4; c++; /* SHA256 */
				*c = 0x1; c++; /* RSA */
				/* Normal handshake hash uses SHA256 and has been done above */
				hashSize = SHA256_HASH_SIZE;
#ifdef USE_SHA384
			} else if (ssl->keys->cert->sigAlgorithm == OID_SHA384_RSA_SIG ||
					ssl->keys->cert->sigAlgorithm == OID_SHA384_ECDSA_SIG) {
				*c = 0x5; c++; /* SHA384 */
				*c = 0x1; c++; /* RSA */
				hashSize = SHA384_HASH_SIZE;
#endif /* USE_SHA384 */
			} else {
				psTraceInfo("Need additional hash support for certVerify\n");
				return MATRIXSSL_ERROR;
			}

			ssl->pkaAfter.type = PKA_AFTER_RSA_SIG_GEN_ELEMENT;
		} else {	
			ssl->pkaAfter.type = PKA_AFTER_RSA_SIG_GEN;
		}
#else /* ! USE_TLS_1_2 */
		ssl->pkaAfter.type = PKA_AFTER_RSA_SIG_GEN;
#endif /* USE_TLS_1_2 */

		*c = (ssl->keys->privKey->keysize & 0xFF00) >> 8; c++;
		*c = (ssl->keys->privKey->keysize & 0xFF); c++;
		ssl->pkaAfter.data = pkiData;
		ssl->pkaAfter.inlen = hashSize;
		ssl->pkaAfter.outbuf = c;
		c += ssl->keys->privKey->keysize;
		
#else /* RSA is the 'default' so if that didn't get hit there is a problem */
		psTraceInfo("There is no handler for writeCertificateVerify.  ERROR\n");
		return MATRIXSSL_ERROR;
#endif /* USE_RSA */
#ifdef USE_ECC
	} /* Closing sigAlgorithm test */
#endif /* USE_ECC */
	
	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_CERTIFICATE_VERIFY, messageSize,	padLen, encryptStart, out,
			&c)) < 0) {
		return rc;
	}
	out->end = c;
	return MATRIXSSL_SUCCESS;
}
#endif /* USE_CLIENT_AUTH */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */

#else /* USE_CLIENT_SIDE_SSL */
/******************************************************************************/
/*
	Stub out this function rather than ifdef it out in the public header
*/
int32 matrixSslEncodeClientHello(ssl_t *ssl, sslBuf_t *out, uint32 cipherSpec[],
			uint16 cipherSpecLen, uint32 *requiredLen, tlsExtension_t *userExt)
{
	psTraceInfo("Library not built with USE_CLIENT_SIDE_SSL\n");
	return PS_UNSUPPORTED_FAIL;
}
#endif /* USE_CLIENT_SIDE_SSL */

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
/******************************************************************************/
/*
	Write the CertificateRequest message (client auth only)
	The message contains the list of CAs the server is willing to accept
	children certificates of from the client.
*/
static int32 writeCertificateRequest(ssl_t *ssl, sslBuf_t *out, int32 certLen,
								   int32 certCount)
{
	unsigned char	*c, *end, *encryptStart;
	psX509Cert_t	*cert;
	char			padLen;
	int32			messageSize, rc;
	int32			sigHashLen = 0;


	psTraceHs("<<< Server creating CERTIFICATE_REQUEST message\n");
	c = out->end;
	end = out->buf + out->size;

	messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
		4 + (certCount * 2) + certLen;
#ifdef USE_ECC
	messageSize += 1; /* Adding ECDSA_SIGN type */
#endif /* USE_ECC */

#ifdef USE_TLS_1_2
	if (ssl->flags & SSL_FLAGS_TLS_1_2) {
			/* TLS 1.2 has a SignatureAndHashAlgorithm type after CertType */
		sigHashLen = 2;
#ifdef USE_ECC
#ifdef USE_SHA384			
		sigHashLen += 6;
#else
		sigHashLen += 4;
#endif	/* USE_SHA */
#endif /* USE_ECC */
#ifdef USE_RSA
#ifdef USE_SHA384			
		sigHashLen += 6;
#else
		sigHashLen += 4;
#endif	/* USE_SHA */
#endif /* USE_RSA */
		messageSize += sigHashLen;
	}	
#endif /* TLS_1_2 */

	if ((messageSize - ssl->recordHeadLen) > ssl->maxPtFrag) {
		return writeMultiRecordCertRequest(ssl, out, certLen, certCount,
			sigHashLen);
	}

	if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_CERTIFICATE_REQUEST, &messageSize, &padLen,
			&encryptStart, &end, &c)) < 0) {
		return rc;
	}

#ifdef USE_ECC
	*c++ = 2;
	*c++ = ECDSA_SIGN;
#else
	*c++ = 1;
#endif		
	*c++ = RSA_SIGN;
#ifdef USE_TLS_1_2
	if (ssl->flags & SSL_FLAGS_TLS_1_2) {
		/* RFC: "The interaction of the certificate_types and
		supported_signature_algorithms fields is somewhat complicated.
		certificate_types has been present in TLS since SSLv3, but was
		somewhat underspecified.  Much of its functionality is superseded
		by supported_signature_algorithms."
		
		The spec says the cert must support the hash/sig algorithm but
		it's a bit confusing what this means for the hash portion.
		Just going to use SHA1, SHA256, and SHA384 support.
			
		We're just sending the raw list of all sig algorithms that are
		compiled into the library.  It might be smart to look through the
		individual CA files here only send the pub key operations that
		they use but the CA info is sent explicitly anyway so the client
		can confirm they have a proper match.
			
		If a new algorithm is added here it will require additions to
		messageSize	directly above in this function and in the flight
		calculation in sslEncodeResponse */
		*c++ = 0x0;
		*c++ = sigHashLen - 2;
#ifdef USE_ECC
#ifdef USE_SHA384			
		*c++ = 0x5; /* SHA384 */
		*c++ = 0x3; /* ECDSA */
		*c++ = 0x4; /* SHA256 */
		*c++ = 0x3; /* ECDSA */
		*c++ = 0x2; /* SHA1 */
		*c++ = 0x3; /* ECDSA */
#else
		*c++ = 0x4; /* SHA256 */
		*c++ = 0x3; /* ECDSA */
		*c++ = 0x2; /* SHA1 */
		*c++ = 0x3; /* ECDSA */
#endif	
#endif

#ifdef USE_RSA
#ifdef USE_SHA384			
		*c++ = 0x5; /* SHA384 */
		*c++ = 0x1; /* RSA */
		*c++ = 0x4; /* SHA256 */
		*c++ = 0x1; /* RSA */
		*c++ = 0x2; /* SHA1 */
		*c++ = 0x1; /* RSA */
#else
		*c++ = 0x4; /* SHA256 */
		*c++ = 0x1; /* RSA */
		*c++ = 0x2; /* SHA1 */
		*c++ = 0x1; /* RSA */
#endif	
#endif /* USE_RSA */
	}
#endif /* TLS_1_2 */
	
	cert = ssl->keys->CAcerts;
	if (cert) {
		*c = ((certLen + (certCount * 2))& 0xFF00) >> 8; c++;
		*c = (certLen + (certCount * 2)) & 0xFF; c++;
		while (cert) {
			*c = (cert->subject.dnencLen & 0xFF00) >> 8; c++;
			*c = cert->subject.dnencLen & 0xFF; c++;
			memcpy(c, cert->subject.dnenc, cert->subject.dnencLen);
			c += cert->subject.dnencLen;
			cert = cert->next;
		}
	} else {	
		*c++ = 0; /* Cert len */
		*c++ = 0;
	}
	if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
			SSL_HS_CERTIFICATE_REQUEST, messageSize, padLen, encryptStart, out,
			&c)) < 0) {
		return rc;
	}
	out->end = c;
	return MATRIXSSL_SUCCESS;
}



static int32 writeMultiRecordCertRequest(ssl_t *ssl, sslBuf_t *out,
				int32 certLen, int32 certCount, int32 sigHashLen)
{
	psX509Cert_t	*cert, *future;
	unsigned char	*c, *end, *encryptStart;
	char			padLen;
	int32			messageSize, rc, dnencLen;
	int32			midWrite, midSizeWrite, countDown, firstOne = 1;
	
	c = out->end;
	end = out->buf + out->size;
	
	midSizeWrite = midWrite = 0;
	
	while (certLen > 0) {
		if (firstOne){
			firstOne = 0;
			countDown = ssl->maxPtFrag;
			messageSize = ssl->recordHeadLen + ssl->hshakeHeadLen +
				4 + (certCount * 2) + certLen + sigHashLen;
#ifdef USE_ECC
			messageSize += 1; /* Adding ECDSA_SIGN type */
#endif /* USE_ECC */				
			if ((rc = writeRecordHeader(ssl,
					SSL_RECORD_TYPE_HANDSHAKE_FIRST_FRAG,
					SSL_HS_CERTIFICATE_REQUEST, &messageSize, &padLen,
					&encryptStart, &end, &c)) < 0) {
				return rc;
			}
#ifdef USE_ECC
			*c++ = 2;
			*c++ = ECDSA_SIGN;
			countDown -= 2;
#else
			*c++ = 1;
			countDown--;
#endif		
			*c++ = RSA_SIGN;
			countDown--;
#ifdef USE_TLS_1_2
			if (ssl->flags & SSL_FLAGS_TLS_1_2) {
				*c++ = 0x0;
				*c++ = sigHashLen - 2;
#ifdef USE_ECC
#ifdef USE_SHA384			
				*c++ = 0x5; /* SHA384 */
				*c++ = 0x3; /* ECDSA */
				*c++ = 0x4; /* SHA256 */
				*c++ = 0x3; /* ECDSA */
				*c++ = 0x2; /* SHA1 */
				*c++ = 0x3; /* ECDSA */
#else
				*c++ = 0x4; /* SHA256 */
				*c++ = 0x3; /* ECDSA */
				*c++ = 0x2; /* SHA1 */
				*c++ = 0x3; /* ECDSA */
#endif	
#endif

#ifdef USE_RSA
#ifdef USE_SHA384			
				*c++ = 0x5; /* SHA384 */
				*c++ = 0x1; /* RSA */
				*c++ = 0x4; /* SHA256 */
				*c++ = 0x1; /* RSA */
				*c++ = 0x2; /* SHA1 */
				*c++ = 0x1; /* RSA */
#else
				*c++ = 0x4; /* SHA256 */
				*c++ = 0x1; /* RSA */
				*c++ = 0x2; /* SHA1 */
				*c++ = 0x1; /* RSA */
#endif	
#endif /* USE_RSA */
				countDown -= sigHashLen;
			}
#endif /* TLS_1_2 */
			cert = ssl->keys->CAcerts;
			*c = ((certLen + (certCount * 2))& 0xFF00) >> 8; c++;
			*c = (certLen + (certCount * 2)) & 0xFF; c++;
			countDown -= ssl->hshakeHeadLen + 2;
			while (cert) {
				midWrite = 0;
				dnencLen = cert->subject.dnencLen;
				if (dnencLen > 0) {
					if (countDown < 2) {
						/* Fragment falls right on dn len write.  Has
							to be at least one byte or countDown would have
							been 0 and got us out of here already*/
						*c = (cert->subject.dnencLen & 0xFF00) >> 8; c++;
						midSizeWrite = 1;
						break;
					} else {
						*c = (cert->subject.dnencLen & 0xFF00) >> 8; c++;
						*c = cert->subject.dnencLen & 0xFF; c++;
						countDown -= 2;
					}
					midWrite = min(dnencLen, countDown);
					memcpy(c, cert->subject.dnenc, midWrite);
					dnencLen -= midWrite;
					c += midWrite;
					certLen -= midWrite;
					countDown -= midWrite;
					if (countDown == 0) {
						break;
					}
				}
				cert = cert->next;
			}
			if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
					SSL_HS_CERTIFICATE_REQUEST, messageSize, padLen,
					encryptStart, out, &c)) < 0) {
				return rc;
			}
			out->end = c;
		} else {
			/*	Not-first fragments */
			if (midSizeWrite > 0) {
				messageSize = midSizeWrite;
			} else {
				messageSize = 0;
			}
			if ((certLen + messageSize) > ssl->maxPtFrag) {
				messageSize += ssl->maxPtFrag;
			} else {			
				messageSize += dnencLen;
				if (cert->next != NULL) {
					future = cert->next;
					while (future != NULL) {
						if (messageSize + future->subject.dnencLen + 2 >
								(uint32)ssl->maxPtFrag) {
							messageSize = ssl->maxPtFrag;
							future = NULL;
						} else {
							messageSize += 2 + future->subject.dnencLen;
							future = future->next;
						}
						
					}
				}			
			}
			countDown = messageSize;
			messageSize += ssl->recordHeadLen;
			/* Second, etc... */
			if ((rc = writeRecordHeader(ssl, SSL_RECORD_TYPE_HANDSHAKE_FRAG,
					SSL_HS_CERTIFICATE_REQUEST, &messageSize, &padLen,
					&encryptStart, &end, &c)) < 0) {
				return rc;
			}
			if (midSizeWrite > 0) {
				*c = (dnencLen & 0xFF); c++;
				countDown -= 1;
			}
			midSizeWrite = 0;
			if (countDown < dnencLen) {
				memcpy(c, cert->subject.dnenc + midWrite, countDown);
				dnencLen -= countDown;
				c += countDown;
				certLen -= countDown;
				midWrite += countDown;
				countDown = 0;
			} else {
				memcpy(c, cert->subject.dnenc + midWrite, dnencLen);
				c += dnencLen;
				certLen -= dnencLen;
				countDown -= dnencLen;
				dnencLen -= dnencLen;
			}
			while (countDown > 0) {				
				cert = cert->next;
				dnencLen =  cert->subject.dnencLen;
				midWrite = 0;
				if (countDown < 2) {
					/* Fragment falls right on cert len write */
					*c = (unsigned char)((dnencLen & 0xFF00) >> 8);
					c++; countDown--;
					midSizeWrite = 1;
					break;
				} else {
					*c = (unsigned char)((dnencLen & 0xFF00) >> 8); c++;
					*c = (dnencLen & 0xFF); c++;
					countDown -= 2;
				}
				midWrite = min(dnencLen, countDown);
				memcpy(c, cert->subject.dnenc, midWrite);
				dnencLen -= midWrite;
				c += midWrite;
				certLen -= midWrite;
				countDown -= midWrite;
				if (countDown == 0) {
					break;
				}			
			
			}
			if ((rc = postponeEncryptRecord(ssl, SSL_RECORD_TYPE_HANDSHAKE,
					SSL_HS_CERTIFICATE_REQUEST, messageSize, padLen,
					encryptStart, out, &c)) < 0) {
				return rc;
			}
			out->end = c;

		}
	
	}
	out->end = c;
	return MATRIXSSL_SUCCESS;
}

#endif /* USE_SERVER_SIDE && USE_CLIENT_AUTH */
#endif /* !USE_ONLY_PSK_CIPHER_SUITE */



/******************************************************************************/
/*
	Write out a SSLv3 record header.
	Assumes 'c' points to a buffer of at least SSL3_HEADER_LEN bytes
		1 byte type (SSL_RECORD_TYPE_*)
		1 byte major version
		1 byte minor version
		2 bytes length (network byte order)
	Returns the number of bytes written
*/
int32 psWriteRecordInfo(ssl_t *ssl, unsigned char type, int32 len, 
							   unsigned char *c, int32 hsType)
{
#if defined(USE_TLS_1_2) && defined (USE_AES_GCM)
	int32	gcmWrite = 0;
#endif
	
	if (type == SSL_RECORD_TYPE_HANDSHAKE_FRAG) {
		type = SSL_RECORD_TYPE_HANDSHAKE;
	}
	*c = type; c++;
	*c = ssl->majVer; c++;
	*c = ssl->minVer; c++;
	*c = (len & 0xFF00) >> 8; c++;
	*c = (len & 0xFF);
	
#if defined(USE_TLS_1_2) && defined (USE_AES_GCM)
	if (hsType == SSL_HS_FINISHED) {
		if (ssl->cipher->flags & CRYPTO_FLAGS_GCM) {
			gcmWrite++;
		}
	} else if (ssl->flags & SSL_FLAGS_GMAC_W) {
		gcmWrite++;
	}
	if (gcmWrite) {
		c++;
		ssl->seqDelay = c; /* not being incremented in postpone mechanism */
		*c = ssl->sec.seq[0]; c++;
		*c = ssl->sec.seq[1]; c++;
		*c = ssl->sec.seq[2]; c++;
		*c = ssl->sec.seq[3]; c++;
		*c = ssl->sec.seq[4]; c++;
		*c = ssl->sec.seq[5]; c++;
		*c = ssl->sec.seq[6]; c++;
		*c = ssl->sec.seq[7];
		return ssl->recordHeadLen + 8;
	}
#endif /* USE_TLS_1_2 && AES_GCM */

	return ssl->recordHeadLen;
}

/******************************************************************************/
/*
	Write out an ssl handshake message header.
	Assumes 'c' points to a buffer of at least ssl->hshakeHeadLen bytes
		1 byte type (SSL_HS_*)
		3 bytes length (network byte order)
	Returns the number of bytes written
*/
int32 psWriteHandshakeHeader(ssl_t *ssl, unsigned char type, int32 len, 
								int32 seq, int32 fragOffset, int32 fragLen,
								unsigned char *c)
{
	*c = type; c++;
	*c = (unsigned char)((len & 0xFF0000) >> 16); c++;
	*c = (len & 0xFF00) >> 8; c++;
	*c = (len & 0xFF);

	return ssl->hshakeHeadLen;
}

/******************************************************************************/
/*
	Write pad bytes and pad length per the TLS spec.  Most block cipher
	padding fills each byte with the number of padding bytes, but SSL/TLS
	pretends one of these bytes is a pad length, and the remaining bytes are
	filled with that length.  The end result is that the padding is identical
	to standard padding except the values are one less. For SSLv3 we are not
	required to have any specific pad values, but they don't hurt.

	PadLen	Result
	0
	1		00
	2		01 01
	3		02 02 02
	4		03 03 03 03
	5		04 04 04 04 04
	6		05 05 05 05 05 05
	7		06 06 06 06 06 06 06
	8		07 07 07 07 07 07 07 07
	9		08 08 08 08 08 08 08 08 08
	...
	15		...

	We calculate the length of padding required for a record using
	psPadLenPwr2()
*/
int32 sslWritePad(unsigned char *p, unsigned char padLen)
{
	unsigned char c = padLen;

	while (c-- > 0) {
		*p++ = padLen - 1;
	}
	return padLen;
}

/******************************************************************************/
