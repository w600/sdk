/*
 *	matrixssllib.h
 *	Release $Name: MATRIXSSL-3-6-1-OPEN $
 *
 *	Internal header file used for the MatrixSSL implementation.
 *	Only modifiers of the library should be intersted in this file
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

#ifndef _h_MATRIXSSLLIB
#define _h_MATRIXSSLLIB

#ifdef __cplusplus
extern "C" {
#endif


#ifdef USE_ZLIB_COMPRESSION
#include "zlib.h"
#endif

/* PKCS11 is set in crypto. Use all modes of it if enabled */
#ifdef USE_PKCS11
#define USE_PKCS11_TLS_ALGS
#define USE_PKCS11_TLS_HS_HASH
#define USE_PKCS11_SYMMETRIC
#include "pkcs11.h"

/* SafeZone uses the V (vendor) designation for unratified mechs and params */
#include "pkcs-11-sfzext.h"
#define CK_TLS12_MASTER_KEY_DERIVE_PARAMS CKV_TLS12_MASTER_KEY_DERIVE_PARAMS
#define CK_TLS12_KEY_MAT_PARAMS CKV_TLS12_KEY_MAT_PARAMS
#define CK_TLS12_PRF_PARAMS CKV_TLS12_PRF_PARAMS
#define CK_GCM_PARAMS CKV_GCM_PARAMS

#define CKM_AES_GCM CKMV_AES_GCM
#define CKM_TLS12_PRF CKMV_TLS12_PRF
#define CKM_TLS12_MASTER_KEY_DERIVE CKMV_TLS12_MASTER_KEY_DERIVE
#define CKM_TLS12_MASTER_KEY_DERIVE_DH CKMV_TLS12_MASTER_KEY_DERIVE_DH
#define CKM_TLS12_KEY_AND_MAC_DERIVE CKMV_TLS12_KEY_AND_MAC_DERIVE

#else /* NATIVE */
#define USE_NATIVE_TLS_ALGS
#define USE_NATIVE_TLS_HS_HASH
#define USE_NATIVE_SYMMETRIC
#endif /* PKCS11 or NATIVE */


/*****************************************************************************/
/*
	Start with compile-time checks for the necessary proto and crypto support.
*/ 
#if !defined(USE_TLS) && defined(DISABLE_SSLV3)
#error "Must enable a protocol: USE_TLS enabled or DISABLE_SSLV3 disabled"
#endif


#if defined(USE_TLS_1_1) && !defined(USE_TLS)
#error "Must define USE_TLS if defining USE_TLS_1_1"
#endif

#ifdef USE_TLS
#if !defined(USE_TLS_1_2) && defined(DISABLE_TLS_1_0) && defined(DISABLE_TLS_1_1) && defined(DISABLE_SSLV3)
#error "Bad combination of USE_TLS and DISABLE_TLS"
#endif
#endif

	
/******************************************************************************/
/*
	SHA1 and MD5 are essential elements for SSL key derivation during protocol
*/
#if !defined USE_MD5 || !defined USE_SHA1
#error "Must enable both USE_MD5 and USE_SHA1 in cryptoConfig.h for MatrixSSL"
#endif 

#if !defined USE_CLIENT_SIDE_SSL && !defined USE_SERVER_SIDE_SSL
#error "Must enable either USE_CLIENT_SIDE_SSL or USE_SERVER_SIDE_SSL (or both)"
#endif

#ifdef USE_TLS
	#ifndef USE_HMAC
	#error "Must enable USE_HMAC in cryptoConfig.h for TLS protocol support"
	#endif
#endif

/*
	Handle the various combos of REHANDSHAKES defines
*/
#if defined(ENABLE_INSECURE_REHANDSHAKES) && defined(REQUIRE_SECURE_REHANDSHAKES)
#error "Can't enable both ENABLE_INSECURE_REHANDSHAKES and REQUIRE_SECURE_REHANDSHAKES"
#endif

#if defined(ENABLE_INSECURE_REHANDSHAKES) || defined(ENABLE_SECURE_REHANDSHAKES)
#define SSL_REHANDSHAKES_ENABLED
#endif

#if defined(REQUIRE_SECURE_REHANDSHAKES) && !defined(ENABLE_SECURE_REHANDSHAKES)
#define SSL_REHANDSHAKES_ENABLED
#define ENABLE_SECURE_REHANDSHAKES
#endif

#ifdef USE_STATELESS_SESSION_TICKETS
#ifndef USE_HMAC
#error "Must enable USE_HMAC for USE_STATELESS_SESSION_TICKETS"
#endif
#ifndef USE_SHA256
#error "Must enable USE_SHA256 for USE_STATELESS_SESSION_TICKETS"
#endif
#ifndef USE_AES
#error "Must enable USE_AES for USE_STATELESS_SESSION_TICKETS"
#endif
#endif
/******************************************************************************/
/*
	Test specific crypto features based on which cipher suites are enabled 
*/
#ifdef USE_SSL_RSA_WITH_NULL_MD5
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for SSL_RSA_WITH_NULL_MD5 suite"
	#endif
	#define USE_MD5_MAC
	#define USE_RSA_CIPHER_SUITE
#endif

#ifdef USE_SSL_RSA_WITH_NULL_SHA
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for SSL_RSA_WITH_NULL_SHA suite"
	#endif
	#define USE_SHA_MAC
	#define USE_RSA_CIPHER_SUITE
#endif

#ifdef USE_SSL_RSA_WITH_RC4_128_SHA
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for SSL_RSA_WITH_RC4_128_SHA suite"
	#endif
	#ifndef USE_ARC4
	#error "Enable USE_ARC4 in cryptoConfig.h for SSL_RSA_WITH_RC4_128_SHA suite"
	#endif
	#define USE_SHA_MAC
	#define USE_RSA_CIPHER_SUITE
	#define USE_ARC4_CIPHER_SUITE
#endif

#ifdef USE_SSL_RSA_WITH_RC4_128_MD5
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for SSL_RSA_WITH_RC4_128_MD5 suite"
	#endif
	#ifndef USE_ARC4
	#error "Enable USE_ARC4 in cryptoConfig.h for SSL_RSA_WITH_RC4_128_MD5 suite"
	#endif
	#define USE_MD5_MAC
	#define USE_RSA_CIPHER_SUITE
	#define USE_ARC4_CIPHER_SUITE
#endif

#ifdef USE_SSL_RSA_WITH_3DES_EDE_CBC_SHA
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for SSL_RSA_WITH_3DES_EDE_CBC_SHA"
	#endif
	#ifndef USE_3DES
	#error "Enable USE_3DES in cryptoConfig.h for SSL_RSA_WITH_3DES_EDE_CBC_SHA"
	#endif
	#define USE_SHA_MAC
	#define USE_RSA_CIPHER_SUITE
	#define USE_3DES_CIPHER_SUITE
#endif

#ifdef USE_TLS_RSA_WITH_AES_128_CBC_SHA
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_RSA_WITH_AES_128_CBC_SHA"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_RSA_WITH_AES_128_CBC_SHA"
	#endif
	#define USE_SHA_MAC
	#define USE_AES_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
#endif

#ifdef USE_TLS_RSA_WITH_AES_256_CBC_SHA
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_RSA_WITH_AES_256_CBC_SHA"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_RSA_WITH_AES_256_CBC_SHA"
	#endif
	#define USE_SHA_MAC
	#define USE_AES_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
#endif

/******************************************************************************/

/******************************************************************************/
/*
	Notes on DHE-related defines
		USE_DHE_CIPHER_SUITE is used for SSL state control for ECC or DH ciphers
		USE_ECC_CIPHER_SUITE is a subset of DHE_CIPHER to determine ECC key
		REQUIRE_DH_PARAMS is a subset of DHE_CIPHER to use 'normal' dh params
*/
#ifdef USE_TLS_1_2
#ifndef USE_TLS_1_1
#error "Enable USE_TLS_1_1 in matrixsslConfig.h for TLS_1_2 support"
#endif
#ifndef USE_SHA256
#error "Enable USE_SHA256 in matrixsslConfig.h for TLS_1_2 support"
#endif

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 
	#ifndef USE_AES_GCM
	#error "Enable USE_AES_GCM in cryptoConfig.h for USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	#endif
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	#endif
	#define USE_DHE_CIPHER_SUITE
	#define USE_ECDSA_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	#ifndef USE_AES_GCM
	#error "Enable USE_AES_GCM in cryptoConfig.h for USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifndef USE_SHA384
	#error "Enable USE_SHA384 in cryptoConfig.h for USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	#endif
	#define USE_DHE_CIPHER_SUITE
	#define USE_ECDSA_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_RSA_WITH_AES_128_CBC_SHA256
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_RSA_WITH_AES_128_CBC_SHA256"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_RSA_WITH_AES_128_CBC_SHA256"
	#endif
	#define USE_SHA_MAC
	#define USE_AES_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
#endif

#ifdef USE_TLS_RSA_WITH_AES_256_CBC_SHA256
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_RSA_WITH_AES_256_CBC_SHA256"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_RSA_WITH_AES_256_CBC_SHA256"
	#endif
	#define USE_SHA_MAC
	#define USE_AES_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
#endif

#ifdef USE_TLS_RSA_WITH_AES_256_GCM_SHA384
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_RSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifndef USE_AES_GCM
	#error "Enable USE_AES_GCM in cryptoConfig.h for TLS_RSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifndef USE_SHA384
	#error "Enable USE_SHA384 in cryptoConfig.h for TLS_RSA_WITH_AES_256_GCM_SHA384"
	#endif
	#define USE_AES_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
#endif

#ifdef USE_TLS_RSA_WITH_AES_128_GCM_SHA256
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_RSA_WITH_AES_128_GCM_SHA256"
	#endif
	#ifndef USE_AES_GCM
	#error "Enable USE_AES_GCM in cryptoConfig.h for TLS_RSA_WITH_AES_128_GCM_SHA256"
	#endif
	#define USE_AES_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
#endif

#ifdef USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
	#endif
	#ifndef USE_DH
	#error "Enable USE_DH in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
	#endif
	#define REQUIRE_DH_PARAMS
	#define USE_SHA_MAC
	#define USE_DHE_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
#endif

#ifdef USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
	#endif
	#ifndef USE_DH
	#error "Enable USE_DH in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
	#endif
	#define REQUIRE_DH_PARAMS
	#define USE_SHA_MAC
	#define USE_DHE_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	#endif
	#define USE_SHA_MAC
	#define USE_DHE_CIPHER_SUITE
	#define USE_ECDSA_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
	#endif
	#ifndef USE_SHA384
	#error "Enable USE_SHA384 in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
	#endif
	#define USE_SHA_MAC
	#define USE_DHE_CIPHER_SUITE
	#define USE_ECDSA_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"
	#endif
	#ifndef USE_SHA384
	#error "Enable USE_SHA384 in cryptoConfig.h for USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"
	#endif
	#define USE_SHA_MAC
	#define USE_DH_CIPHER_SUITE
	#define USE_ECDSA_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"
	#endif
	#define USE_SHA_MAC
	#define USE_DH_CIPHER_SUITE
	#define USE_ECDSA_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 
	#ifndef USE_AES_GCM
	#error "Enable USE_AES_GCM in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"
	#endif
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"
	#endif
	#define USE_DH_CIPHER_SUITE
	#define USE_ECDSA_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 
	#ifndef USE_AES_GCM
	#error "Enable USE_AES_GCM in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifndef USE_SHA384
	#error "Enable USE_SHA384 in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
	#endif
	#define USE_DH_CIPHER_SUITE
	#define USE_ECDSA_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	#endif
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	#endif
	#define USE_SHA_MAC
	#define USE_DHE_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
	#endif
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
	#endif
	#ifndef USE_SHA384
	#error "Enable USE_SHA384 in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
	#endif
	#define USE_SHA_MAC
	#define USE_DHE_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	#ifndef USE_AES_GCM
	#error "Enable USE_AES_GCM in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	#endif
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	#endif
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	#endif
	#define USE_DHE_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	#ifndef USE_AES_GCM
	#error "Enable USE_AES_GCM in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifndef USE_SHA384
	#error "Enable USE_SHA384 in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	#endif
	#define USE_DHE_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifndef USE_AES_GCM
	#error "Enable USE_AES_GCM in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifndef USE_SHA384
	#error "Enable USE_SHA384 in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
	#endif
	#define USE_DH_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"
	#endif
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"
	#endif
	#ifndef USE_AES_GCM
	#error "Enable USE_AES_GCM in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"
	#endif
	#define USE_DH_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
	#endif
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
	#endif
	#ifndef USE_SHA384
	#error "Enable USE_SHA384 in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
	#endif
	#define USE_SHA_MAC
	#define USE_DH_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"
	#endif
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"
	#endif
	#define USE_SHA_MAC
	#define USE_DH_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif
#endif /* USE_TLS_1_2 */

#ifdef USE_TLS_1_1
	#ifndef USE_TLS
	#error "Enable USE_TLS in matrixsslConfig.h for TLS_1_1 support"
	#endif
#endif

#ifndef USE_TLS_1_2
	#ifdef USE_TLS_RSA_WITH_AES_128_CBC_SHA256
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_RSA_WITH_AES_128_CBC_SHA256"
	#endif
	#ifdef USE_TLS_RSA_WITH_AES_256_CBC_SHA256
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_RSA_WITH_AES_256_CBC_SHA256"
	#endif
	#ifdef USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
	#endif
	#ifdef USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
	#endif
	#ifdef USE_TLS_RSA_WITH_AES_128_GCM_SHA256
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_RSA_WITH_AES_128_GCM_SHA256"
	#endif
	#ifdef USE_TLS_RSA_WITH_AES_256_GCM_SHA384
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_RSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	#endif
	#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	#endif
	#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
	#endif
	#ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
	#endif
	#ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	#endif
	#ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	#endif
	#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"
	#endif
	#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"
	#endif
	#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"
	#endif
	#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifdef USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
	#endif
	#ifdef USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"
	#endif
	#ifdef USE_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
	#endif
	#ifdef USE_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
	#error "Enable USE_TLS_1_2 in matrixsslConfig.h for TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 "
	#endif
#endif /* ! TLS_1_2 */

#ifdef USE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA
	#ifndef USE_3DES
	#error "Enable USE_3DES in cryptoConfig.h for SSL_DH_anon_WITH_3DES_EDE_CBC_SHA"
	#endif
	#ifndef USE_DH
	#error "Enable USE_DH in cryptoConfig.h for SSL_DH_anon_WITH_3DES_EDE_CBC_SHA"
	#endif
	#define REQUIRE_DH_PARAMS
	#define USE_ANON_DH_CIPHER_SUITE
	#define USE_DHE_CIPHER_SUITE
	#define USE_3DES_CIPHER_SUITE
	#define USE_SHA_MAC
#endif

#ifdef USE_SSL_DH_anon_WITH_RC4_128_MD5
	#ifndef USE_ARC4
	#error "Enable USE_ARC4 in cryptoConfig.h for SSL_DH_anon_WITH_RC4_128_MD5"
	#endif
	#ifndef USE_DH
	#error "Enable USE_DH in cryptoConfig.h for SSL_DH_anon_WITH_RC4_128_MD5"
	#endif
	#define REQUIRE_DH_PARAMS
	#define USE_ANON_DH_CIPHER_SUITE
	#define USE_DHE_CIPHER_SUITE
	#define USE_ARC4_CIPHER_SUITE
	#define USE_MD5_MAC
#endif

#ifdef USE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
	#endif
	#ifndef USE_3DES
	#error "Enable USE_3DES in cryptoConfig.h for SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
	#endif
	#ifndef USE_DH
	#error "Enable USE_DH in cryptoConfig.h for SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
	#endif
	#define REQUIRE_DH_PARAMS
	#define USE_SHA_MAC
	#define USE_DHE_CIPHER_SUITE
	#define USE_3DES_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
#endif

#ifdef USE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
	#endif
	#ifndef USE_DH
	#error "Enable USE_DH in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
	#endif
	#define REQUIRE_DH_PARAMS
	#define USE_SHA_MAC
	#define USE_DHE_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
#endif

#ifdef USE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
	#endif
	#ifndef USE_DH
	#error "Enable USE_DH in cryptoConfig.h for TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
	#endif
	#define REQUIRE_DH_PARAMS
	#define USE_SHA_MAC
	#define USE_DHE_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
#endif

#ifdef USE_TLS_DHE_PSK_WITH_AES_128_CBC_SHA
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_DHE_PSK_WITH_AES_128_CBC_SHA"
	#endif
	#ifndef USE_DH
	#error "Enable USE_DH in cryptoConfig.h for TLS_DHE_PSK_WITH_AES_128_CBC_SHA"
	#endif
	#if !defined(USE_TLS) && !defined(USE_DTLS)
	#error "Enable USE_TLS in matrixsslConfig.h for TLS_DHE_PSK_WITH_AES_128_CBC_SHA"
	#endif
	#define REQUIRE_DH_PARAMS
	#define USE_SHA_MAC
	#define USE_ANON_DH_CIPHER_SUITE
	#define USE_DHE_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
	#define USE_PSK_CIPHER_SUITE
	#define USE_DHE_PSK_CIPHER_SUITE
#endif

#ifdef USE_TLS_DHE_PSK_WITH_AES_256_CBC_SHA
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_DHE_PSK_WITH_AES_256_CBC_SHA"
	#endif
	#ifndef USE_DH
	#error "Enable USE_DH in cryptoConfig.h for TLS_DHE_PSK_WITH_AES_256_CBC_SHA"
	#endif
	#if !defined(USE_TLS) && !defined(USE_DTLS)
	#error "Enable USE_TLS in matrixsslConfig.h for TLS_DHE_PSK_WITH_AES_256_CBC_SHA"
	#endif
	#define REQUIRE_DH_PARAMS
	#define USE_SHA_MAC
	#define USE_ANON_DH_CIPHER_SUITE
	#define USE_DHE_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
	#define USE_PSK_CIPHER_SUITE
	#define USE_DHE_PSK_CIPHER_SUITE
#endif

#ifdef USE_TLS_PSK_WITH_AES_256_CBC_SHA
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_PSK_WITH_AES_256_CBC_SHA"
	#endif
	#if !defined(USE_TLS) && !defined(USE_DTLS)
	#error "Enable USE_TLS in matrixsslConfig.h for TLS_PSK_WITH_AES_256_CBC_SHA"
	#endif
	#define USE_SHA_MAC
	#define USE_AES_CIPHER_SUITE
	#define USE_PSK_CIPHER_SUITE
#endif

#ifdef USE_TLS_PSK_WITH_AES_128_CBC_SHA
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_PSK_WITH_AES_128_CBC_SHA"
	#endif
	#if !defined(USE_TLS) && !defined(USE_DTLS)
	#error "Enable USE_TLS in matrixsslConfig.h for TLS_PSK_WITH_AES_128_CBC_SHA"
	#endif
	#define USE_SHA_MAC
	#define USE_AES_CIPHER_SUITE
	#define USE_PSK_CIPHER_SUITE
#endif

#ifdef USE_TLS_PSK_WITH_AES_128_CBC_SHA256
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_PSK_WITH_AES_128_CBC_SHA256"
	#endif
	#if !defined(USE_TLS) && !defined(USE_DTLS)
	#error "Enable USE_TLS in matrixsslConfig.h for TLS_PSK_WITH_AES_128_CBC_SHA256"
	#endif
	#ifndef USE_SHA256
	#error "Enable USE_SHA256 in cryptoConfig.h for TLS_PSK_WITH_AES_128_CBC_SHA256"
	#endif
	#define USE_SHA_MAC
	#define USE_AES_CIPHER_SUITE
	#define USE_PSK_CIPHER_SUITE
#endif

#ifdef USE_TLS_PSK_WITH_AES_256_CBC_SHA384
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_PSK_WITH_AES_256_CBC_SHA384"
	#endif
	#if !defined(USE_TLS) && !defined(USE_DTLS)
	#error "Enable USE_TLS in matrixsslConfig.h for TLS_PSK_WITH_AES_256_CBC_SHA384"
	#endif
	#ifndef USE_SHA384
	#error "Enable USE_SHA384 in cryptoConfig.h for TLS_PSK_WITH_AES_256_CBC_SHA384"
	#endif
	#define USE_SHA_MAC
	#define USE_AES_CIPHER_SUITE
	#define USE_PSK_CIPHER_SUITE
#endif

#ifdef USE_TLS_DH_anon_WITH_AES_128_CBC_SHA
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_DH_anon_WITH_AES_128_CBC_SHA"
	#endif
	#ifndef USE_DH
	#error "Enable USE_DH in cryptoConfig.h for TLS_DH_anon_WITH_AES_128_CBC_SHA"
	#endif
	#define REQUIRE_DH_PARAMS
	#define USE_SHA_MAC
	#define USE_ANON_DH_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
	#define USE_DHE_CIPHER_SUITE
#endif

#ifdef USE_TLS_DH_anon_WITH_AES_256_CBC_SHA
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_DH_anon_WITH_AES_256_CBC_SHA"
	#endif
	#ifndef USE_DH
	#error "Enable USE_DH in cryptoConfig.h for TLS_DH_anon_WITH_AES_256_CBC_SHA"
	#endif
	#define REQUIRE_DH_PARAMS
	#define USE_SHA_MAC
	#define USE_ANON_DH_CIPHER_SUITE
	#define USE_DHE_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_RSA_WITH_SEED_CBC_SHA
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_RSA_WITH_SEED_CBC_SHA"
	#endif
	#ifndef USE_SEED
	#error "Enable USE_SEED in cryptoConfig.h for TLS_RSA_WITH_SEED_CBC_SHA"
	#endif
	#define USE_SHA_MAC
	#define USE_RSA_CIPHER_SUITE
	#define USE_SEED_CIPHER_SUITE
#endif

#ifdef USE_TLS_RSA_WITH_IDEA_CBC_SHA
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_RSA_WITH_IDEA_CBC_SHA"
	#endif
	#ifndef USE_IDEA
	#error "Enable USE_IDEA in cryptoConfig.h for TLS_RSA_WITH_IDEA_CBC_SHA"
	#endif
	#define USE_SHA_MAC
	#define USE_IDEA_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"
	#endif
	#define USE_SHA_MAC
	#define USE_DH_CIPHER_SUITE
	#define USE_ECDSA_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"
	#endif
	#define USE_SHA_MAC
	#define USE_DH_CIPHER_SUITE
	#define USE_ECDSA_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	#endif
	#define USE_SHA_MAC
	#define USE_DHE_CIPHER_SUITE
	#define USE_ECDSA_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	#endif
	#define USE_SHA_MAC
	#define USE_DHE_CIPHER_SUITE
	#define USE_ECDSA_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	#endif
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	#endif
	#define USE_SHA_MAC
	#define USE_DHE_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	#endif
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	#endif
	#define USE_SHA_MAC
	#define USE_DHE_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	#endif
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	#endif
	#ifndef USE_3DES
	#error "Enable USE_3DES in cryptoConfig.h for TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	#endif
	#define USE_SHA_MAC
	#define USE_DHE_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
	#define USE_3DES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"
	#endif
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"
	#endif
	#define USE_SHA_MAC
	#define USE_DH_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

#ifdef USE_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
	#ifndef USE_ECC
	#error "Enable USE_ECC in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
	#endif
	#ifndef USE_RSA
	#error "Enable USE_RSA in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
	#endif
	#ifndef USE_AES
	#error "Enable USE_AES in cryptoConfig.h for TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
	#endif
	#define USE_SHA_MAC
	#define USE_DH_CIPHER_SUITE
	#define USE_ECC_CIPHER_SUITE
	#define USE_RSA_CIPHER_SUITE
	#define USE_AES_CIPHER_SUITE
#endif

/******************************************************************************/
/* 
	If only PSK suites have been enabled (non-DHE), flip on the USE_ONLY_PSK
	define to create the smallest version of the library. If this is hit, the
	user can disable USE_X509, USE_RSA, USE_ECC, and USE_PRIVATE_KEY_PARSING in
	cryptoConfig.h.  The user can also enable DISABLE_PSTM in cryptoConfig.h
*/
#if !defined(USE_RSA_CIPHER_SUITE) && !defined(USE_DHE_CIPHER_SUITE) && \
	!defined(USE_DH_CIPHER_SUITE)
#define USE_ONLY_PSK_CIPHER_SUITE
#ifndef USE_X509
typedef int32 psX509Cert_t;
#endif
#endif	/* !RSA && !DH */

#if !defined(USE_RSA_CIPHER_SUITE) && !defined(USE_DH_CIPHER_SUITE) && \
	defined(USE_DHE_PSK_CIPHER_SUITE)
#define USE_ONLY_PSK_CIPHER_SUITE
#ifndef USE_X509
typedef int32 psX509Cert_t;
#endif
#endif	/* DHE_PSK only */

#if !defined(USE_CERT_PARSE) && !defined(USE_ONLY_PSK_CIPHER_SUITE)
#ifdef USE_CLIENT_SIDE_SSL
#error "Must enable USE_CERT_PARSE if building client with USE_CLIENT_SIDE_SSL"
#endif
#ifdef USE_CLIENT_AUTH
#error "Must enable USE_CERT_PARSE if client auth (USE_CLIENT_AUTH) is needed"
#endif
#endif

/******************************************************************************/

/******************************************************************************/
/*
	Leave this enabled for run-time check of sslKeys_t content when a cipher
	suite is matched.  Disable only if you need to manage key material yourself.
	Always conditional on whether certificate parsing is enabled because it
	looks at members that only exist if certificates have been parsed 
*/
#ifdef USE_CERT_PARSE
//#define VALIDATE_KEY_MATERIAL
#endif /* USE_CERT_PARSE */
/******************************************************************************/

/******************************************************************************/
/*	SSL protocol and MatrixSSL defines */
/******************************************************************************/
/*
	Maximum SSL record size, per specification
*/
#define     SSL_MAX_PLAINTEXT_LEN		0x4000  /* 16KB */
#define     SSL_MAX_RECORD_LEN			SSL_MAX_PLAINTEXT_LEN + 2048
#define     SSL_MAX_BUF_SIZE			SSL_MAX_RECORD_LEN + 0x5
#define		SSL_MAX_DISABLED_CIPHERS	8
/*
	Maximum buffer sizes for static SSL array types 
*/
#define SSL_MAX_MAC_SIZE		48 /* SHA384 */
#define SSL_MAX_IV_SIZE			16
#define SSL_MAX_BLOCK_SIZE		16
#define SSL_MAX_SYM_KEY_SIZE	32

/*
	Negative return codes must be between -50 and -69 in the MatrixSSL module
*/
#define     SSL_FULL            -50  /* must call sslRead before decoding */
#define     SSL_PARTIAL         -51 /* more data reqired to parse full msg */
#define     SSL_SEND_RESPONSE   -52  /* decode produced output data */
#define     SSL_PROCESS_DATA    -53  /* succesfully decoded application data */
#define     SSL_ALERT           -54  /* we've decoded an alert */
#define     SSL_FILE_NOT_FOUND  -55  /* File not found */
#define     SSL_MEM_ERROR       PS_MEM_FAIL  /* Memory allocation failure */

/*
	Magic numbers for handshake header lengths
*/
#define SSL2_HEADER_LEN				2
#define SSL3_HEADER_LEN				5
#define SSL3_HANDSHAKE_HEADER_LEN	4
#define TLS_GCM_TAG_LEN				16
#define TLS_GCM_NONCE_LEN			8

/*
	matrixSslSetSessionOption defines
*/
#define	SSL_OPTION_FULL_HANDSHAKE			1
#ifdef USE_CLIENT_AUTH
#define	SSL_OPTION_DISABLE_CLIENT_AUTH		2
#define	SSL_OPTION_ENABLE_CLIENT_AUTH		3
#endif /* USE_CLIENT_AUTH */
#define SSL_OPTION_DISABLE_REHANDSHAKES		4
#define SSL_OPTION_REENABLE_REHANDSHAKES	5

/*
    SSL Alert levels and descriptions
    This implementation treats all alerts that are not related to 
	certificate validation as fatal
*/
#define SSL_ALERT_LEVEL_WARNING             1
#define SSL_ALERT_LEVEL_FATAL               2

#define SSL_ALERT_CLOSE_NOTIFY              0
#define SSL_ALERT_UNEXPECTED_MESSAGE        10
#define SSL_ALERT_BAD_RECORD_MAC            20
#define SSL_ALERT_DECRYPTION_FAILED			21 /* Do not use. RFC 5246 */
#define SSL_ALERT_RECORD_OVERFLOW			22
#define SSL_ALERT_DECOMPRESSION_FAILURE     30
#define SSL_ALERT_HANDSHAKE_FAILURE         40
#define SSL_ALERT_NO_CERTIFICATE            41
#define SSL_ALERT_BAD_CERTIFICATE           42
#define SSL_ALERT_UNSUPPORTED_CERTIFICATE   43
#define SSL_ALERT_CERTIFICATE_REVOKED       44
#define SSL_ALERT_CERTIFICATE_EXPIRED       45
#define SSL_ALERT_CERTIFICATE_UNKNOWN       46
#define SSL_ALERT_ILLEGAL_PARAMETER         47
#define SSL_ALERT_UNKNOWN_CA				48
#define SSL_ALERT_ACCESS_DENIED				49
#define SSL_ALERT_DECODE_ERROR				50
#define SSL_ALERT_DECRYPT_ERROR				51
#define SSL_ALERT_PROTOCOL_VERSION			70
#define SSL_ALERT_INSUFFICIENT_SECURITY		71
#define SSL_ALERT_INTERNAL_ERROR			80
#define SSL_ALERT_NO_RENEGOTIATION			100
#define SSL_ALERT_UNSUPPORTED_EXTENSION		110
#define SSL_ALERT_UNRECOGNIZED_NAME			112

/*
    Use as return code in user validation callback to allow
    anonymous connections to proceed.
	MUST NOT OVERLAP WITH ANY OF THE ALERT CODES ABOVE
*/
#define SSL_ALLOW_ANON_CONNECTION           254

/*
	Internal flags for ssl_t.flags field.
*/
#define	SSL_FLAGS_SERVER		0x00000001
#define	SSL_FLAGS_READ_SECURE	0x00000002
#define	SSL_FLAGS_WRITE_SECURE	0x00000004
#define SSL_FLAGS_RESUMED		0x00000008
#define SSL_FLAGS_CLOSED		0x00000010
#define SSL_FLAGS_NEED_ENCODE	0x00000020
#define SSL_FLAGS_ERROR			0x00000040
#define SSL_FLAGS_TLS			0x00000080
#define SSL_FLAGS_CLIENT_AUTH	0x00000100
#define SSL_FLAGS_ANON_CIPHER	0x00000200
#define SSL_FLAGS_FALSE_START	0x00000400
#define SSL_FLAGS_TLS_1_1		0x00000800
#define SSL_FLAGS_TLS_1_2		0x00001000
#define SSL_FLAGS_DHE_KEY_EXCH	0x00002000
#define SSL_FLAGS_DHE_WITH_RSA	0x00004000
#define SSL_FLAGS_DHE_WITH_DSA	0x00008000
#define SSL_FLAGS_PSK_CIPHER	0x00010000
#define SSL_FLAGS_ECC_CIPHER	0x00020000
#define SSL_FLAGS_HW			0x00040000 /* Use HW for decode/encode */
#define SSL_FLAGS_HW_SW			0x00080000 /* Use HW and SW in parallel (debug) */
#define SSL_FLAGS_NONBLOCK		0x00100000 /* Use async HW for decode/encode */
#define SSL_FLAGS_PENDING_R		0x00200000 /* Non-blocking read record op */
#define SSL_FLAGS_PENDING_W		0x00400000 /* Non-blocking write record op */
#define SSL_FLAGS_PENDING_FLIGHT_W	0x80000000 /* mid encryptFlight */
#define SSL_FLAGS_PENDING_PKA_R	0x00800000 /* Non-blocking public key op */
#define SSL_FLAGS_PENDING_PKA_W	0x40000000 /* Non-blocking public key op */
#define SSL_FLAGS_EAGAIN		0x02000000 /* Not submitted.  Skip hsHash */
#define SSL_FLAGS_HW_BAD		0x04000000 /* Bad hardware result,go software */
#define SSL_FLAGS_GMAC_W		0x08000000 /* Write and read states for GMAC */
#define SSL_FLAGS_GMAC_R		0x10000000
	
/* Just to stay consistent with the SSL_FLAGS_TLS_maj_min for NewSession use */
#define SSL_FLAGS_TLS_1_0	SSL_FLAGS_TLS
#define SSL_FLAGS_SSLV3		0x20000000
/*
	Buffer flags (ssl->bFlags)
*/
#define BFLAG_CLOSE_AFTER_SENT	0x01
#define BFLAG_HS_COMPLETE		0x02
#define BFLAG_STOP_BEAST		0x04 
	
/*
	Number of bytes server must send before creating a re-handshake credit
*/
#define DEFAULT_RH_CREDITS		1 /* Allow for one rehandshake by default */
#define	BYTES_BEFORE_RH_CREDIT	20 * 1024 * 1024

/*
	Cipher types
*/
#define CS_NULL			0
#define CS_RSA			1
#define CS_DHE_RSA		2
#define CS_DH_ANON		3
#define CS_DHE_PSK		4
#define CS_PSK			5
#define	CS_ECDHE_ECDSA	6
#define CS_ECDHE_RSA	7
#define	CS_ECDH_ECDSA	8
#define CS_ECDH_RSA		9

/*
	These are defines rather than enums because we want to store them as char,
	not int32 (enum size)
*/
#define SSL_RECORD_TYPE_CHANGE_CIPHER_SPEC		20
#define SSL_RECORD_TYPE_ALERT					21
#define SSL_RECORD_TYPE_HANDSHAKE				22
#define SSL_RECORD_TYPE_APPLICATION_DATA		23
#define SSL_RECORD_TYPE_HANDSHAKE_FIRST_FRAG	90 /*    internal */
#define SSL_RECORD_TYPE_HANDSHAKE_FRAG			91 /* non-standard types */

#define SSL_HS_HELLO_REQUEST		0
#define SSL_HS_CLIENT_HELLO			1
#define SSL_HS_SERVER_HELLO			2
#define SSL_HS_HELLO_VERIFY_REQUEST	3
#define SSL_HS_NEW_SESSION_TICKET	4
#define SSL_HS_CERTIFICATE			11
#define SSL_HS_SERVER_KEY_EXCHANGE	12
#define SSL_HS_CERTIFICATE_REQUEST	13
#define SSL_HS_SERVER_HELLO_DONE	14
#define SSL_HS_CERTIFICATE_VERIFY	15
#define SSL_HS_CLIENT_KEY_EXCHANGE	16
#define SSL_HS_FINISHED				20
#define SSL_HS_DONE					255	/* Handshake complete (internal) */

#define	INIT_ENCRYPT_CIPHER		0
#define INIT_DECRYPT_CIPHER		1

#define HMAC_CREATE	1
#define HMAC_VERIFY 2


#ifdef USE_TLS_1_2
#define HASH_SIG_256_RSA	0x0401	/* SHA256 hash and RSA sig */
#define HASH_SIG_384_RSA	0x0501	/* SHA256 hash and RSA sig */
#define	HASH_SIG_1_RSA		0x0201	/* SHA1 hash and RSA sig */
#define HASH_SIG_5_RSA		0x0101	/* MD5 hash and RSA sig */
#define HASH_SIG_1_ECDSA	0x0203	/* SHA1 hash and ECDSA sig */
#define HASH_SIG_256_ECDSA	0x0403	/* SHA256 hash and ECDSA sig */
#define HASH_SIG_384_ECDSA	0x0503	/* SHA384 hash and ECDSA sig */
/* bit map helper */
#define HASH_SIG_256_RSA_BM	0x1	
#define HASH_SIG_384_RSA_BM	0x2	
#define HASH_SIG_1_RSA_BM	0x4	
#define HASH_SIG_5_RSA_BM	0x8	 /* MD5 */
#define HASH_SIG_1_ECDSA_BM	0x10	
#define HASH_SIG_256_ECDSA_BM	0x20	
#define HASH_SIG_384_ECDSA_BM	0x40	
#endif

/*
	Additional ssl alert value, indicating no error has ocurred.
*/
#define SSL_ALERT_NONE					255	/* No error */

#define SSL_HS_RANDOM_SIZE			32
#define SSL_HS_RSA_PREMASTER_SIZE	48

#define SSL2_MAJ_VER	2
#define SSL3_MAJ_VER	3
#define SSL3_MIN_VER	0
#define TLS_MIN_VER		1
#define TLS_1_1_MIN_VER	2
#define TLS_1_2_MIN_VER	3

#ifdef USE_TLS
#define TLS_HS_FINISHED_SIZE	12
#define TLS_MAJ_VER		3
#endif /* USE_TLS */

/*
	SSL cipher suite specification IDs
*/
#define SSL_NULL_WITH_NULL_NULL				0x0000
#define SSL_RSA_WITH_NULL_MD5				0x0001
#define SSL_RSA_WITH_NULL_SHA				0x0002
#define SSL_RSA_WITH_RC4_128_MD5			0x0004
#define SSL_RSA_WITH_RC4_128_SHA			0x0005		
#define SSL_RSA_WITH_3DES_EDE_CBC_SHA		0x000A		/* 10 */
#define TLS_RSA_WITH_AES_128_CBC_SHA		0x002F		/* 47 */
#define TLS_RSA_WITH_AES_256_CBC_SHA		0x0035		/* 53 */
#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV	0x00FF

#define TLS_RSA_WITH_IDEA_CBC_SHA			0x0007		/* 7 */
#define	SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA	0x0016		/* 22 */
#define SSL_DH_anon_WITH_RC4_128_MD5		0x0018		/* 24 */
#define SSL_DH_anon_WITH_3DES_EDE_CBC_SHA	0x001B		/* 27 */
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA	0x0033		/* 51 */
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA	0x0039		/* 57 */
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 0x0067		/* 103 */
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 0x006B		/* 107 */
#define	TLS_DH_anon_WITH_AES_128_CBC_SHA	0x0034		/* 52 */
#define	TLS_DH_anon_WITH_AES_256_CBC_SHA	0x003A		/* 58 */
#define TLS_RSA_WITH_AES_128_CBC_SHA256		0x003C		/* 60 */
#define TLS_RSA_WITH_AES_256_CBC_SHA256		0x003D		/* 61 */
#define TLS_RSA_WITH_SEED_CBC_SHA			0x0096		/* 150 */
#define TLS_PSK_WITH_AES_128_CBC_SHA		0x008C		/* 140 */
#define TLS_PSK_WITH_AES_128_CBC_SHA256		0x00AE		/* 174 */
#define TLS_PSK_WITH_AES_256_CBC_SHA384		0x00AF		/* 175 */
#define TLS_PSK_WITH_AES_256_CBC_SHA		0x008D		/* 141 */
#define TLS_DHE_PSK_WITH_AES_128_CBC_SHA	0x0090		/* 144 */
#define TLS_DHE_PSK_WITH_AES_256_CBC_SHA	0x0091		/* 145 */
#define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA	0xC004		/* 49156 */
#define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA	0xC005		/* 49157 */
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA	0xC009	/* 49161 */
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA	0xC00A  /* 49162 */
#define TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA		0xC012	/* 49170 */
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA		0xC013	/* 49171 */
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA		0xC014	/* 49172 */
#define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA		0xC00E	/* 49166 */
#define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA		0xC00F	/* 49167 */
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 0xC023	/* 49187 */
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 0xC024	/* 49188 */
#define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256  0xC025	/* 49189 */
#define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384  0xC026	/* 49190 */
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256	0xC027	/* 49191 */
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384	0xC028	/* 49192 */
#define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256	0xC029	/* 49193 */
#define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384	0xC02A	/* 49194 */

#define TLS_RSA_WITH_AES_128_GCM_SHA256			0x009C	/* 156 */
#define TLS_RSA_WITH_AES_256_GCM_SHA384			0x009D	/* 157 */
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xC02B	/* 49195 */
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xC02C	/* 49196 */
#define TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256	0xC02D	/* 49197 */
#define TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384	0xC02E	/* 49198 */
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	0xC02F	/* 49199 */
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384	0xC030	/* 49200 */
#define TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256	0xC031	/* 49201 */
#define TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384	0xC032	/* 49202 */


/*
	Supported HELLO extensions
*/
#define EXT_SERVER_NAME					0x00
#define EXT_MAX_FRAGMENT_LEN			0x01
#define EXT_TRUNCATED_HMAC				0x04
#define EXT_RENEGOTIATION_INFO			0xFF01
#define EXT_SIGNATURE_ALGORITHMS		0x00D

/*
	Maximum key block size for any defined cipher
	This must be validated if new ciphers are added
	Value is largest total among all cipher suites for
		2*macSize + 2*keySize + 2*ivSize
*/
#define SSL_MAX_KEY_BLOCK_SIZE			2*48 + 2*32 + 2*16 + SHA1_HASH_SIZE

/*
	Master secret is 48 bytes, sessionId is 32 bytes max
*/
#define		SSL_HS_MASTER_SIZE		48
#define		SSL_MAX_SESSION_ID_SIZE	32



#ifndef USE_SSL_HANDSHAKE_MSG_TRACE
#define psTraceHs(x) 
#define psTraceStrHs(x, y) 
#else
#define psTraceHs(x) _psTrace(x)
#define psTraceStrHs(x, y) _psTraceStr(x, y)
#endif /* USE_SSL_HANDSHAKE_MSG_TRACE */

#ifndef USE_SSL_INFORMATIONAL_TRACE
#define psTraceInfo(x) 
#define psTraceStrInfo(x, y) 
#define psTraceIntInfo(x, y)
#else
#define psTraceInfo(x) _psTrace(x)
#define psTraceStrInfo(x, y) _psTraceStr(x, y)
#define psTraceIntInfo(x, y) _psTraceInt(x, y)
#endif /* USE_SSL_INFORMATIONAL_TRACE */

/******************************************************************************/

typedef psBuf_t	sslBuf_t;
	
/******************************************************************************/	
#ifdef USE_PSK_CIPHER_SUITE
typedef struct psPsk {
	unsigned char	*pskKey;
	int32			pskLen;
	unsigned char	*pskId;
	int32			pskIdLen;
	struct psPsk	*next;
} psPsk_t;
#endif /* USE_PSK_CIPHER_SUITE */


#if defined(USE_SERVER_SIDE_SSL) && defined(USE_STATELESS_SESSION_TICKETS)
typedef int32 (*sslSessTicketCb_t)(void *keys, unsigned char[16], short);

typedef struct sessTicketKey {
	unsigned char			name[16];
	unsigned char			symkey[32];
	unsigned char			hashkey[32];
	short					nameLen, symkeyLen, hashkeyLen, inUse;
	struct sessTicketKey	*next;
} psSessionTicketKeys_t;
#endif

/******************************************************************************/
/*
	SSL certificate public-key structure
*/
typedef struct {
	psPool_t		*pool;
#if defined(USE_SERVER_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	psX509Cert_t	*cert;	
	psPubKey_t		*privKey;
#endif /* USE_SERVER_SIDE_SSL || USE_CLIENT_AUTH */
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	psX509Cert_t	*CAcerts;
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#ifdef REQUIRE_DH_PARAMS
	psDhParams_t	*dhParams;
#endif /* REQUIRE_DH_PARAMS */
#ifdef USE_PSK_CIPHER_SUITE
	psPsk_t			*pskKeys;
#endif /* USE_PSK_CIPHER_SUITE */
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_STATELESS_SESSION_TICKETS)
	psSessionTicketKeys_t	*sessTickets;
	sslSessTicketCb_t		ticket_cb;
#endif
} sslKeys_t;

/******************************************************************************/

/******************************************************************************/
/*
	SSL record and session structures
*/
typedef struct {
	unsigned short	len;
	unsigned char	majVer;
	unsigned char	minVer;
#ifdef USE_CERT_CHAIN_PARSING
	unsigned short	hsBytesHashed;
	unsigned short	hsBytesParsed;
	unsigned short	trueLen;
	unsigned char	partial;
	unsigned char	certPad;
#endif
#ifdef USE_APP_DATA_PARTIAL_PARSING	
	unsigned short byteParsed;
#endif
	unsigned char	type;
	unsigned char	pad[3];		/* Padding for 64 bit compat */
} sslRec_t;

typedef struct {
	unsigned char	clientRandom[SSL_HS_RANDOM_SIZE];	/* From ClientHello */
	unsigned char	serverRandom[SSL_HS_RANDOM_SIZE];	/* From ServerHello */
#ifdef USE_UNIFIED_PKCS11
	CK_OBJECT_HANDLE	masterSecret;
	CK_SESSION_HANDLE	pkcs11Ses; 
	CK_SESSION_HANDLE	oldCrypt; /* For rehandhakes and DTLS */
#else
	unsigned char	masterSecret[SSL_HS_MASTER_SIZE];
#endif
	unsigned char	*premaster;							/* variable size */
	uint32			premasterSize;

	unsigned char	keyBlock[SSL_MAX_KEY_BLOCK_SIZE];	/* Storage for 'ptr' */
	unsigned char	*wMACptr;
	unsigned char	*rMACptr;
	unsigned char	*wKeyptr;
	unsigned char	*rKeyptr;
	
	/*	All maximum sizes for current cipher suites */
	unsigned char	writeMAC[SSL_MAX_MAC_SIZE];
	unsigned char	readMAC[SSL_MAX_MAC_SIZE];
	unsigned char	writeKey[SSL_MAX_SYM_KEY_SIZE];
	unsigned char	readKey[SSL_MAX_SYM_KEY_SIZE];
#ifdef USE_PKCS11_TLS_ALGS
	CK_OBJECT_HANDLE	wMACptr;
	CK_OBJECT_HANDLE	rMACptr;
	CK_OBJECT_HANDLE	wKeyptr;
	CK_OBJECT_HANDLE	rKeyptr;
	CK_OBJECT_HANDLE	writeMAC;
	CK_OBJECT_HANDLE	readMAC;
	CK_OBJECT_HANDLE	writeKey;
	CK_OBJECT_HANDLE	readKey;
#endif
	unsigned char	*wIVptr;
	unsigned char	*rIVptr;
	unsigned char	writeIV[SSL_MAX_IV_SIZE];
	unsigned char	readIV[SSL_MAX_IV_SIZE];

	unsigned char	seq[8];
	unsigned char	remSeq[8];

#ifndef USE_ONLY_PSK_CIPHER_SUITE
#if defined(USE_CLIENT_SIDE_SSL) || defined(USE_CLIENT_AUTH)
	psX509Cert_t	*cert;
	int32 (*validateCert)(void *ssl, psX509Cert_t *certInfo, int32 alert);
#endif /* USE_CLIENT_SIDE_SSL || USE_CLIENT_AUTH */
#endif /* USE_ONLY_PSK_CIPHER_SUITE */

#ifdef USE_CLIENT_SIDE_SSL
	int32				certMatch;
#endif /* USE_CLIENT_SIDE_SSL */

	psDigestContext_t	msgHashMd5;
	psDigestContext_t	msgHashSha1;
	psCipherContext_t	encryptCtx;
	psCipherContext_t	decryptCtx;
#ifdef USE_PKCS11_SYMMETRIC
	CK_SESSION_HANDLE	encryptCtx; /* same as pkcs11Ses */
	CK_SESSION_HANDLE	decryptCtx; /* same as pkcs11Ses */
#endif /* USE_PKCS11_SYMMETRIC */


#ifdef USE_TLS_1_2
	psDigestContext_t	msgHashSha256;
#ifdef USE_SHA384
	psDigestContext_t	msgHashSha384;
#endif
#ifdef USE_PKCS11_TLS_HS_HASH
	CK_SESSION_HANDLE	msgHashSha256;
	CK_SESSION_HANDLE	msgHashSha256Final;
	CK_SESSION_HANDLE	msgHashSha384;
	CK_SESSION_HANDLE	msgHashSha384Final;
#ifdef USE_CLIENT_AUTH
	CK_SESSION_HANDLE	msgHashSha256CertVerify;
	CK_SESSION_HANDLE	msgHashSha384CertVerify;
#endif
#endif /* USE_PKCS11_TLS_HS_HASH */
	
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)	
	unsigned char		sha1Snapshot[SHA1_HASH_SIZE];
#ifdef USE_SHA384
	unsigned char		sha384Snapshot[SHA384_HASH_SIZE];
#endif	
#endif	
	
#endif /* USE_TLS_1_2 */
#ifdef REQUIRE_DH_PARAMS
	unsigned char		*dhP;			/* modulus */
	unsigned char		*dhG;			/* generator */
	uint32				dhPLen;
	uint32				dhGLen;
	psDhKey_t			dhKeyPub;		/* other side */
	psDhKey_t			dhKeyPriv;		/* our key */
	psPool_t			*dhKeyPool;		/* handshake-scope pool for clients */
#endif /* REQUIRE_DH_PARAMS */
#if defined(USE_PSK_CIPHER_SUITE) && defined(USE_CLIENT_SIDE_SSL)
	char				*hint;
	uint32				hintLen;
#endif /* USE_PSK_CIPHER_SUITE && USE_CLIENT_SIDE_SSL */
#ifdef USE_ECC_CIPHER_SUITE
	psEccKey_t			*eccKeyPriv; /* local ECC key */
	psEccKey_t			*eccKeyPub; /* remote ECC key */
	psPool_t			*eccDhKeyPool; /* handshake-scope pool for clients */
#endif /* USE_ECC_CIPHER_SUITE */
	int32				anon;
} sslSec_t;

typedef struct {
	uint16			ident;	/* Official cipher ID */
	uint16			type;	/* Key exchange method */
	uint32			flags;	/* from CRYPTO_FLAGS_* */
	unsigned char	macSize;
	unsigned char	keySize;
	unsigned char	ivSize;
	unsigned char	blockSize;
	/* Init function */
	int32 (*init)(sslSec_t *sec, int32 type, uint32 keysize);
	/* Cipher functions */
	int32 (*encrypt)(void *ssl, unsigned char *in,
		unsigned char *out, uint32 len);
	int32 (*decrypt)(void *ssl, unsigned char *in,
		unsigned char *out, uint32 len);
	int32 (*generateMac)(void *ssl, unsigned char type, unsigned char *data,
		uint32 len, unsigned char *mac);
	int32 (*verifyMac)(void *ssl, unsigned char type, unsigned char *data,
		uint32 len, unsigned char *mac);
} sslCipherSpec_t;

#ifdef USE_STATELESS_SESSION_TICKETS
#define SESS_TICKET_FLAG_SENT_EMPTY		1
#define SESS_TICKET_FLAG_SENT_TICKET	2
#define SESS_TICKET_FLAG_RECVD_EXT		3
#define SESS_TICKET_FLAG_IN_LIMBO		4
#define SESS_TICKET_FLAG_USING_TICKET	5

#define SESSION_ID_STANDARD				0x1
#define SESSION_ID_TICKET				0x2
#endif

typedef struct {
	unsigned char	id[SSL_MAX_SESSION_ID_SIZE];
	unsigned char	masterSecret[SSL_HS_MASTER_SIZE];
	uint32			cipherId;
#ifdef USE_STATELESS_SESSION_TICKETS
	unsigned char	*sessionTicket;
	uint32			sessionTicketLen;
	uint32			sessionTicketLifetimeHint;
	uint32			sessionTicketFlag;
#endif	
} sslSessionId_t;

typedef struct {
	unsigned char	id[SSL_MAX_SESSION_ID_SIZE];
	unsigned char	masterSecret[SSL_HS_MASTER_SIZE];
	sslCipherSpec_t	*cipher;
	unsigned char	majVer;
	unsigned char	minVer;
	psTime_t		startTime;
	int32			inUse;
	DLListEntry		chronList;
} sslSessionEntry_t;

typedef struct tlsHelloExt {
	psPool_t			*pool;
	int32				extType;
	uint32				extLen;
	unsigned char		*extData;
	struct tlsHelloExt	*next;
} tlsExtension_t;
	

/* Hold the info needed to perform a public key operation for flight writes
	until the very end.  This is an architectural change that was added to aid
	the	integration of non-blocking hardware acceleration */
#define PKA_AFTER_RSA_SIG_GEN_ELEMENT	1
#define PKA_AFTER_RSA_SIG_GEN			2
#define PKA_AFTER_ECDSA_SIG_GEN			3
typedef struct {
	unsigned char	*inbuf; /* allocated to handshake pool */
	unsigned char	*outbuf;
	void			*data; /* pkiData */
	int32			inlen;
	short			type; /* one of the above defines */
} pkaAfter_t;

typedef struct nextMsgInFlight {
	unsigned char	*start;
	unsigned char	*seqDelay;
	int32			len;
	int32			type;
	int32			messageSize;
	int32			padLen;
	int32			hsMsg;
	struct nextMsgInFlight	*next;
} flightEncode_t;

typedef struct ssl {
	sslRec_t		rec;			/* Current SSL record information*/
									
	sslSec_t		sec;			/* Security structure */

	sslKeys_t		*keys;			/* SSL public and private keys */
	
	pkaAfter_t		pkaAfter;
	flightEncode_t	*flightEncode;
	unsigned char	*delayHsHash;
	unsigned char	*seqDelay;	/* tmp until flightEncode_t is built */

	psPool_t		*sPool;			/* SSL session pool */
	psPool_t		*hsPool;		/* Full session handshake pool */
	psPool_t		*flightPool;	/* Small but handy */

	unsigned char	sessionIdLen;
	unsigned char	sessionId[SSL_MAX_SESSION_ID_SIZE];
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_STATELESS_SESSION_TICKETS)
	int32			sessionIdAndTicket;
#endif	
	sslSessionId_t	*sid;
	char			*expectedName;	/* The expected cert subject name */
#ifdef USE_SERVER_SIDE_SSL	
	uint16			disabledCiphers[SSL_MAX_DISABLED_CIPHERS];
	void			(*sni_cb)(void *ssl, char *hostname, int32 hostnameLen,
						sslKeys_t **newKeys);
	short			sniUsed;
#endif /* USE_SERVER_SIDE_SSL */	
#ifdef USE_CLIENT_SIDE_SSL
	/* Just to handle corner case of app data tacked on HELLO_REQUEST */
	int32			anonBk;
	int32			flagsBk;
	uint32			bFlagsBk;
#endif /* USE_CLIENT_SIDE_SSL */
	

	unsigned char	*inbuf;
	unsigned char	*outbuf;
	int32			inlen;		/* Bytes unprocessed in inbuf */
	int32			outlen;		/* Bytes unsent in outbuf */
	int32			insize;		/* Total allocated size of inbuf */
	int32			outsize;	/* Total allocated size of outbuf */
	uint32			bFlags;		/* Buffer related flags */
	
	int32			maxPtFrag;	/* 16K by default - SSL_MAX_PLAINTEXT_LEN */
	unsigned char	*fragMessage; /* holds the constructed fragmented message */
	uint32			fragIndex;	/* How much data has been written to msg */
	uint32			fragTotal;	/* Total length of fragmented message */
		
	/* Pointer to the negotiated cipher information */
	sslCipherSpec_t	*cipher;
	
	/* 	Symmetric cipher callbacks

		We duplicate these here from 'cipher' because we need to set the
		various callbacks at different times in the handshake protocol
		Also, there are 64 bit alignment issues in using the function pointers
		within 'cipher' directly
	*/
	int32 (*encrypt)(void *ctx, unsigned char *in,
		unsigned char *out, uint32 len);
	int32 (*decrypt)(void *ctx, unsigned char *in,
		unsigned char *out, uint32 len);
	/* Message Authentication Codes */
	int32 (*generateMac)(void *ssl, unsigned char type, unsigned char *data,
		uint32 len, unsigned char *mac);
	int32 (*verifyMac)(void *ssl, unsigned char type, unsigned char *data,
		uint32 len, unsigned char *mac);

	/* Current encryption/decryption parameters */
	unsigned char	enMacSize;
	unsigned char	nativeEnMacSize; /* truncated hmac support */
	unsigned char	enIvSize;
	unsigned char	enBlockSize;
	unsigned char	deMacSize;
	unsigned char	nativeDeMacSize; /* truncated hmac support */
	unsigned char	deIvSize;
	unsigned char	deBlockSize;

	int32			flags;
	int32			hsState;		/* Next expected handshake message type */
	int32			err;			/* SSL errno of last api call */
	int32			ignoredMessageCount;

	unsigned char	reqMajVer;
	unsigned char	reqMinVer;
	unsigned char	majVer;
	unsigned char	minVer;
	unsigned char	outRecType;

#ifdef ENABLE_SECURE_REHANDSHAKES		
	unsigned char	myVerifyData[SHA384_HASH_SIZE]; /*SSLv3 max*/
	unsigned char	peerVerifyData[SHA384_HASH_SIZE];
	uint32			myVerifyDataLen;
	uint32			peerVerifyDataLen;
	int32			secureRenegotiationFlag;
#endif /* ENABLE_SECURE_REHANDSHAKES */
#ifdef SSL_REHANDSHAKES_ENABLED
	int32			rehandshakeCount; /* Make this an internal define of 1 */
	int32			rehandshakeBytes; /* Make this an internal define of 10MB */
#endif /* SSL_REHANDSHAKES_ENABLED */	
	int32			(*extCb)(void *ssl, unsigned short extType,
						unsigned short extLen, void *e);
#ifdef USE_AES_GCM
	int32			nonceCtrLen;	/* DTLS overrides with epoch/rsn bytes */
#endif
#ifdef USE_ZLIB_COMPRESSION
	int32			compression;
	z_stream		inflate;
	z_stream		deflate;
	unsigned char	*zlibBuffer; /* scratch pad for inflate/deflate data */
#endif
#ifdef USE_TRUNCATED_HMAC
	int32			truncHmac;
#endif
	int32			recordHeadLen;
	int32			hshakeHeadLen;
#ifdef USE_MATRIXSSL_STATS
	void (*statCb)(void *ssl, void *stats_ptr, int32 type, int32 value);
	void *statsPtr;
#endif
	void *userPtr; /* ISSL.C USES */

	unsigned char* lastData;
	int32  lastDataLen;
	int32  lastDataOffset;
#ifdef USE_APP_DATA_PARTIAL_PARSING
	psDigestContext_t hmac_ctx;
#endif
} ssl_t;


/******************************************************************************/
/*
	Former public APIS in 1.x and 2.x. Now deprecated in 3.x
	These functions are still heavily used internally, just no longer publically
	supported.
 */
extern int32 matrixSslDecode(ssl_t *ssl, unsigned char **buf, uint32 *len,
						uint32 size, uint32 *remaining, uint32 *requiredLen,
						int32 *error, unsigned char *alertLevel,
						unsigned char *alertDescription);
extern int32 matrixSslEncode(ssl_t *ssl, unsigned char *buf, uint32 size,
						unsigned char *ptBuf, uint32 *len);
extern int32	matrixSslGetEncodedSize(ssl_t *ssl, uint32 len);
extern void		matrixSslSetCertValidator(ssl_t *ssl,
					int32 (*certValidator)(void *, psX509Cert_t *, int32));
extern int32	matrixSslNewSession(ssl_t **ssl, sslKeys_t *keys,
						sslSessionId_t *session, int32 flags);
extern void		matrixSslSetSessionOption(ssl_t *ssl, int32 option,	void *arg);
extern int32	matrixSslHandshakeIsComplete(ssl_t *ssl);
typedef int32	(*sslExtCb_t)(void *, unsigned short, unsigned short, void *);

/* This used to be prefixed with 'matrix' */
extern int32	sslEncodeClosureAlert(ssl_t *ssl, sslBuf_t *out, 
									  uint32 *reqLen);

extern int32	matrixSslEncodeHelloRequest(ssl_t *ssl, sslBuf_t *out,
					uint32 *reqLen);
extern int32	matrixSslEncodeClientHello(ssl_t *ssl, sslBuf_t *out,
					uint32 cipherSpec[], uint16 cipherSpecLen,
					uint32 *requiredLen, tlsExtension_t *userExt);

#ifdef USE_CLIENT_SIDE_SSL
extern int32	matrixSslGetSessionId(ssl_t *ssl, sslSessionId_t *sessionId);
#endif /* USE_CLIENT_SIDE_SSL */

extern int32 matrixSslGetPrngData(unsigned char *bytes, uint32 size);

#ifdef USE_SSL_INFORMATIONAL_TRACE
extern void matrixSslPrintHSDetails(ssl_t *ssl);
#endif /* USE_SSL_INFORMATIONAL_TRACE */

#ifdef SSL_REHANDSHAKES_ENABLED
PSPUBLIC int32 matrixSslGetRehandshakeCredits(ssl_t *ssl);
PSPUBLIC void matrixSslAddRehandshakeCredits(ssl_t *ssl, int32 credits);
#endif

/******************************************************************************/
/*
	MatrixSSL internal cert functions
*/
typedef int32 (*sslCertCb_t)(void *, psX509Cert_t *, int32);
#ifndef USE_ONLY_PSK_CIPHER_SUITE	
extern int32 matrixValidateCerts(psPool_t *pool, psX509Cert_t *subjectCerts,
				psX509Cert_t *issuerCerts, char *expectedName,
				psX509Cert_t **foundIssuer);
extern int32 matrixUserCertValidator(ssl_t *ssl, int32 alert, 
				 psX509Cert_t *subjectCert, sslCertCb_t certCb);
#endif /* USE_ONLY_PSK_CIPHER_SUITE */

/******************************************************************************/
/*
	sslEncode.c and sslDecode.c
*/
extern int32 psWriteRecordInfo(ssl_t *ssl, unsigned char type, int32 len,
							 unsigned char *c, int32 hsType);
extern int32 psWriteHandshakeHeader(ssl_t *ssl, unsigned char type, int32 len, 
								int32 seq, int32 fragOffset, int32 fragLen,
								unsigned char *c);
extern int32 sslEncodeResponse(ssl_t *ssl, psBuf_t *out, uint32 *requiredLen);
extern int32 sslActivateReadCipher(ssl_t *ssl);
extern int32 sslActivateWriteCipher(ssl_t *ssl);
extern int32 sslUpdateHSHash(ssl_t *ssl, unsigned char *in, uint32 len);
extern int32 sslInitHSHash(ssl_t *ssl);
extern int32 sslSnapshotHSHash(ssl_t *ssl, unsigned char *out, int32 senderFlag);
extern int32 sslWritePad(unsigned char *p, unsigned char padLen);
extern int32 sslCreateKeys(ssl_t *ssl);
extern void sslResetContext(ssl_t *ssl);
extern void clearPkaAfter(ssl_t *ssl);
extern void clearFlightList(ssl_t *ssl);

#ifdef USE_SERVER_SIDE_SSL
extern int32 matrixRegisterSession(ssl_t *ssl);
extern int32 matrixResumeSession(ssl_t *ssl);
extern int32 matrixClearSession(ssl_t *ssl, int32 remove);
extern int32 matrixUpdateSession(ssl_t *ssl);
extern int32 matrixServerSetKeysSNI(ssl_t *ssl, char *host, int32 hostLen);

#ifdef USE_STATELESS_SESSION_TICKETS
extern int32 matrixSessionTicketLen(void);
extern int32 matrixCreateSessionTicket(ssl_t *ssl, unsigned char *out,
				int32 *outLen);
extern int32 matrixUnlockSessionTicket(ssl_t *ssl, unsigned char *in,
				int32 inLen);
extern int32 matrixSessionTicketLen(void);
#endif
#endif /* USE_SERVER_SIDE_SSL */



/*
	cipherSuite.c
*/
extern sslCipherSpec_t *sslGetCipherSpec(ssl_t *ssl, uint32 cid);
extern int32 sslGetCipherSpecListLen(ssl_t *ssl);
extern int32 sslGetCipherSpecList(ssl_t *ssl, unsigned char *c, int32 len,
				int32 addScsv);
#ifdef USE_RSA				
extern int32 csRsaEncryptPub(psPool_t *pool, psPubKey_t *key, 
			unsigned char *in, uint32 inlen, unsigned char *out, uint32 outlen,
			void *data);
#ifdef USE_SERVER_SIDE_SSL
extern int32 csRsaDecryptPub(psPool_t *pool, psPubKey_t *key, 
			unsigned char *in, uint32 inlen, unsigned char *out, uint32 outlen,
			void *data);
extern int32 csRsaEncryptPriv(psPool_t *pool, psPubKey_t *key, 
			unsigned char *in, uint32 inlen, unsigned char *out, uint32 outlen,
			void *data);
extern int32 csRsaDecryptPriv(psPool_t *pool, psPubKey_t *key, 
			unsigned char *in, uint32 inlen, unsigned char *out, uint32 outlen,
			void *data);			
#endif
#endif /* USE_RSA */	
#ifdef USE_CLIENT_SIDE_SSL
int32 csCheckCertAgainstCipherSuite(int32 sigAlg, int32 cipherType);
#endif
extern void matrixSslSetKexFlags(ssl_t *ssl);

#ifndef DISABLE_SSLV3
/******************************************************************************/
/*
	sslv3.c
*/
extern int32 sslGenerateFinishedHash(psDigestContext_t *md5,
				psDigestContext_t *sha1, unsigned char *masterSecret,
				unsigned char *out, int32 sender);

extern int32 sslDeriveKeys(ssl_t *ssl);

#ifdef USE_SHA_MAC
extern int32 ssl3HMACSha1(ssl_t *ssl, int32 mode, unsigned char *key, unsigned char *seq, 
						unsigned char type, unsigned char *data, uint32 len,
						unsigned char *mac);
#endif /* USE_SHA_MAC */

#ifdef USE_MD5_MAC
extern int32 ssl3HMACMd5(ssl_t *ssl, int32 mode, unsigned char *key, unsigned char *seq, 
						unsigned char type, unsigned char *data, uint32 len,
						unsigned char *mac);
#endif /* USE_MD5_MAC */
#endif /* DISABLE_SSLV3 */

#ifdef USE_TLS
/******************************************************************************/
/*
	tls.c
*/
extern int32 tlsDeriveKeys(ssl_t *ssl);

extern int32 tlsHMACSha1(ssl_t *ssl, int32 mode, unsigned char type,	
						unsigned char *data, uint32 len, unsigned char *mac);

extern int32 tlsHMACMd5(ssl_t *ssl, int32 mode, unsigned char type,	
						unsigned char *data, uint32 len, unsigned char *mac);
#ifdef  USE_SHA256
extern int32 tlsHMACSha2(ssl_t *ssl, int32 mode, unsigned char type,	
						unsigned char *data, uint32 len, unsigned char *mac,
						int32 hashSize);
#endif						
#ifdef USE_TLS_1_2						
#if defined(USE_SERVER_SIDE_SSL) && defined(USE_CLIENT_AUTH)
extern int32 sslSha1RetrieveHSHash(ssl_t *ssl, unsigned char *out);
#ifdef USE_SHA384
extern int32 sslSha384RetrieveHSHash(ssl_t *ssl, unsigned char *out);
#endif
#endif
#ifdef USE_CLIENT_SIDE_SSL
extern void sslSha1SnapshotHSHash(ssl_t *ssl, unsigned char *out);
#ifdef USE_SHA384
extern void sslSha384SnapshotHSHash(ssl_t *ssl, unsigned char *out);
#endif
#endif
#endif /* USE_TLS_1_2 */


extern int32 prf(unsigned char *sec, uint32 secLen, unsigned char *seed,
			   uint32 seedLen, unsigned char *out, uint32 outLen);
#ifdef USE_TLS_1_2
extern int32 prf2(unsigned char *sec, uint32 secLen, unsigned char *seed,
			   uint32 seedLen, unsigned char *out, uint32 outLen, uint32 flags);
#endif /* USE_NATIVE_TLS_ALGS || USE_NATIVE_TLS_HS_HASH */
#endif /* USE_TLS */


#ifdef USE_AES_CIPHER_SUITE
extern int32 csAesInit(sslSec_t *sec, int32 type, uint32 keysize);
extern int32 csAesEncrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len);
extern int32 csAesDecrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len);
#ifdef USE_AES_GCM
extern int32 csAesGcmInit(sslSec_t *sec, int32 type, uint32 keysize);
extern int32 csAesGcmEncrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len);
extern int32 csAesGcmDecrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len);
#endif
#endif /* USE_AES_CIPHER_SUITE */
#ifdef USE_3DES_CIPHER_SUITE
extern int32 csDes3Encrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len);
extern int32 csDes3Decrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len);
#endif /* USE_3DES_CIPHER_SUITE */
#ifdef USE_ARC4_CIPHER_SUITE
extern int32 csArc4Encrypt(void *ssl, unsigned char *pt,unsigned char *ct,
					uint32 len);
extern int32 csArc4Decrypt(void *ssl, unsigned char *pt,unsigned char *ct,
					uint32 len);
#endif /* USE_ARC4_CIPHER_SUITE */
#ifdef USE_SEED_CIPHER_SUITE
extern int32 csSeedEncrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len);
extern int32 csSeedDecrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len);
#endif /* USE_SEED_CIPHER_SUITE */

#ifdef USE_IDEA_CIPHER_SUITE
extern int32 csIdeaInit(sslSec_t *sec, int32 type, uint32 keysize);
extern int32 csIdeaEncrypt(void *ssl, unsigned char *pt,
					 unsigned char *ct, uint32 len);
extern int32 csIdeaDecrypt(void *ssl, unsigned char *ct,
					 unsigned char *pt, uint32 len);
#endif /* USE_IDEA_CIPHER_SUITE */

#ifdef USE_PSK_CIPHER_SUITE
/*
	TLS implementations supporting these ciphersuites MUST support
	arbitrary PSK identities up to 128 octets in length, and arbitrary
	PSKs up to 64 octets in length.  Supporting longer identities and
	keys is RECOMMENDED.
*/
#define SSL_PSK_MAX_KEY_SIZE 128
#define SSL_PSK_MAX_ID_SIZE 256

#define SSL_PSK_MAX_HINT_SIZE 0 /* ServerKeyExchange hint is non-standard */ 

extern int32 matrixSslPskGetKey(ssl_t *ssl, unsigned char *id, uint32 idLen,
			unsigned char **key, uint32 *keyLen);
extern int32 matrixSslPskGetKeyId(ssl_t *ssl, unsigned char **id, uint32 *idLen,
			char *hint, uint32 hintLen);
extern int32 matrixPskGetHint(ssl_t *ssl, char **hint, uint32 *hintLen);
#endif /* USE_PSK_CIPHER_SUITE */


#ifdef USE_ECC_CIPHER_SUITE
#define ELLIPTIC_CURVE_EXT 10
#define ELLIPTIC_POINTS_EXT 11
extern int32 eccSuitesSupported(ssl_t *ssl, uint16 cipherSpecLen,
		uint32 cipherSpecs[]);
#endif /* USE_ECC_CIPHER_SUITE */

#ifdef USE_STATELESS_SESSION_TICKETS
#define SESSION_TICKET_EXT	35
#endif


/******************************************************************************/


#ifdef USE_MATRIXSSL_STATS

#define CH_RECV_STAT 1
#define CH_SENT_STAT 2
#define SH_RECV_STAT 3
#define SH_SENT_STAT 4
#define ALERT_SENT_STAT 5
#define RESUMPTIONS_STAT 6
#define FAILED_RESUMPTIONS_STAT 7
#define APP_DATA_RECV_STAT 8
#define APP_DATA_SENT_STAT 9

extern void matrixsslUpdateStat(ssl_t *ssl, int32 type, int32 value);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _h_MATRIXSSLLIB */

/******************************************************************************/

