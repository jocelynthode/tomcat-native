/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SSL_PRIVATE_H
#define SSL_PRIVATE_H

/* Exclude unused OpenSSL features
 * even if the OpenSSL supports them
 */
#ifndef OPENSSL_NO_IDEA
#define OPENSSL_NO_IDEA
#endif
#ifndef OPENSSL_NO_KRB5
#define OPENSSL_NO_KRB5
#endif
#ifndef OPENSSL_NO_MDC2
#define OPENSSL_NO_MDC2
#endif
#ifndef OPENSSL_NO_RC5
#define OPENSSL_NO_RC5
#endif

/* OpenSSL headers */
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
/* Avoid tripping over an engine build installed globally and detected
 * when the user points at an explicit non-engine flavor of OpenSSL
 */
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#ifndef RAND_MAX
#include <limits.h>
#define RAND_MAX INT_MAX
#endif

#define SSL_AIDX_RSA     (0)
#define SSL_AIDX_DSA     (1)
#define SSL_AIDX_ECC     (3)
#define SSL_AIDX_MAX     (4)

/*
 * Define the SSL options
 */
#define SSL_OPT_NONE            (0)
#define SSL_OPT_RELSET          (1<<0)
#define SSL_OPT_STDENVVARS      (1<<1)
#define SSL_OPT_EXPORTCERTDATA  (1<<3)
#define SSL_OPT_FAKEBASICAUTH   (1<<4)
#define SSL_OPT_STRICTREQUIRE   (1<<5)
#define SSL_OPT_OPTRENEGOTIATE  (1<<6)
#define SSL_OPT_ALL             (SSL_OPT_STDENVVARS|SSL_OPT_EXPORTCERTDATA|SSL_OPT_FAKEBASICAUTH|SSL_OPT_STRICTREQUIRE|SSL_OPT_OPTRENEGOTIATE)

/*
 * Define the SSL Protocol options
 */
#define SSL_PROTOCOL_NONE       (0)
#define SSL_PROTOCOL_SSLV2      (1<<0)
#define SSL_PROTOCOL_SSLV3      (1<<1)
#define SSL_PROTOCOL_TLSV1      (1<<2)
#define SSL_PROTOCOL_TLSV1_1    (1<<3)
#define SSL_PROTOCOL_TLSV1_2    (1<<4)

#define SSL_MODE_CLIENT         (0)
#define SSL_MODE_SERVER         (1)
#define SSL_MODE_COMBINED       (2)

#define SSL_BIO_FLAG_RDONLY     (1<<0)
#define SSL_BIO_FLAG_CALLBACK   (1<<1)
#define SSL_DEFAULT_CACHE_SIZE  (256)
#define SSL_DEFAULT_VHOST_NAME  ("_default_:443")
#define SSL_MAX_STR_LEN         (2048)
#define SSL_MAX_PASSWORD_LEN    (256)

#define SSL_CVERIFY_UNSET           (-1)
#define SSL_CVERIFY_NONE            (0)
#define SSL_CVERIFY_OPTIONAL        (1)
#define SSL_CVERIFY_REQUIRE         (2)
#define SSL_CVERIFY_OPTIONAL_NO_CA  (3)
#define SSL_VERIFY_PEER_STRICT      (SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT)

#define SSL_SHUTDOWN_TYPE_UNSET     (0)
#define SSL_SHUTDOWN_TYPE_STANDARD  (1)
#define SSL_SHUTDOWN_TYPE_UNCLEAN   (2)
#define SSL_SHUTDOWN_TYPE_ACCURATE  (3)

#define SSL_TO_APR_ERROR(X)         (APR_OS_START_USERERR + 1000 + X)

#define SSL_INFO_SESSION_ID                 (0x0001)
#define SSL_INFO_CIPHER                     (0x0002)
#define SSL_INFO_CIPHER_USEKEYSIZE          (0x0003)
#define SSL_INFO_CIPHER_ALGKEYSIZE          (0x0004)
#define SSL_INFO_CIPHER_VERSION             (0x0005)
#define SSL_INFO_CIPHER_DESCRIPTION         (0x0006)
#define SSL_INFO_PROTOCOL                   (0x0007)

#define SSL_INFO_CLIENT_S_DN                (0x0010)
#define SSL_INFO_CLIENT_I_DN                (0x0020)
#define SSL_INFO_SERVER_S_DN                (0x0040)
#define SSL_INFO_SERVER_I_DN                (0x0080)

#define SSL_INFO_DN_COUNTRYNAME             (0x0001)
#define SSL_INFO_DN_STATEORPROVINCENAME     (0x0002)
#define SSL_INFO_DN_LOCALITYNAME            (0x0003)
#define SSL_INFO_DN_ORGANIZATIONNAME        (0x0004)
#define SSL_INFO_DN_ORGANIZATIONALUNITNAME  (0x0005)
#define SSL_INFO_DN_COMMONNAME              (0x0006)
#define SSL_INFO_DN_TITLE                   (0x0007)
#define SSL_INFO_DN_INITIALS                (0x0008)
#define SSL_INFO_DN_GIVENNAME               (0x0009)
#define SSL_INFO_DN_SURNAME                 (0x000A)
#define SSL_INFO_DN_DESCRIPTION             (0x000B)
#define SSL_INFO_DN_UNIQUEIDENTIFIER        (0x000C)
#define SSL_INFO_DN_EMAILADDRESS            (0x000D)

#define SSL_INFO_CLIENT_MASK                (0x0100)

#define SSL_INFO_CLIENT_M_VERSION           (0x0101)
#define SSL_INFO_CLIENT_M_SERIAL            (0x0102)
#define SSL_INFO_CLIENT_V_START             (0x0103)
#define SSL_INFO_CLIENT_V_END               (0x0104)
#define SSL_INFO_CLIENT_A_SIG               (0x0105)
#define SSL_INFO_CLIENT_A_KEY               (0x0106)
#define SSL_INFO_CLIENT_CERT                (0x0107)
#define SSL_INFO_CLIENT_V_REMAIN            (0x0108)

#define SSL_INFO_SERVER_MASK                (0x0200)

#define SSL_INFO_SERVER_M_VERSION           (0x0201)
#define SSL_INFO_SERVER_M_SERIAL            (0x0202)
#define SSL_INFO_SERVER_V_START             (0x0203)
#define SSL_INFO_SERVER_V_END               (0x0204)
#define SSL_INFO_SERVER_A_SIG               (0x0205)
#define SSL_INFO_SERVER_A_KEY               (0x0206)
#define SSL_INFO_SERVER_CERT                (0x0207)
#define SSL_INFO_CLIENT_CERT_CHAIN          (0x0400)

#define SSL_VERIFY_ERROR_IS_OPTIONAL(errnum) \
   ((errnum == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) \
    || (errnum == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) \
    || (errnum == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) \
    || (errnum == X509_V_ERR_CERT_UNTRUSTED) \
    || (errnum == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE))

#define SSL_DEFAULT_PASS_PROMPT "Some of your private key files are encrypted for security reasons.\n"  \
                                "In order to read them you have to provide the pass phrases.\n"         \
                                "Enter password :"

#define SSL_CIPHERS_ALWAYS_DISABLED         ("!aNULL:!eNULL:!EXP:")

#if defined(SSL_OP_NO_TLSv1_1)
#define HAVE_TLSV1_1
#endif

#if defined(SSL_OP_NO_TLSv1_2)
#define HAVE_TLSV1_2
#endif

/**
 * The following features all depend on TLS extension support.
 * Within this block, check again for features (not version numbers).
 */
#if !defined(OPENSSL_NO_TLSEXT) && defined(SSL_set_tlsext_host_name)

#define HAVE_TLSEXT

/* ECC */
#if !defined(OPENSSL_NO_EC) && defined(TLSEXT_ECPOINTFORMAT_uncompressed)
#define HAVE_ECC
#endif

/* OCSP stapling */
#if !defined(OPENSSL_NO_OCSP) && defined(SSL_CTX_set_tlsext_status_cb)
#define HAVE_OCSP_STAPLING
#define OCSP_STATUS_OK        0
#define OCSP_STATUS_REVOKED   1
#define OCSP_STATUS_UNKNOWN   2
#endif

#endif /* !defined(OPENSSL_NO_TLSEXT) && defined(SSL_set_tlsext_host_name) */

#define MAX_ALPN_NPN_PROTO_SIZE 65535
#define SSL_SELECTOR_FAILURE_CHOOSE_MY_LAST_PROTOCOL            1

typedef struct {
    /* client can have any number of cert/key pairs */
    const char  *cert_file;
    const char  *cert_path;
    STACK_OF(X509_INFO) *certs;
} ssl_pkc_t;



typedef struct {
    char            password[SSL_MAX_PASSWORD_LEN];
    const char     *prompt;
    tcn_callback_t cb;
} tcn_pass_cb_t;

extern tcn_pass_cb_t tcn_password_callback;

typedef struct {
    SSL_CTX         *ctx;
    BIO             *bio_os;
    BIO             *bio_is;

    unsigned char   context_id[SHA_DIGEST_LENGTH];

    int             protocol;
    /* we are one or the other */
    int             mode;

    /* certificate revocation list */
    X509_STORE      *crl;
    /* pointer to the context verify store */
    X509_STORE      *store;
    X509            *certs[SSL_AIDX_MAX];
    EVP_PKEY        *keys[SSL_AIDX_MAX];

    int             ca_certs;
    int             shutdown_type;
    char            *rand_file;

    const char      *cipher_suite;
    /* for client or downstream server authentication */
    int             verify_depth;
    int             verify_mode;

    /* for client: List of protocols to request via ALPN.
     * for server: List of protocols to accept via ALPN.
     */
    /* member alpn is array of protocol strings encoded as a list of bytes
     * of length alpnlen, each protocol string is prepended with a byte
     * containing the protocol string length (max 255), then follows the
     * protocol string itself.
     */
    char            *alpn;
    int             alpnlen;
    /* Add from netty-tcnative */
    /* certificate verifier callback */
    jobject verifier;
    jmethodID verifier_method;

    unsigned char   *next_proto_data;
    unsigned int    next_proto_len;
    int             next_selector_failure_behavior;

    /* Holds the alpn protocols, each of them prefixed with the len of the protocol */
    unsigned char   *alpn_proto_data;
    unsigned int    alpn_proto_len;
    /* End add from netty-tcnative */
    jobject session_context;
} tcn_ssl_ctxt_t;

typedef struct {
    tcn_ssl_ctxt_t *ctx;
    SSL            *ssl;
    X509           *peer;
    int             shutdown_type;
    jobject         alpn_selection_callback;
    /* Track the handshake/renegotiation state for the connection so
     * that all client-initiated renegotiations can be rejected, as a
     * partial fix for CVE-2009-3555.
     */
    enum {
        RENEG_INIT = 0, /* Before initial handshake */
        RENEG_REJECT,   /* After initial handshake; any client-initiated
                         * renegotiation should be rejected
                         */
        RENEG_ALLOW,    /* A server-initated renegotiation is taking
                         * place (as dictated by configuration)
                         */
        RENEG_ABORT     /* Renegotiation initiated by client, abort the
                         * connection
                         */
    } reneg_state;
} tcn_ssl_conn_t;


/*
 *  Additional Functions
 */
void        SSL_init_app_data2_3_idx(void);
/* The app_data2 is used to store the tcn_ssl_ctxt_t pointer for the SSL instance. */ 
tcn_ssl_ctxt_t *SSL_get_app_data2(SSL *ssl);
void        SSL_set_app_data2(SSL *, void *);
/* The app_data3 is used to store the handshakeCount pointer for the SSL instance. */
void       *SSL_get_app_data3(const SSL *);
void        SSL_set_app_data3(SSL *, void *);
int         SSL_password_prompt(tcn_pass_cb_t *);
int         SSL_password_callback(char *, int, int, void *);
void        SSL_BIO_close(BIO *);
void        SSL_BIO_doref(BIO *);
DH         *SSL_get_dh_params(unsigned keylen);
DH         *SSL_dh_GetParamFromFile(const char *);
#ifdef HAVE_ECC
EC_GROUP   *SSL_ec_GetParamFromFile(const char *);
#endif
DH         *SSL_callback_tmp_DH(SSL *, int, int);
void        SSL_callback_handshake(const SSL *, int, int);
int         SSL_CTX_use_certificate_chain(SSL_CTX *, const char *, int);
int         SSL_callback_SSL_verify(int, X509_STORE_CTX *);
int         SSL_rand_seed(const char *file);
int         SSL_callback_next_protos(SSL *, const unsigned char **, unsigned int *, void *);
int         SSL_callback_select_next_proto(SSL *, unsigned char **, unsigned char *, const unsigned char *, unsigned int,void *);
int         SSL_callback_alpn_select_proto(SSL *, const unsigned char **, unsigned char *, const unsigned char *, unsigned int, void *);


#endif /* SSL_PRIVATE_H */
