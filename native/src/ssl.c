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


#include <dlfcn.h>

#if defined(SSL_OP_NO_TLSv1_1)
#define HAVE_TLSV1_1
#endif

#if defined(SSL_OP_NO_TLSv1_2)
#define HAVE_TLSV1_2
#endif

#ifdef __APPLE__
#define LIBCRYPTO_NAME "libcrypto.dylib"
#else
#define LIBCRYPTO_NAME "libcrypto.so"
#endif

#ifdef __APPLE__
#define LIBSSL_NAME "libssl.dylib"
#else
#define LIBSSL_NAME "libssl.so"
#endif


#include "tcn.h"

#ifdef HAVE_OPENSSL
#include "ssl_private.h"

static int ssl_initialized = 0;
static char *ssl_global_rand_file = NULL;

ENGINE *tcn_ssl_engine = NULL;
tcn_pass_cb_t tcn_password_callback;


/* From netty-tcnative */
static jclass byteArrayClass;
static jclass stringClass;


static jclass sessionContextClass;
static jmethodID sessionInit;
static jmethodID sessionRemove;


/*
 * supported_ssl_opts is a bitmask that contains all supported SSL_OP_*
 * options at compile-time. This is used in hasOp to determine which
 * SSL_OP_* options are available at runtime.
 *
 * Note that at least up through OpenSSL 0.9.8o, checking SSL_OP_ALL will
 * return JNI_FALSE because SSL_OP_ALL is a mask that covers all bug
 * workarounds for OpenSSL including future workarounds that are defined
 * to be in the least-significant 3 nibbles of the SSL_OP_* bit space.
 *
 * This implementation has chosen NOT to simply set all those lower bits
 * so that the return value for SSL_OP_FUTURE_WORKAROUND will only be
 * reported by versions that actually support that specific workaround.
 */
static const jint supported_ssl_opts = 0
/*
  Specifically skip SSL_OP_ALL
#ifdef SSL_OP_ALL
     | SSL_OP_ALL
#endif
*/
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
     | SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
#endif

#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
     | SSL_OP_CIPHER_SERVER_PREFERENCE
#endif

#ifdef SSL_OP_CRYPTOPRO_TLSEXT_BUG
     | SSL_OP_CRYPTOPRO_TLSEXT_BUG
#endif

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
     | SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
#endif

#ifdef SSL_OP_EPHEMERAL_RSA
     | SSL_OP_EPHEMERAL_RSA
#endif

#ifdef SSL_OP_LEGACY_SERVER_CONNECT
     | SSL_OP_LEGACY_SERVER_CONNECT
#endif

#ifdef SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
     | SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
#endif

#ifdef SSL_OP_MICROSOFT_SESS_ID_BUG
     | SSL_OP_MICROSOFT_SESS_ID_BUG
#endif

#ifdef SSL_OP_MSIE_SSLV2_RSA_PADDING
     | SSL_OP_MSIE_SSLV2_RSA_PADDING
#endif

#ifdef SSL_OP_NETSCAPE_CA_DN_BUG
     | SSL_OP_NETSCAPE_CA_DN_BUG
#endif

#ifdef SSL_OP_NETSCAPE_CHALLENGE_BUG
     | SSL_OP_NETSCAPE_CHALLENGE_BUG
#endif

#ifdef SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
     | SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
#endif

#ifdef SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
     | SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
#endif

#ifdef SSL_OP_NO_COMPRESSION
     | SSL_OP_NO_COMPRESSION
#endif

#ifdef SSL_OP_NO_QUERY_MTU
     | SSL_OP_NO_QUERY_MTU
#endif

#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
     | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
#endif

#ifdef SSL_OP_NO_SSLv2
     | SSL_OP_NO_SSLv2
#endif

#ifdef SSL_OP_NO_SSLv3
     | SSL_OP_NO_SSLv3
#endif

#ifdef SSL_OP_NO_TICKET
     | SSL_OP_NO_TICKET
#endif

#ifdef SSL_OP_NO_TLSv1
     | SSL_OP_NO_TLSv1
#endif

#ifdef SSL_OP_PKCS1_CHECK_1
     | SSL_OP_PKCS1_CHECK_1
#endif

#ifdef SSL_OP_PKCS1_CHECK_2
     | SSL_OP_PKCS1_CHECK_2
#endif

#ifdef SSL_OP_NO_TLSv1_1
     | SSL_OP_NO_TLSv1_1
#endif

#ifdef SSL_OP_NO_TLSv1_2
     | SSL_OP_NO_TLSv1_2
#endif

#ifdef SSL_OP_SINGLE_DH_USE
     | SSL_OP_SINGLE_DH_USE
#endif

#ifdef SSL_OP_SINGLE_ECDH_USE
     | SSL_OP_SINGLE_ECDH_USE
#endif

#ifdef SSL_OP_SSLEAY_080_CLIENT_DH_BUG
     | SSL_OP_SSLEAY_080_CLIENT_DH_BUG
#endif

#ifdef SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
     | SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
#endif

#ifdef SSL_OP_TLS_BLOCK_PADDING_BUG
     | SSL_OP_TLS_BLOCK_PADDING_BUG
#endif

#ifdef SSL_OP_TLS_D5_BUG
     | SSL_OP_TLS_D5_BUG
#endif

#ifdef SSL_OP_TLS_ROLLBACK_BUG
     | SSL_OP_TLS_ROLLBACK_BUG
#endif
     | 0;


/* containers for libssl/libcrypto functions */
ssl_dynamic_methods ssl_methods;
crypto_dynamic_methods crypto_methods;

/*
 * Grab well-defined DH parameters from OpenSSL, see the get_rfc*
 * functions in <openssl/bn.h> for all available primes.
 */
static DH *make_dh_params(BIGNUM *(*prime)(BIGNUM *), const char *gen)
{
    DH *dh = DH_new();

    if (!dh) {
        return NULL;
    }
    dh->p = prime(NULL);
    BN_dec2bn(&dh->g, gen);
    if (!dh->p || !dh->g) {
        DH_free(dh);
        return NULL;
    }
    return dh;
}

/* Storage and initialization for DH parameters.
 * The prime function of each dhparam will be set when loading the library.
 */
static struct dhparam {
    BIGNUM *(* prime)(BIGNUM *); /* function to generate... */
    DH *dh;                           /* ...this, used for keys.... */
    const unsigned int min;           /* ...of length >= this. */
} dhparams[] = {
    { 0, NULL, 6145 },
    { 0, NULL, 4097 },
    { 0, NULL, 3073 },
    { 0, NULL, 2049 },
    { 0, NULL, 1025 },
    { 0, NULL, 0 }
};

static void init_dh_params(void)
{
    unsigned n;

    for (n = 0; n < sizeof(dhparams)/sizeof(dhparams[0]); n++)
        dhparams[n].dh = make_dh_params(dhparams[n].prime, "2");
}

static void free_dh_params(void)
{
    unsigned n;

    /* DH_free() is a noop for a NULL parameter, so these are harmless
     * in the (unexpected) case where these variables are already
     * NULL. */
    for (n = 0; n < sizeof(dhparams)/sizeof(dhparams[0]); n++) {
        DH_free(dhparams[n].dh);
        dhparams[n].dh = NULL;
    }
}

/* Hand out the same DH structure though once generated as we leak
 * memory otherwise and freeing the structure up after use would be
 * hard to track and in fact is not needed at all as it is safe to
 * use the same parameters over and over again security wise (in
 * contrast to the keys itself) and code safe as the returned structure
 * is duplicated by OpenSSL anyway. Hence no modification happens
 * to our copy. */
DH *SSL_get_dh_params(unsigned keylen)
{
    unsigned n;

    for (n = 0; n < sizeof(dhparams)/sizeof(dhparams[0]); n++)
        if (keylen >= dhparams[n].min)
            return dhparams[n].dh;

    return NULL; /* impossible to reach. */
}

void session_init(JNIEnv *e) {
    jclass sClazz = (*e)->FindClass(e, "io/undertow/openssl/OpenSSLSessionContext");
    sessionContextClass = (jclass) (*e)->NewGlobalRef(e, sClazz);
    sessionInit = (*e)->GetMethodID(e, sessionContextClass, "sessionCreatedCallback", "(JJ[B)V");
    sessionRemove = (*e)->GetMethodID(e, sessionContextClass, "sessionRemovedCallback", "([B)V");
}


#define REQUIRE_SSL_SYMBOL(symb) ssl_methods.symb = dlsym(ssl, #symb); if(ssl_methods.symb == 0) { printf("Failed to find %s", #symb); throwIllegalStateException(e, "Could not load required symbol from libssl: " #symb); return 1;}
#define GET_SSL_SYMBOL(symb) ssl_methods.symb = dlsym(ssl, #symb);
#define REQUIRE_CRYPTO_SYMBOL(symb) crypto_methods.symb = dlsym(crypto, #symb); if(crypto_methods.symb == 0) {printf("Failed to find %s", #symb); throwIllegalStateException(e, "Could not load required symbol from libcrypto: " #symb); return 1;}
#define GET_CRYPTO_SYMBOL(symb) crypto_methods.symb = dlsym(crypto, #symb);

int load_openssl_dynamic_methods(JNIEnv *e, const char * path) {
    void * ssl;
    if(path == NULL) {
        ssl = dlopen(LIBSSL_NAME, RTLD_LAZY);
    } else {
        int pathLen = strlen(path);
        int size = (strlen(LIBSSL_NAME) + pathLen + 1);
        char * full = malloc(sizeof(char) * size);
        strncpy(full, path, size);
        strncpy(full + pathLen, LIBSSL_NAME, size - pathLen);
        ssl = dlopen(full, RTLD_LAZY);
    }
    REQUIRE_SSL_SYMBOL(SSLeay);
    REQUIRE_SSL_SYMBOL(SSL_CIPHER_get_name);
    REQUIRE_SSL_SYMBOL(SSL_CTX_callback_ctrl);
    REQUIRE_SSL_SYMBOL(SSL_CTX_check_private_key);
    REQUIRE_SSL_SYMBOL(SSL_CTX_ctrl);
    REQUIRE_SSL_SYMBOL(SSL_CTX_free);
    REQUIRE_SSL_SYMBOL(SSL_CTX_get_cert_store);
    REQUIRE_SSL_SYMBOL(SSL_CTX_get_client_CA_list);
    REQUIRE_SSL_SYMBOL(SSL_CTX_get_ex_data);
    REQUIRE_SSL_SYMBOL(SSL_CTX_get_timeout);
    REQUIRE_SSL_SYMBOL(SSL_CTX_load_verify_locations);
    REQUIRE_SSL_SYMBOL(SSL_CTX_new);
    REQUIRE_SSL_SYMBOL(SSL_CTX_sess_set_new_cb);
    REQUIRE_SSL_SYMBOL(SSL_CIPHER_get_name);
    REQUIRE_SSL_SYMBOL(SSL_CTX_callback_ctrl);
    REQUIRE_SSL_SYMBOL(SSL_CTX_get_ex_data);
    REQUIRE_SSL_SYMBOL(SSL_CTX_sess_set_remove_cb);
    GET_SSL_SYMBOL(SSL_CTX_set_alpn_protos);
    GET_SSL_SYMBOL(SSL_CTX_set_alpn_select_cb);
    GET_SSL_SYMBOL(SSL_get0_alpn_selected);
    REQUIRE_SSL_SYMBOL(SSL_CTX_set_cert_verify_callback);
    REQUIRE_SSL_SYMBOL(SSL_CTX_set_cipher_list);
    REQUIRE_SSL_SYMBOL(SSL_CTX_set_default_verify_paths);
    REQUIRE_SSL_SYMBOL(SSL_CTX_set_ex_data);
    REQUIRE_SSL_SYMBOL(SSL_CTX_set_info_callback);
    REQUIRE_SSL_SYMBOL(SSL_CTX_set_session_id_context);
    REQUIRE_SSL_SYMBOL(SSL_CTX_set_timeout);
    REQUIRE_SSL_SYMBOL(SSL_CTX_set_verify);
    REQUIRE_SSL_SYMBOL(SSL_CTX_use_PrivateKey);
    REQUIRE_SSL_SYMBOL(SSL_CTX_use_certificate);
    REQUIRE_SSL_SYMBOL(SSL_SESSION_free);
    REQUIRE_SSL_SYMBOL(SSL_SESSION_get_id);
    REQUIRE_SSL_SYMBOL(SSL_SESSION_get_time);
    REQUIRE_SSL_SYMBOL(SSL_add_file_cert_subjects_to_stack);
    REQUIRE_SSL_SYMBOL(SSL_ctrl);
    REQUIRE_SSL_SYMBOL(SSL_do_handshake);
    REQUIRE_SSL_SYMBOL(SSL_free);
    REQUIRE_SSL_SYMBOL(SSL_get_ciphers);
    REQUIRE_SSL_SYMBOL(SSL_get_current_cipher);
    REQUIRE_SSL_SYMBOL(SSL_get_ex_data);
    REQUIRE_SSL_SYMBOL(SSL_get_ex_data_X509_STORE_CTX_idx);
    REQUIRE_SSL_SYMBOL(SSL_get_ex_new_index);
    REQUIRE_SSL_SYMBOL(SSL_get_peer_cert_chain);
    REQUIRE_SSL_SYMBOL(SSL_get_peer_certificate);
    REQUIRE_SSL_SYMBOL(SSL_get_privatekey);
    REQUIRE_SSL_SYMBOL(SSL_get_servername);
    REQUIRE_SSL_SYMBOL(SSL_get_session);
    REQUIRE_SSL_SYMBOL(SSL_get_shutdown);
    REQUIRE_SSL_SYMBOL(SSL_get_version);
    REQUIRE_SSL_SYMBOL(SSL_library_init);
    REQUIRE_SSL_SYMBOL(SSL_load_client_CA_file);
    REQUIRE_SSL_SYMBOL(SSL_load_error_strings);
    REQUIRE_SSL_SYMBOL(SSL_new);
    REQUIRE_SSL_SYMBOL(SSL_pending);
    REQUIRE_SSL_SYMBOL(SSL_read);
    REQUIRE_SSL_SYMBOL(SSL_renegotiate);
    REQUIRE_SSL_SYMBOL(SSL_renegotiate_pending);
    REQUIRE_SSL_SYMBOL(SSL_set_SSL_CTX);
    REQUIRE_SSL_SYMBOL(SSL_set_accept_state);
    REQUIRE_SSL_SYMBOL(SSL_set_bio);
    REQUIRE_SSL_SYMBOL(SSL_set_cipher_list);
    REQUIRE_SSL_SYMBOL(SSL_set_connect_state);
    REQUIRE_SSL_SYMBOL(SSL_set_ex_data);
    REQUIRE_SSL_SYMBOL(SSL_set_verify);
    REQUIRE_SSL_SYMBOL(SSL_set_verify_result);
    REQUIRE_SSL_SYMBOL(SSL_shutdown);
    REQUIRE_SSL_SYMBOL(SSL_state);
    REQUIRE_SSL_SYMBOL(SSL_write);
    REQUIRE_SSL_SYMBOL(SSLv23_client_method);
    REQUIRE_SSL_SYMBOL(SSLv23_method);
    REQUIRE_SSL_SYMBOL(SSLv23_server_method);
    REQUIRE_SSL_SYMBOL(SSLv3_client_method);
    REQUIRE_SSL_SYMBOL(SSLv3_method);
    REQUIRE_SSL_SYMBOL(SSLv3_server_method);
    GET_SSL_SYMBOL(TLSv1_1_client_method);
    GET_SSL_SYMBOL(TLSv1_1_method);
    GET_SSL_SYMBOL(TLSv1_1_server_method);
    GET_SSL_SYMBOL(TLSv1_2_client_method);
    GET_SSL_SYMBOL(TLSv1_2_method);
    GET_SSL_SYMBOL(TLSv1_2_server_method);
    GET_SSL_SYMBOL(TLSv1_client_method);
    GET_SSL_SYMBOL(TLSv1_method);
    GET_SSL_SYMBOL(TLSv1_server_method);
    GET_SSL_SYMBOL(TLS_client_method);
    GET_SSL_SYMBOL(TLS_server_method);
    GET_SSL_SYMBOL(TLS_method);
    REQUIRE_SSL_SYMBOL(SSL_CTX_set_client_CA_list);

    void * crypto = dlopen(LIBCRYPTO_NAME, RTLD_LAZY);
    if(path == NULL) {
        crypto = dlopen(LIBCRYPTO_NAME, RTLD_LAZY);
    } else {
        int pathLen = strlen(path);
        int size = (strlen(LIBCRYPTO_NAME) + pathLen + 1);
        char * full = malloc(sizeof(char) * size);
        strncpy(full, path, size);
        strncpy(full + pathLen, LIBCRYPTO_NAME, size - pathLen);
        crypto = dlopen(full, RTLD_LAZY);
    }


    REQUIRE_CRYPTO_SYMBOL(ASN1_INTEGER_cmp);
    REQUIRE_CRYPTO_SYMBOL(BIO_ctrl);
    REQUIRE_CRYPTO_SYMBOL(BIO_ctrl_pending);
    REQUIRE_CRYPTO_SYMBOL(BIO_free);
    REQUIRE_CRYPTO_SYMBOL(BIO_new);
    REQUIRE_CRYPTO_SYMBOL(BIO_new_file);
    REQUIRE_CRYPTO_SYMBOL(BIO_new_bio_pair);
    REQUIRE_CRYPTO_SYMBOL(BIO_printf);
    REQUIRE_CRYPTO_SYMBOL(BIO_read);
    REQUIRE_CRYPTO_SYMBOL(BIO_s_file);
    REQUIRE_CRYPTO_SYMBOL(BIO_s_mem);
    REQUIRE_CRYPTO_SYMBOL(BIO_write);
    REQUIRE_CRYPTO_SYMBOL(CRYPTO_free);
    REQUIRE_CRYPTO_SYMBOL(CRYPTO_num_locks);
    REQUIRE_CRYPTO_SYMBOL(CRYPTO_set_dynlock_create_callback);
    REQUIRE_CRYPTO_SYMBOL(CRYPTO_set_dynlock_destroy_callback);
    REQUIRE_CRYPTO_SYMBOL(CRYPTO_set_dynlock_lock_callback);
    REQUIRE_CRYPTO_SYMBOL(CRYPTO_set_id_callback);
    REQUIRE_CRYPTO_SYMBOL(CRYPTO_set_locking_callback);
    REQUIRE_CRYPTO_SYMBOL(CRYPTO_set_mem_functions);
    REQUIRE_CRYPTO_SYMBOL(ERR_error_string);
    REQUIRE_CRYPTO_SYMBOL(ERR_get_error);
    REQUIRE_CRYPTO_SYMBOL(ERR_load_crypto_strings);
    REQUIRE_CRYPTO_SYMBOL(EVP_Digest);
    REQUIRE_CRYPTO_SYMBOL(EVP_PKEY_bits);
    REQUIRE_CRYPTO_SYMBOL(EVP_PKEY_free);
    REQUIRE_CRYPTO_SYMBOL(EVP_PKEY_type);
    REQUIRE_CRYPTO_SYMBOL(EVP_sha1);
    REQUIRE_CRYPTO_SYMBOL(OPENSSL_add_all_algorithms_noconf);
    REQUIRE_CRYPTO_SYMBOL(OPENSSL_load_builtin_modules);
    REQUIRE_CRYPTO_SYMBOL(PEM_read_bio_PrivateKey);
    REQUIRE_CRYPTO_SYMBOL(X509_CRL_verify);
    REQUIRE_CRYPTO_SYMBOL(X509_LOOKUP_ctrl);
    REQUIRE_CRYPTO_SYMBOL(X509_LOOKUP_file);
    REQUIRE_CRYPTO_SYMBOL(X509_LOOKUP_hash_dir);
    REQUIRE_CRYPTO_SYMBOL(X509_OBJECT_free_contents);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_CTX_cleanup);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_CTX_get_current_cert);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_CTX_get_error);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_CTX_get_error_depth);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_CTX_get_ex_data);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_CTX_init);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_CTX_set_error);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_add_lookup);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_free);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_get_by_subject);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_new);
    REQUIRE_CRYPTO_SYMBOL(X509_STORE_set_flags);
    REQUIRE_CRYPTO_SYMBOL(X509_cmp_current_time);
    REQUIRE_CRYPTO_SYMBOL(X509_free);
    REQUIRE_CRYPTO_SYMBOL(X509_get_issuer_name);
    REQUIRE_CRYPTO_SYMBOL(X509_get_pubkey);
    REQUIRE_CRYPTO_SYMBOL(X509_get_serialNumber);
    REQUIRE_CRYPTO_SYMBOL(X509_get_subject_name);
    REQUIRE_CRYPTO_SYMBOL(d2i_X509);
    REQUIRE_CRYPTO_SYMBOL(d2i_X509_bio);
    REQUIRE_CRYPTO_SYMBOL(get_rfc2409_prime_1024);
    REQUIRE_CRYPTO_SYMBOL(get_rfc3526_prime_2048);
    REQUIRE_CRYPTO_SYMBOL(get_rfc3526_prime_3072);
    REQUIRE_CRYPTO_SYMBOL(get_rfc3526_prime_4096);
    REQUIRE_CRYPTO_SYMBOL(get_rfc3526_prime_6144);
    REQUIRE_CRYPTO_SYMBOL(get_rfc3526_prime_8192);
    REQUIRE_CRYPTO_SYMBOL(i2d_X509);
    REQUIRE_CRYPTO_SYMBOL(sk_num);
    REQUIRE_CRYPTO_SYMBOL(sk_value);
    REQUIRE_CRYPTO_SYMBOL(X509_free);
    GET_CRYPTO_SYMBOL(ENGINE_load_builtin_engines);


    dhparams[0].prime = crypto_methods.get_rfc3526_prime_8192;
    dhparams[1].prime = crypto_methods.get_rfc3526_prime_6144;
    dhparams[2].prime = crypto_methods.get_rfc3526_prime_4096;
    dhparams[3].prime = crypto_methods.get_rfc3526_prime_3072;
    dhparams[4].prime = crypto_methods.get_rfc3526_prime_2048;
    dhparams[5].prime = crypto_methods.get_rfc2409_prime_1024;

    return 0;
}


TCN_IMPLEMENT_CALL(jint, SSL, version)(TCN_STDARGS)
{
    UNREFERENCED_STDARGS;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return OPENSSL_VERSION_NUMBER;
#else
    return OpenSSL_version_num();
#endif
}

TCN_IMPLEMENT_CALL(jstring, SSL, versionString)(TCN_STDARGS)
{
    UNREFERENCED(o);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return AJP_TO_JSTRING(SSLeay_version(SSLEAY_VERSION));
#else
    return AJP_TO_JSTRING(OpenSSL_version(OPENSSL_VERSION));
#endif
}

/*
 *  the various processing hooks
 */


static apr_status_t ssl_init_cleanup()
{
    if (!ssl_initialized)
        return (jint)APR_SUCCESS;
    ssl_initialized = 0;

    if (tcn_password_callback.cb.obj) {
        JNIEnv *env;
        tcn_get_java_env(&env);
        TCN_UNLOAD_CLASS(env,
                         tcn_password_callback.cb.obj);
    }

    free_dh_params();

    /*
     * Try to kill the internals of the SSL library.
     */
    /* Corresponds to crypto_methods.OPENSSL_load_builtin_modules():
     * XXX: borrowed from apps.h, but why not CONF_modules_free()
     * which also invokes CONF_modules_finish()?
     */
    CONF_modules_unload(1);
    /* Corresponds to SSL_library_init: */
    EVP_cleanup();
#if HAVE_ENGINE_LOAD_BUILTIN_ENGINES
    ENGINE_cleanup();
#endif
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);

    /* Don't call ERR_free_strings here; ERR_load_*_strings only
     * actually load the error strings once per process due to static
     * variable abuse in OpenSSL. */

    /*
     * TODO: determine somewhere we can safely shove out diagnostics
     *       (when enabled) at this late stage in the game:
     * CRYPTO_mem_leaks_fp(stderr);
     */
    return APR_SUCCESS;
}

#ifndef OPENSSL_NO_ENGINE
/* Try to load an engine in a shareable library */
static ENGINE *ssl_try_load_engine(const char *engine)
{
    ENGINE *e = ENGINE_by_id("dynamic");
    if (e) {
        if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0)
            || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
            ENGINE_free(e);
            e = NULL;
        }
    }
    return e;
}
#endif

static apr_status_t ssl_thread_cleanup(void *data)
{
    UNREFERENCED(data);
    crypto_methods.CRYPTO_set_locking_callback(NULL);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(OPENSSL_USE_DEPRECATED)
    crypto_methods.CRYPTO_set_id_callback(NULL);
#endif
    crypto_methods.CRYPTO_set_dynlock_create_callback(NULL);
    crypto_methods.CRYPTO_set_dynlock_lock_callback(NULL);
    crypto_methods.CRYPTO_set_dynlock_destroy_callback(NULL);

    /* Let the registered mutex cleanups do their own thing
     */
    return APR_SUCCESS;
}

/* TODO: Rewrite */
static int ssl_rand_choosenum(int l, int h)
{
    int i;
    char buf[50];

    snprintf(buf, sizeof(buf), "%.0f",
                 (((double)(rand()%RAND_MAX)/RAND_MAX)*(h-l)));
    i = atoi(buf)+1;
    if (i < l) i = l;
    if (i > h) i = h;
    return i;
}

 /*TODO: Check method in ssl.c in ssl-experiments to see if we can take it and change dynamic to static */
TCN_IMPLEMENT_CALL(jint, SSL, initialize)(TCN_STDARGS, jstring engine)
{
    /* TODO: use openSSLPath as function argument ? */
    /* const char * path = NULL;
    TCN_ALLOC_CSTRING(openSSLPath);
    if(openSSLPath != NULL) {
        path = J2S(openSSLPath);
    } else {

    }*/
//    char openSSLPath[] = "/usr/lib";

    if(load_openssl_dynamic_methods(e, NULL) != 0) {
        /* TCN_FREE_CSTRING(openSSLPath); */
        throwIllegalStateException(e, "Couldn't load OpenSSL shared object");
        return 0;
    }
    /* TCN_FREE_CSTRING(openSSLPath); */
    jclass clazz;
    jclass sClazz;

    TCN_ALLOC_CSTRING(engine);

    UNREFERENCED(o);
    /* Check if already initialized */
    if (ssl_initialized++) {
        TCN_FREE_CSTRING(engine);
        return (jint)APR_SUCCESS;
    }

    /* We must register the library in full, to ensure our configuration
     * code can successfully test the SSL environment.
     */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    CRYPTO_malloc_init();
#else
    OPENSSL_malloc_init();
#endif
    crypto_methods.ERR_load_crypto_strings();
    ssl_methods.SSL_load_error_strings();
    ssl_methods.SSL_library_init();
    crypto_methods.OPENSSL_add_all_algorithms_noconf();
#if HAVE_ENGINE_LOAD_BUILTIN_ENGINES
    crypto_methods.ENGINE_load_builtin_engines();
#endif
    crypto_methods.OPENSSL_load_builtin_modules();

    /* Initialize thread support */
    ssl_thread_setup();

    if (J2S(engine)) {
        ENGINE *ee = NULL;
        apr_status_t err = APR_SUCCESS;
        if(strcmp(J2S(engine), "auto") == 0) {
            ENGINE_register_all_complete();
        }
        else {
            if ((ee = ENGINE_by_id(J2S(engine))) == NULL
                && (ee = ssl_try_load_engine(J2S(engine))) == NULL)
                err = APR_ENOTIMPL;
            else {
                if (strcmp(J2S(engine), "chil") == 0)
                    ENGINE_ctrl(ee, ENGINE_CTRL_CHIL_SET_FORKCHECK, 1, 0, 0);
                if (!ENGINE_set_default(ee, ENGINE_METHOD_ALL))
                    err = APR_ENOTIMPL;
            }
            /* Free our "structural" reference. */
            if (ee)
                ENGINE_free(ee);
        }
        if (err != APR_SUCCESS) {
            TCN_FREE_CSTRING(engine);
            ssl_init_cleanup();
//            tcn_ThrowAPRException(e, err);
            char dummy_error[50];
            snprintf(dummy_error, 50, "APR Error number: %d", err);
            throwIllegalStateException(e, dummy_error);
            return (jint)err;
        }
        tcn_ssl_engine = ee;
    }

    /* For SSL_get_app_data2() and SSL_get_app_data3() at request time */
    SSL_init_app_data2_3_idx(); // TODO: dynload replace ?

    memset(&tcn_password_callback, 0, sizeof(tcn_pass_cb_t));

    init_dh_params();
    /* TODO END */
    /*
     * Let us cleanup the ssl library when the library is unloaded
     */
      /* TODO: Rewrite so that it gets executed when SSL is freed */
    /*apr_pool_cleanup_register(tcn_global_pool, NULL,
                              ssl_init_cleanup,
                              apr_pool_cleanup_null);
                              */
    TCN_FREE_CSTRING(engine);

    /* Cache the byte[].class for performance reasons */
    clazz = (*e)->FindClass(e, "[B");
    byteArrayClass = (jclass) (*e)->NewGlobalRef(e, clazz);

    /* Cache the String.class for performance reasons */
    sClazz = (*e)->FindClass(e, "java/lang/String");
    stringClass = (jclass) (*e)->NewGlobalRef(e, sClazz);

    /* TODO: add those ? */
    //alpn_init(e);
    //session_init(e);
    return (jint)APR_SUCCESS;
}


TCN_IMPLEMENT_CALL(jint, SSL, fipsModeGet)(TCN_STDARGS)
{
    UNREFERENCED(o);
#ifdef OPENSSL_FIPS
    return FIPS_mode();
#else
    /* FIPS is unavailable */
    throwIllegalStateException(e, "FIPS was not available to tcnative at build time. You will need to re-build tcnative against an OpenSSL with FIPS.");

    return 0;
#endif
}

TCN_IMPLEMENT_CALL(jint, SSL, fipsModeSet)(TCN_STDARGS, jint mode)
{
    int r = 0;
    UNREFERENCED(o);

#ifdef OPENSSL_FIPS
    if(1 != (r = (jint)FIPS_mode_set((int)mode))) {
      /* arrange to get a human-readable error message */
      unsigned long err = crypto_methods.ERR_get_error();
      char msg[256];

      /* ERR_load_crypto_strings() already called in initialize() */

      crypto_methods.ERR_error_string_n(err, msg, 256);

      throwIllegalStateException(e, msg);
    }
#else
    /* FIPS is unavailable */
    throwIllegalStateException(e, "FIPS was not available to tcnative at build time. You will need to re-build tcnative against an OpenSSL with FIPS.");
#endif

    return r;
}

/* OpenSSL Java Stream BIO */

typedef struct  {
    int            refcount;
    tcn_callback_t cb;
} BIO_JAVA;

static apr_status_t generic_bio_cleanup(void *data)
{
    BIO *b = (BIO *)data;

    if (b) {
        crypto_methods.BIO_free(b);
    }
    return APR_SUCCESS;
}

void SSL_BIO_close(BIO *bi)
{
    if (bi == NULL)
        return;
    else
        crypto_methods.BIO_free(bi);
}

void SSL_BIO_doref(BIO *bi)
{
    if (bi == NULL)
        return;
    if (bi->ptr != NULL && (bi->flags & SSL_BIO_FLAG_CALLBACK)) {
        BIO_JAVA *j = (BIO_JAVA *)bi->ptr;
        j->refcount++;
    }
}


static int jbs_new(BIO *bi)
{
    BIO_JAVA *j;

    // TODO: dynlod
    if ((j = OPENSSL_malloc(sizeof(BIO_JAVA))) == NULL)
        return 0;
    j->refcount  = 1;
    bi->shutdown = 1;
    bi->init     = 0;
    bi->num      = -1;
    bi->ptr      = (char *)j;

    return 1;
}

static int jbs_free(BIO *bi)
{
    if (bi == NULL)
        return 0;
    if (bi->ptr != NULL) {
        BIO_JAVA *j = (BIO_JAVA *)bi->ptr;
        if (bi->init) {
            JNIEnv   *e = NULL;
            bi->init = 0;
            tcn_get_java_env(&e);
            TCN_UNLOAD_CLASS(e, j->cb.obj);
        }
        // TODO dynload
        OPENSSL_free(bi->ptr);
    }
    bi->ptr = NULL;
    return 1;
}

static int jbs_write(BIO *b, const char *in, int inl)
{
    jint ret = -1;
    if (b->init && in != NULL) {
        BIO_JAVA *j = (BIO_JAVA *)b->ptr;
        JNIEnv   *e = NULL;
        jbyteArray jb;
        tcn_get_java_env(&e);
        jb = (*e)->NewByteArray(e, inl);
        if (!(*e)->ExceptionOccurred(e)) {
            BIO_clear_retry_flags(b);
            (*e)->SetByteArrayRegion(e, jb, 0, inl, (jbyte *)in);
            ret = (*e)->CallIntMethod(e, j->cb.obj,
                                      j->cb.mid[0], jb);
            (*e)->ReleaseByteArrayElements(e, jb, (jbyte *)in, JNI_ABORT);
            (*e)->DeleteLocalRef(e, jb);
        }
    }
    /* From netty-tc-native, in the AF we were returning 0 */
    if (ret == 0) {
        BIO_set_retry_write(b);
        ret = -1;
    }
    return ret;
}

static int jbs_read(BIO *b, char *out, int outl)
{
    jint ret = 0;
    if (b->init && out != NULL) {
        BIO_JAVA *j = (BIO_JAVA *)b->ptr;
        JNIEnv   *e = NULL;
        jbyteArray jb;
        tcn_get_java_env(&e);
        jb = (*e)->NewByteArray(e, outl);
        if (!(*e)->ExceptionOccurred(e)) {
            BIO_clear_retry_flags(b);
            ret = (*e)->CallIntMethod(e, j->cb.obj,
                                      j->cb.mid[1], jb);
            if (ret > 0) {
                jbyte *jout = (*e)->GetPrimitiveArrayCritical(e, jb, NULL);
                memcpy(out, jout, ret);
                (*e)->ReleasePrimitiveArrayCritical(e, jb, jout, 0);
            } else if (outl != 0) {
                ret = -1;
                BIO_set_retry_read(b);
            }
            (*e)->DeleteLocalRef(e, jb);
        }
    }
    return ret;
}

static int jbs_puts(BIO *b, const char *in)
{
    int ret = 0;
    if (b->init && in != NULL) {
        BIO_JAVA *j = (BIO_JAVA *)b->ptr;
        JNIEnv   *e = NULL;
        tcn_get_java_env(&e);
        ret = (*e)->CallIntMethod(e, j->cb.obj,
                                  j->cb.mid[2],
                                  tcn_new_string(e, in));
    }
    return ret;
}

static int jbs_gets(BIO *b, char *out, int outl)
{
    int ret = 0;
    if (b->init && out != NULL) {
        BIO_JAVA *j = (BIO_JAVA *)b->ptr;
        JNIEnv   *e = NULL;
        jobject  o;
        tcn_get_java_env(&e);
        if ((o = (*e)->CallObjectMethod(e, j->cb.obj,
                            j->cb.mid[3], (jint)(outl - 1)))) {
            TCN_ALLOC_CSTRING(o);
            if (J2S(o)) {
                int l = (int)strlen(J2S(o));
                if (l < outl) {
                    strcpy(out, J2S(o));
                    ret = outl;
                }
            }
            TCN_FREE_CSTRING(o);
        }
    }
    return ret;
}

static long jbs_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    int ret = 0;
    switch (cmd) {
        case BIO_CTRL_FLUSH:
            ret = 1;
            break;
        default:
            ret = 0;
            break;
    }
    return ret;
}

static BIO_METHOD jbs_methods = {
    BIO_TYPE_FILE,
    "Java Callback",
    jbs_write,
    jbs_read,
    jbs_puts,
    jbs_gets,
    jbs_ctrl,
    jbs_new,
    jbs_free,
    NULL
};

static BIO_METHOD *BIO_jbs()
{
    return(&jbs_methods);
}

TCN_IMPLEMENT_CALL(void, SSL, setPassword)(TCN_STDARGS, jstring password)
{
    TCN_ALLOC_CSTRING(password);
    UNREFERENCED(o);
    if (J2S(password)) {
        strncpy(tcn_password_callback.password, J2S(password), SSL_MAX_PASSWORD_LEN);
        tcn_password_callback.password[SSL_MAX_PASSWORD_LEN-1] = '\0';
    }
    TCN_FREE_CSTRING(password);
}

TCN_IMPLEMENT_CALL(jstring, SSL, getLastError)(TCN_STDARGS)
{
    char buf[256];
    UNREFERENCED(o);
    crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), buf);
    return tcn_new_string(e, buf);
}

TCN_IMPLEMENT_CALL(jboolean, SSL, hasOp)(TCN_STDARGS, jint op)
{
    return op == (op & supported_ssl_opts) ? JNI_TRUE : JNI_FALSE;
}

/*** Begin Twitter 1:1 API addition ***/
TCN_IMPLEMENT_CALL(jint, SSL, getLastErrorNumber)(TCN_STDARGS) {
    UNREFERENCED_STDARGS;
    return crypto_methods.ERR_get_error();
}

static void ssl_info_callback(const SSL *ssl, int where, int ret) {
    int *handshakeCount = NULL;
    if (0 != (where & SSL_CB_HANDSHAKE_DONE)) {
        handshakeCount = (int*) SSL_get_app_data3(ssl);
        if (handshakeCount != NULL) {
            ++(*handshakeCount);
        }
    }
}

 /* TODO: Take from ssl.c in ssl-experiments and rewrite so that we don't use dynamic functions */
TCN_IMPLEMENT_CALL(jlong /* SSL * */, SSL, newSSL)(TCN_STDARGS,
                                                   jlong ctx /* tcn_ssl_ctxt_t * */,
                                                   jboolean server) {
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    int *handshakeCount = malloc(sizeof(int));
    SSL *ssl;
    tcn_ssl_conn_t *con;

    UNREFERENCED_STDARGS;

    TCN_ASSERT(ctx != 0);
    ssl = ssl_methods.SSL_new(c->ctx);
    if (ssl == NULL) {
        throwIllegalStateException(e, "cannot create new ssl");
        return 0;
    }
    if ((con = malloc(sizeof(tcn_ssl_conn_t))) == NULL) {
        throwIllegalStateException(e, "Failed to allocate memory");
        return 0;
    }
    memset(con, 0, sizeof(*con));
    con->ctx  = c;
    con->ssl  = ssl;
    con->shutdown_type = c->shutdown_type;

    /* Store the handshakeCount in the SSL instance. */
    *handshakeCount = 0;
    SSL_set_app_data3(ssl, handshakeCount);

    /* Add callback to keep track of handshakes. */
    ssl_methods.SSL_CTX_set_info_callback(c->ctx, ssl_info_callback);

    if (server) {
        ssl_methods.SSL_set_accept_state(ssl);
    } else {
        ssl_methods.SSL_set_connect_state(ssl);
    }

    /* Setup verify and seed */
    ssl_methods.SSL_set_verify_result(ssl, X509_V_OK);

    /* Store for later usage in SSL_callback_SSL_verify */
    SSL_set_app_data2(ssl, c);
    ssl_methods.SSL_set_ex_data(ssl,0,(char *)con);
    return P2J(ssl);
}

/* How much did SSL write into this BIO? */
TCN_IMPLEMENT_CALL(jint /* nbytes */, SSL, pendingWrittenBytesInBIO)(TCN_STDARGS,
                                                                     jlong bio /* BIO * */) {
    UNREFERENCED_STDARGS;

    return crypto_methods.BIO_ctrl_pending(J2P(bio, BIO *));
}

/* How much is available for reading in the given SSL struct? */
TCN_IMPLEMENT_CALL(jint, SSL, pendingReadableBytesInSSL)(TCN_STDARGS, jlong ssl /* SSL * */) {
    UNREFERENCED_STDARGS;

    return ssl_methods.SSL_pending(J2P(ssl, SSL *));
}

/* Write wlen bytes from wbuf into bio */
TCN_IMPLEMENT_CALL(jint /* status */, SSL, writeToBIO)(TCN_STDARGS,
                                                       jlong bio /* BIO * */,
                                                       jlong wbuf /* char* */,
                                                       jint wlen /* sizeof(wbuf) */) {
    UNREFERENCED_STDARGS;

    return crypto_methods.BIO_write(J2P(bio, BIO *), J2P(wbuf, void *), wlen);

}

/* Read up to rlen bytes from bio into rbuf */
TCN_IMPLEMENT_CALL(jint /* status */, SSL, readFromBIO)(TCN_STDARGS,
                                                        jlong bio /* BIO * */,
                                                        jlong rbuf /* char * */,
                                                        jint rlen /* sizeof(rbuf) - 1 */) {
    UNREFERENCED_STDARGS;

    return crypto_methods.BIO_read(J2P(bio, BIO *), J2P(rbuf, void *), rlen);
}

/* Write up to wlen bytes of application data to the ssl BIO (encrypt) */
TCN_IMPLEMENT_CALL(jint /* status */, SSL, writeToSSL)(TCN_STDARGS,
                                                       jlong ssl /* SSL * */,
                                                       jlong wbuf /* char * */,
                                                       jint wlen /* sizeof(wbuf) */) {
    UNREFERENCED_STDARGS;

    return ssl_methods.SSL_write(J2P(ssl, SSL *), J2P(wbuf, void *), wlen);
}

/* Read up to rlen bytes of application data from the given SSL BIO (decrypt) */
TCN_IMPLEMENT_CALL(jint /* status */, SSL, readFromSSL)(TCN_STDARGS,
                                                        jlong ssl /* SSL * */,
                                                        jlong rbuf /* char * */,
                                                        jint rlen /* sizeof(rbuf) - 1 */) {
    UNREFERENCED_STDARGS;

    return ssl_methods.SSL_read(J2P(ssl, SSL *), J2P(rbuf, void *), rlen);
}

/* Get the shutdown status of the engine */
TCN_IMPLEMENT_CALL(jint /* status */, SSL, getShutdown)(TCN_STDARGS,
                                                        jlong ssl /* SSL * */) {
    UNREFERENCED_STDARGS;

    return ssl_methods.SSL_get_shutdown(J2P(ssl, SSL *));
}

/* Free the SSL * and its associated internal BIO */
TCN_IMPLEMENT_CALL(void, SSL, freeSSL)(TCN_STDARGS,
                                       jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);
    int *handshakeCount = SSL_get_app_data3(ssl_);

    UNREFERENCED_STDARGS;

    if (handshakeCount != NULL) {
        free(handshakeCount);
    }

    tcn_ssl_conn_t *con = (tcn_ssl_conn_t *)ssl_methods.SSL_get_ex_data(ssl_, 0);
    if(con->alpn_selection_callback != NULL) {
        (*e)->DeleteGlobalRef(e, con->alpn_selection_callback);
    }
    free(con);

    ssl_methods.SSL_free(ssl_);

//    ssl_init_cleanup();
}

/* Make a BIO pair (network and internal) for the provided SSL * and return the network BIO */
TCN_IMPLEMENT_CALL(jlong, SSL, makeNetworkBIO)(TCN_STDARGS,
                                               jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);
    BIO *internal_bio;
    BIO *network_bio;

    UNREFERENCED(o);

    if (ssl_ == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        goto fail;
    }

    if (crypto_methods.BIO_new_bio_pair(&internal_bio, 0, &network_bio, 0) != 1) {
        throwIllegalStateException(e, "BIO_new_bio_pair failed");
        goto fail;
    }

    ssl_methods.SSL_set_bio(ssl_, internal_bio, internal_bio);

    return P2J(network_bio);
 fail:
    return 0;
}

/* Free a BIO * (typically, the network BIO) */
TCN_IMPLEMENT_CALL(void, SSL, freeBIO)(TCN_STDARGS,
                                       jlong bio /* BIO * */) {
    BIO *bio_;
    UNREFERENCED_STDARGS;

    bio_ = J2P(bio, BIO *);
    crypto_methods.BIO_free(bio_);
}

/* Send CLOSE_NOTIFY to peer */
TCN_IMPLEMENT_CALL(jint /* status */, SSL, shutdownSSL)(TCN_STDARGS,
                                                        jlong ssl /* SSL * */) {
    UNREFERENCED_STDARGS;

    return ssl_methods.SSL_shutdown(J2P(ssl, SSL *));
}

/* Read which cipher was negotiated for the given SSL *. */
TCN_IMPLEMENT_CALL(jstring, SSL, getCipherForSSL)(TCN_STDARGS,
                                                  jlong ssl /* SSL * */)
{
    UNREFERENCED_STDARGS;

    return AJP_TO_JSTRING(ssl_methods.SSL_CIPHER_get_name(ssl_methods.SSL_get_current_cipher(J2P(ssl, SSL*))));
}

/* Read which protocol was negotiated for the given SSL *. */
TCN_IMPLEMENT_CALL(jstring, SSL, getVersion)(TCN_STDARGS,
                                                  jlong ssl /* SSL * */)
{
    UNREFERENCED_STDARGS;

    return AJP_TO_JSTRING(ssl_methods.SSL_get_version(J2P(ssl, SSL*)));
}

/* Is the handshake over yet? */
TCN_IMPLEMENT_CALL(jint, SSL, isInInit)(TCN_STDARGS,
                                        jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);

    UNREFERENCED(o);

    if (ssl_ == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        return 0;
    } else {
        return (ssl_methods.SSL_state(ssl_) & SSL_ST_INIT) || ssl_methods.SSL_renegotiate_pending(ssl_);
    }
}

TCN_IMPLEMENT_CALL(jint, SSL, doHandshake)(TCN_STDARGS,
                                           jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);
    if (ssl_ == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        return 0;
    }

    UNREFERENCED(o);

    return ssl_methods.SSL_do_handshake(ssl_);
}

TCN_IMPLEMENT_CALL(jint, SSL, renegotiate)(TCN_STDARGS,
                                           jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);
    if (ssl_ == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        return 0;
    }

    UNREFERENCED(o);

    return ssl_methods.SSL_renegotiate(ssl_);
}

/* Read which protocol was negotiated for the given SSL *. */
TCN_IMPLEMENT_CALL(jstring, SSL, getNextProtoNegotiated)(TCN_STDARGS,
                                                         jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);
    const unsigned char *proto;
    unsigned int proto_len;

    if (ssl_ == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        return NULL;
    }

    UNREFERENCED(o);

    // TODO dynload
    SSL_get0_next_proto_negotiated(ssl_, &proto, &proto_len);
    return tcn_new_stringn(e, (const char *)proto, (size_t) proto_len);
}

/*** End Twitter API Additions ***/

/*** Apple API Additions ***/

TCN_IMPLEMENT_CALL(jstring, SSL, getAlpnSelected)(TCN_STDARGS,
                                                         jlong ssl /* SSL * */) {
    /* Looks fishy we have the same in sslnetwork.c, it set by socket/connection */
    SSL *ssl_ = J2P(ssl, SSL *);
    const unsigned char *proto;
    unsigned int proto_len;

    if (ssl_ == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        return NULL;
    }

    UNREFERENCED(o);

    ssl_methods.SSL_get0_alpn_selected(ssl_, &proto, &proto_len);
    return tcn_new_stringn(e, (const char *) proto, (size_t) proto_len);
}

TCN_IMPLEMENT_CALL(jobjectArray, SSL, getPeerCertChain)(TCN_STDARGS,
                                                  jlong ssl /* SSL * */)
{
    STACK_OF(X509) *sk;
    int len;
    int i;
    X509 *cert;
    int length;
    unsigned char *buf;
    jobjectArray array;
    jbyteArray bArray;

    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        return NULL;
    }

    UNREFERENCED(o);

    // Get a stack of all certs in the chain.
    sk = ssl_methods.SSL_get_peer_cert_chain(ssl_);

    len = sk_X509_num(sk);
    if (len <= 0) {
        /* No peer certificate chain as no auth took place yet, or the auth was not successful. */
        return NULL;
    }
    /* Create the byte[][] array that holds all the certs */
    array = (*e)->NewObjectArray(e, len, byteArrayClass, NULL);

    for(i = 0; i < len; i++) {
        cert = (X509*) sk_X509_value(sk, i);

        buf = NULL;
        length = crypto_methods.i2d_X509(cert, &buf);
        if (length < 0) {
            // TODO dynload
            OPENSSL_free(buf);
            /* In case of error just return an empty byte[][] */
            return (*e)->NewObjectArray(e, 0, byteArrayClass, NULL);
        }
        bArray = (*e)->NewByteArray(e, length);
        (*e)->SetByteArrayRegion(e, bArray, 0, length, (jbyte*) buf);
        (*e)->SetObjectArrayElement(e, array, i, bArray);

        /*
         * Delete the local reference as we not know how long the chain is and local references are otherwise
         * only freed once jni method returns.
         */
        (*e)->DeleteLocalRef(e, bArray);

        OPENSSL_free(buf);
    }
    return array;
}

TCN_IMPLEMENT_CALL(jbyteArray, SSL, getPeerCertificate)(TCN_STDARGS,
                                                  jlong ssl /* SSL * */)
{
    X509 *cert;
    int length;
    unsigned char *buf = NULL;
    jbyteArray bArray;

    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        return NULL;
    }

    UNREFERENCED(o);

    /* Get a stack of all certs in the chain */
    cert = ssl_methods.SSL_get_peer_certificate(ssl_);
    if (cert == NULL) {
        return NULL;
    }

    length = crypto_methods.i2d_X509(cert, &buf);

    bArray = (*e)->NewByteArray(e, length);
    (*e)->SetByteArrayRegion(e, bArray, 0, length, (jbyte*) buf);

    /*
     * We need to free the cert as the reference count is incremented by one and it is not destroyed when the
     * session is freed.
     * See https://www.openssl.org/docs/ssl/SSL_get_peer_certificate.html
     */
    crypto_methods.X509_free(cert);

    OPENSSL_free(buf);

    return bArray;
}

TCN_IMPLEMENT_CALL(jstring, SSL, getErrorString)(TCN_STDARGS, jlong number)
{
    char buf[256];
    UNREFERENCED(o);
    crypto_methods.ERR_error_string(number, buf);
    return tcn_new_string(e, buf);
}

TCN_IMPLEMENT_CALL(jlong, SSL, getTime)(TCN_STDARGS, jlong ssl)
{
    const SSL *ssl_ = J2P(ssl, SSL *);
    const SSL_SESSION *session;

    if (ssl_ == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        return 0;
    }

    UNREFERENCED(o);

    session  = ssl_methods.SSL_get_session(ssl_);
    return ssl_methods.SSL_get_time(session);
}

TCN_IMPLEMENT_CALL(void, SSL, setVerify)(TCN_STDARGS, jlong ssl,
                                                jint level, jint depth)
{
    tcn_ssl_ctxt_t *c;
    int verify;
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        return;
    }

    // TODO dynload
    c = SSL_get_app_data2(ssl_);

    verify = SSL_VERIFY_NONE;

    UNREFERENCED(o);

    if (c == NULL) {
        throwIllegalStateException(e, "context is null");
        return;
    }
    c->verify_mode = level;

    if (c->verify_mode == SSL_CVERIFY_UNSET)
        c->verify_mode = SSL_CVERIFY_NONE;
    if (depth > 0)
        c->verify_depth = depth;
    /*
     *  Configure callbacks for SSL context
     */
    if (c->verify_mode == SSL_CVERIFY_REQUIRE)
        verify |= SSL_VERIFY_PEER_STRICT;
    if ((c->verify_mode == SSL_CVERIFY_OPTIONAL) ||
        (c->verify_mode == SSL_CVERIFY_OPTIONAL_NO_CA))
        verify |= SSL_VERIFY_PEER;
    if (!c->store) {
        if (ssl_methods.SSL_CTX_set_default_verify_paths(c->ctx)) {
            c->store = ssl_methods.SSL_CTX_get_cert_store(c->ctx);
            crypto_methods.X509_STORE_set_flags(c->store, 0);
        }
        else {
            /* XXX: See if this is fatal */
        }
    }

    ssl_methods.SSL_set_verify(ssl_, verify, SSL_callback_SSL_verify);
}

TCN_IMPLEMENT_CALL(void, SSL, setOptions)(TCN_STDARGS, jlong ssl,
                                                 jint opt)
{
    SSL *ssl_ = J2P(ssl, SSL *);

    UNREFERENCED_STDARGS;

    if (ssl_ == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        return;
    }

#ifndef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    /* Clear the flag if not supported */
    if (opt & 0x00040000) {
        opt &= ~0x00040000;
    }
#endif
    // TODO dynload
    SSL_set_options(ssl_, opt);
}

TCN_IMPLEMENT_CALL(jint, SSL, getOptions)(TCN_STDARGS, jlong ssl)
{
    SSL *ssl_ = J2P(ssl, SSL *);

    UNREFERENCED_STDARGS;

    if (ssl_ == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        return 0;
    }

    // TODO dynload
    return SSL_get_options(ssl_);
}

TCN_IMPLEMENT_CALL(jobjectArray, SSL, getCiphers)(TCN_STDARGS, jlong ssl)
{
    STACK_OF(SSL_CIPHER) *sk;
    int len;
    jobjectArray array;
    SSL_CIPHER *cipher;
    const char *name;
    int i;
    jstring c_name;
    SSL *ssl_ = J2P(ssl, SSL *);

    UNREFERENCED_STDARGS;

    if (ssl_ == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        return NULL;
    }

    sk = ssl_methods.SSL_get_ciphers(ssl_);
    len = sk_SSL_CIPHER_num(sk);  // TODO dynload

    if (len <= 0) {
        /* No peer certificate chain as no auth took place yet, or the auth was not successful. */
        return NULL;
    }

    /* Create the byte[][] array that holds all the certs */
    array = (*e)->NewObjectArray(e, len, stringClass, NULL);

    for (i = 0; i < len; i++) {
        cipher = (SSL_CIPHER*) sk_SSL_CIPHER_value(sk, i);
        name = ssl_methods.SSL_CIPHER_get_name(cipher);

        c_name = (*e)->NewStringUTF(e, name);
        (*e)->SetObjectArrayElement(e, array, i, c_name);
    }
    return array;
}

TCN_IMPLEMENT_CALL(jboolean, SSL, setCipherSuites)(TCN_STDARGS, jlong ssl,
                                                         jstring ciphers)
{
    jboolean rv = JNI_TRUE;
    SSL *ssl_ = J2P(ssl, SSL *);
    TCN_ALLOC_CSTRING(ciphers);

    UNREFERENCED_STDARGS;

    if (ssl_ == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        return JNI_FALSE;
    }

    UNREFERENCED(o);
    if (!J2S(ciphers)) {
        return JNI_FALSE;
    }
    if (!ssl_methods.SSL_set_cipher_list(ssl_, J2S(ciphers))) {
        char err[256];
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        throwIllegalStateException(e, err);
        rv = JNI_FALSE;
    }
    TCN_FREE_CSTRING(ciphers);
    return rv;
}

jbyteArray getSessionId(JNIEnv *e, SSL_SESSION *session) {

    unsigned int len;
    const unsigned char *session_id;
    session_id = ssl_methods.SSL_SESSION_get_id(session, &len);

    if (len == 0 || session_id == NULL) {
        return NULL;
    }

    jbyteArray bArray;
    bArray = (*e)->NewByteArray(e, len);
    (*e)->SetByteArrayRegion(e, bArray, 0, len, (jbyte*) session_id);
    return bArray;
}

TCN_IMPLEMENT_CALL(jbyteArray, SSL, getSessionId)(TCN_STDARGS, jlong ssl)
{

    SSL_SESSION *session;
    SSL *ssl_ = J2P(ssl, SSL *);
    if (ssl_ == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        return NULL;
    }
    session = ssl_methods.SSL_get_session(ssl_);
    return getSessionId(e, session);
}

TCN_IMPLEMENT_CALL(void, SSL, registerSessionContext)(TCN_STDARGS, jlong ctx, jobject context) {
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    c->session_context = (*e)->NewGlobalRef(e, context);
}

int new_session_cb(SSL * ssl, SSL_SESSION * session) {
    tcn_ssl_ctxt_t  *c = SSL_get_app_data2(ssl);

    JavaVM *javavm = tcn_get_java_vm();
    JNIEnv *e;
    (*javavm)->AttachCurrentThread(javavm, (void **)&e, NULL);
    jbyteArray sessionId = getSessionId(e, session);

    (*e)->CallVoidMethod(e, c->session_context, sessionInit, ssl, session, sessionId);

    (*javavm)->DetachCurrentThread(javavm);
    return 1;
}
void remove_session_cb(SSL_CTX *ctx, SSL_SESSION * session) {
     tcn_ssl_ctxt_t  *c = ssl_methods.SSL_CTX_get_ex_data(ctx,0);
    JavaVM *javavm = tcn_get_java_vm();
    JNIEnv *e;
    (*javavm)->AttachCurrentThread(javavm, (void **)&e, NULL);
    jbyteArray sessionId = getSessionId(e, session);

    (*e)->CallVoidMethod(e, c->session_context, sessionRemove, sessionId);

    (*javavm)->DetachCurrentThread(javavm);
}

void setup_session_context(JNIEnv *e, tcn_ssl_ctxt_t *c) {
 /* Default session context id and cache size */
    ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SET_SESS_CACHE_SIZE,SSL_DEFAULT_CACHE_SIZE,NULL);
    /* Session cache is disabled by default */
	ssl_methods.SSL_CTX_ctrl(c->ctx,SSL_CTRL_SET_SESS_CACHE_MODE,SSL_SESS_CACHE_OFF,NULL);
    /* Longer session timeout */
    ssl_methods.SSL_CTX_set_timeout(c->ctx, 14400);

    ssl_methods.SSL_CTX_sess_set_new_cb(c->ctx, &new_session_cb);
    ssl_methods.SSL_CTX_sess_set_remove_cb(c->ctx, &remove_session_cb);
}


TCN_IMPLEMENT_CALL(void, SSL, invalidateSession)(TCN_STDARGS, jlong ses) {
    SSL_SESSION *session = J2P(ses, SSL_SESSION *);
    if (session == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        return;
    }
    ssl_methods.SSL_SESSION_free(session);
}

TCN_IMPLEMENT_CALL(jint, SSL, getHandshakeCount)(TCN_STDARGS, jlong ssl)
{
    int *handshakeCount = NULL;
    SSL *ssl_ = J2P(ssl, SSL *);
    if (ssl_ == NULL) {
        throwIllegalArgumentException(e, "ssl is null");
        return -1;
    }
    UNREFERENCED(o);

    handshakeCount = SSL_get_app_data3(ssl_);
    if (handshakeCount != NULL) {
        return *handshakeCount;
    }
    return 0;
}

/*** End Apple API Additions ***/

#else /* HAVE_OPENSSL */
/* OpenSSL is not supported. */

#endif /* HAVE_OPENSSL */
