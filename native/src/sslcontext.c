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

/** SSL Context wrapper
 */

#include "tcn.h"


#ifdef HAVE_OPENSSL
#include "ssl_private.h"

static jclass byteArrayClass;
static jclass    ssl_context_class;
static jmethodID sni_java_callback;

/* Callback used when OpenSSL receives a client hello with a Server Name
 * Indication extension.
 */
int ssl_callback_ServerNameIndication(SSL *ssl, int *al, tcn_ssl_ctxt_t *c)
{
    /* TODO: Is it better to cache the JNIEnv* during the call to handshake? */

    /* Get the JNI environment for this callback */
    JavaVM *javavm = tcn_get_java_vm();
    JNIEnv *env;
    const char *servername;
    jstring hostname;
    jlong original_ssl_context, new_ssl_context;
    tcn_ssl_ctxt_t *new_c;

    // Continue only if the static method exists
    if (sni_java_callback == NULL) {
        return SSL_TLSEXT_ERR_OK;
    }

    (*javavm)->AttachCurrentThread(javavm, (void **)&env, NULL);

    // Get the host name presented by the client
    servername = ssl_methods.SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    // Convert to Java compatible parameters ready for the method call
    hostname = (*env)->NewStringUTF(env, servername);
    original_ssl_context = P2J(c);

    new_ssl_context = (*env)->CallStaticLongMethod(env,
                                                   ssl_context_class,
                                                   sni_java_callback,
                                                   original_ssl_context,
                                                   hostname);

    // Delete the local reference as this method is called via callback.
    // Otherwise local references are only freed once jni method returns.
    (*env)->DeleteLocalRef(env, hostname);

    if (new_ssl_context != 0 && new_ssl_context != original_ssl_context) {
        new_c = J2P(new_ssl_context, tcn_ssl_ctxt_t *);
        ssl_methods.SSL_set_SSL_CTX(ssl, new_c->ctx);
    }

    return SSL_TLSEXT_ERR_OK;
}

/* Initialize server context */
TCN_IMPLEMENT_CALL(jlong, SSLContext, make)(TCN_STDARGS,
                                            jint protocol, jint mode)
{
    tcn_ssl_ctxt_t *c = NULL;
    SSL_CTX *ctx = NULL;
    jclass clazz;

    UNREFERENCED(o);
    if (protocol == SSL_PROTOCOL_NONE) {
        throwIllegalStateException(e, "No SSL protocols requested");
        goto init_failed;
    }

    if (protocol == SSL_PROTOCOL_TLSV1_2) {
#ifdef HAVE_TLSV1_2
        if (mode == SSL_MODE_CLIENT)
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.TLSv1_2_client_method());
        else if (mode == SSL_MODE_SERVER)
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.TLSv1_2_server_method());
        else
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.TLSv1_2_method());
#endif
    } else if (protocol == SSL_PROTOCOL_TLSV1_1) {
#ifdef HAVE_TLSV1_1
        if (mode == SSL_MODE_CLIENT)
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.TLSv1_1_client_method());
        else if (mode == SSL_MODE_SERVER)
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.TLSv1_1_server_method());
        else
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.TLSv1_1_method());
#endif
    } else if (protocol == SSL_PROTOCOL_TLSV1) {
        if (mode == SSL_MODE_CLIENT)
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.TLSv1_client_method());
        else if (mode == SSL_MODE_SERVER)
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.TLSv1_server_method());
        else
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.TLSv1_method());
    } else if (protocol == SSL_PROTOCOL_SSLV3) {
        if (mode == SSL_MODE_CLIENT)
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.SSLv3_client_method());
        else if (mode == SSL_MODE_SERVER)
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.SSLv3_server_method());
        else
            ctx = ssl_methods.SSL_CTX_new(ssl_methods.SSLv3_method());
    } else if (protocol == SSL_PROTOCOL_SSLV2) {
        /* requested but not supported */
#ifndef HAVE_TLSV1_2
    } else if (protocol & SSL_PROTOCOL_TLSV1_2) {
        /* requested but not supported */
#endif
#ifndef HAVE_TLSV1_1
    } else if (protocol & SSL_PROTOCOL_TLSV1_1) {
        /* requested but not supported */
#endif
    } else {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        if (mode == SSL_MODE_CLIENT)
                ctx = ssl_methods.SSL_CTX_new(ssl_methods.SSLv23_client_method());
        else if (mode == SSL_MODE_SERVER)
                ctx = ssl_methods.SSL_CTX_new(ssl_methods.SSLv23_server_method());
        else
                ctx = ssl_methods.SSL_CTX_new(ssl_methods.SSLv23_method());
#else
        if (mode == SSL_MODE_CLIENT)
                ctx = ssl_methods.SSL_CTX_new(ssl_methods.TLS_client_method());
        else if (mode == SSL_MODE_SERVER)
                ctx = ssl_methods.SSL_CTX_new(ssl_methods.TLS_server_method());
        else
                ctx = ssl_methods.SSL_CTX_new(ssl_methods.TLS_method());
#endif
    }

    if (!ctx) {
        char err[256];
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Invalid Server SSL Protocol (%s)", err);
        goto init_failed;
    }
    if ((c = malloc(sizeof(tcn_ssl_ctxt_t))) == NULL) {
        throwIllegalStateException(e, "malloc failed");
        goto init_failed;
    }
    memset(c, 0, sizeof(*c));

    c->protocol = protocol;
    c->mode     = mode;
    c->ctx      = ctx;
    c->bio_os   = crypto_methods.BIO_new(crypto_methods.BIO_s_file());
    if (c->bio_os != NULL)
        BIO_set_fp(c->bio_os, stderr, BIO_NOCLOSE | BIO_FP_TEXT);
    ssl_methods.SSL_CTX_set_options(c->ctx, SSL_OP_ALL);
    /* always disable SSLv2, as per RFC 6176 */
    ssl_methods.SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    if (!(protocol & SSL_PROTOCOL_SSLV3))
        ssl_methods.SSL_CTX_set_options(c->ctx, SSL_OP_NO_SSLv3);
    if (!(protocol & SSL_PROTOCOL_TLSV1))
        ssl_methods.SSL_CTX_set_options(c->ctx, SSL_OP_NO_TLSv1);
#ifdef HAVE_TLSV1_1
    if (!(protocol & SSL_PROTOCOL_TLSV1_1))
        ssl_methods.SSL_CTX_set_options(c->ctx, SSL_OP_NO_TLSv1_1);
#endif
#ifdef HAVE_TLSV1_2
    if (!(protocol & SSL_PROTOCOL_TLSV1_2))
        ssl_methods.SSL_CTX_set_options(c->ctx, SSL_OP_NO_TLSv1_2);
#endif
    /*
     * Configure additional context ingredients
     */
    ssl_methods.SSL_CTX_set_options(c->ctx, SSL_OP_SINGLE_DH_USE);
/* TODO: what do we do with these defines? */
#ifdef HAVE_ECC
    ssl_methods.SSL_CTX_set_options(c->ctx, SSL_OP_SINGLE_ECDH_USE);
#endif
#ifdef SSL_OP_NO_COMPRESSION
    /* Disable SSL compression to be safe */
    ssl_methods.SSL_CTX_set_options(c->ctx, SSL_OP_NO_COMPRESSION);
#endif


    /** To get back the tomcat wrapper from CTX */
    ssl_methods.SSL_CTX_set_app_data(c->ctx, (char *)c);

#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
    /*
     * Disallow a session from being resumed during a renegotiation,
     * so that an acceptable cipher suite can be negotiated.
     */
    ssl_methods.SSL_CTX_set_options(c->ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#endif
#ifdef SSL_MODE_RELEASE_BUFFERS
    /* Release idle buffers to the SSL_CTX free list */
    ssl_methods.SSL_CTX_set_mode(c->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
    /* Default session context id and cache size */
    ssl_methods.SSL_CTX_sess_set_cache_size(c->ctx, SSL_DEFAULT_CACHE_SIZE);
    /* Session cache is disabled by default */
    ssl_methods.SSL_CTX_set_session_cache_mode(c->ctx, SSL_SESS_CACHE_OFF);
    /* Longer session timeout */
    ssl_methods.SSL_CTX_set_timeout(c->ctx, 14400);

    crypto_methods.EVP_Digest((const unsigned char *)SSL_DEFAULT_VHOST_NAME,
               (unsigned long)((sizeof SSL_DEFAULT_VHOST_NAME) - 1),
               &(c->context_id[0]), NULL, crypto_methods.EVP_sha1(), NULL);

    /* Set default Certificate verification level
     * and depth for the Client Authentication
     */
    c->verify_depth  = 1;
    c->verify_mode   = SSL_CVERIFY_UNSET;
    c->shutdown_type = SSL_SHUTDOWN_TYPE_UNSET;

    /* Set default password callback */
    /* TODO: fixme, do we need to support these callbacks?
    ssl_methods.SSL_CTX_set_default_passwd_cb(c->ctx, (pem_password_cb *)SSL_password_callback);
    ssl_methods.SSL_CTX_set_default_passwd_cb_userdata(c->ctx, (void *)(&tcn_password_callback));
    ssl_methods.SSL_CTX_set_info_callback(c->ctx, SSL_callback_handshake);
    */

    /* Cache Java side SNI callback if not already cached */
    if (ssl_context_class == NULL) {
        ssl_context_class = (*e)->NewGlobalRef(e, o);
        sni_java_callback = (*e)->GetStaticMethodID(e, ssl_context_class,
                                                    "sniCallBack", "(JLjava/lang/String;)J");
        /* Older Tomcat versions may not have this static method */
        if ( (*e)->ExceptionCheck(e) ) {
            (*e)->ExceptionClear(e);
        }
    }

    /* Set up OpenSSL call back if SNI is provided by the client */
    ssl_methods.SSL_CTX_set_tlsext_servername_callback(c->ctx, ssl_callback_ServerNameIndication);
    ssl_methods.SSL_CTX_set_tlsext_servername_arg(c->ctx, c);

    /* Cache the byte[].class for performance reasons */
    clazz = (*e)->FindClass(e, "[B");
    byteArrayClass = (jclass) (*e)->NewGlobalRef(e, clazz);

    return P2J(c);
init_failed:
    return 0;
}

TCN_IMPLEMENT_CALL(jint, SSLContext, free)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    UNREFERENCED_STDARGS;
    /* Run and destroy the cleanup callback */
    if (c) {
        int i;
        if (c->crl) {
            crypto_methods.X509_STORE_free(c->crl);
        }
        c->crl = NULL;
        if (c->ctx) {
            ssl_methods.SSL_CTX_free(c->ctx);
        }
        c->ctx = NULL;
        for (i = 0; i < SSL_AIDX_MAX; i++) {
            if (c->certs[i]) {
                crypto_methods.X509_free(c->certs[i]);
                c->certs[i] = NULL;
            }
            if (c->keys[i]) {
                printf("b %d", i);
                crypto_methods.EVP_PKEY_free(c->keys[i]);
                c->keys[i] = NULL;
            }
        }
        if (c->bio_is) {
            SSL_BIO_close(c->bio_is);
            c->bio_is = NULL;
        }
        if (c->bio_os) {
            SSL_BIO_close(c->bio_os);
            c->bio_os = NULL;
        }

        if (c->verifier) {
            JNIEnv *e;
            tcn_get_java_env(&e);
            (*e)->DeleteGlobalRef(e, c->verifier);
            c->verifier = NULL;
        }
        c->verifier_method = NULL;

        if (c->next_proto_data) {
            free(c->next_proto_data);
            c->next_proto_data = NULL;
        }
        c->next_proto_len = 0;

        if (c->alpn_proto_data) {
            free(c->alpn_proto_data);
            c->alpn_proto_data = NULL;
        }
        c->alpn_proto_len = 0;
    }
    return 0;
}

TCN_IMPLEMENT_CALL(void, SSLContext, setOptions)(TCN_STDARGS, jlong ctx,
                                                 jint opt)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);

    UNREFERENCED_STDARGS;
    TCN_ASSERT(ctx != 0);
#ifndef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    /* Clear the flag if not supported */
    if (opt & 0x00040000)
        opt &= ~0x00040000;
#endif
    ssl_methods.SSL_CTX_set_options(c->ctx, opt);
}

TCN_IMPLEMENT_CALL(jint, SSLContext, getOptions)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);

    UNREFERENCED_STDARGS;
    TCN_ASSERT(ctx != 0);

    return ssl_methods.SSL_CTX_get_options(c->ctx);
}

TCN_IMPLEMENT_CALL(void, SSLContext, clearOptions)(TCN_STDARGS, jlong ctx,
                                                   jint opt)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);

    UNREFERENCED_STDARGS;
    TCN_ASSERT(ctx != 0);
    ssl_methods.SSL_CTX_clear_options(c->ctx, opt);
}

TCN_IMPLEMENT_CALL(jboolean, SSLContext, setCipherSuite)(TCN_STDARGS, jlong ctx,
                                                         jstring ciphers)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    TCN_ALLOC_CSTRING(ciphers);
    jboolean rv = JNI_TRUE;
#ifndef HAVE_EXPORT_CIPHERS
    size_t len;
    char *buf;
#endif

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);
    if (!J2S(ciphers))
        return JNI_FALSE;

#ifndef HAVE_EXPORT_CIPHERS
    /*
     *  Always disable NULL and export ciphers,
     *  no matter what was given in the config.
     */
    len = strlen(J2S(ciphers)) + strlen(SSL_CIPHERS_ALWAYS_DISABLED) + 1;
    buf = malloc(len * sizeof(char *));
    if (buf == NULL)
        return JNI_FALSE;
    memcpy(buf, SSL_CIPHERS_ALWAYS_DISABLED, strlen(SSL_CIPHERS_ALWAYS_DISABLED));
    memcpy(buf + strlen(SSL_CIPHERS_ALWAYS_DISABLED), J2S(ciphers), strlen(J2S(ciphers)));
    buf[len - 1] = '\0';
    if (!ssl_methods.SSL_CTX_set_cipher_list(c->ctx, buf)) {
#else
    if (!ssl_methods.SSL_CTX_set_cipher_list(c->ctx, J2S(ciphers))) {
#endif
        char err[256];
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Unable to configure permitted SSL ciphers (%s)", err);
        rv = JNI_FALSE;
    }
#ifndef HAVE_EXPORT_CIPHERS
    free(buf);
#endif
    TCN_FREE_CSTRING(ciphers);
    return rv;
}

TCN_IMPLEMENT_CALL(jboolean, SSLContext, setCARevocation)(TCN_STDARGS, jlong ctx,
                                                          jstring file,
                                                          jstring path)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    TCN_ALLOC_CSTRING(file);
    TCN_ALLOC_CSTRING(path);
    jboolean rv = JNI_FALSE;
    X509_LOOKUP *lookup;
    char err[256];

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);
    if (J2S(file) == NULL && J2S(path) == NULL)
        return JNI_FALSE;

    if (!c->crl) {
        if ((c->crl = crypto_methods.X509_STORE_new()) == NULL)
            goto cleanup;
    }
    if (J2S(file)) {
        lookup = crypto_methods.X509_STORE_add_lookup(c->crl, crypto_methods.X509_LOOKUP_file());
        if (lookup == NULL) {
            crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
            crypto_methods.X509_STORE_free(c->crl);
            c->crl = NULL;
            tcn_Throw(e, "Lookup failed for file %s (%s)", J2S(file), err);
            goto cleanup;
        }
        X509_LOOKUP_load_file(lookup, J2S(file), X509_FILETYPE_PEM);
    }
    if (J2S(path)) {
        lookup = crypto_methods.X509_STORE_add_lookup(c->crl, crypto_methods.X509_LOOKUP_hash_dir());
        if (lookup == NULL) {
            crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
            crypto_methods.X509_STORE_free(c->crl);
            c->crl = NULL;
            tcn_Throw(e, "Lookup failed for path %s (%s)", J2S(file), err);
            goto cleanup;
        }
        X509_LOOKUP_add_dir(lookup, J2S(path), X509_FILETYPE_PEM);
    }
    rv = JNI_TRUE;
cleanup:
    TCN_FREE_CSTRING(file);
    TCN_FREE_CSTRING(path);
    return rv;
}

TCN_IMPLEMENT_CALL(jboolean, SSLContext, setCertificateChainFile)(TCN_STDARGS, jlong ctx,
                                                                  jstring file,
                                                                  jboolean skipfirst)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jboolean rv = JNI_FALSE;
    TCN_ALLOC_CSTRING(file);

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);
    if (!J2S(file))
        return JNI_FALSE;
    if (ssl_methods.SSL_CTX_use_certificate_chain(c->ctx, J2S(file), skipfirst) > 0)
        rv = JNI_TRUE;
    TCN_FREE_CSTRING(file);
    return rv;
}

TCN_IMPLEMENT_CALL(jboolean, SSLContext, setCACertificate)(TCN_STDARGS,
                                                           jlong ctx,
                                                           jstring file,
                                                           jstring path)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jboolean rv = JNI_TRUE;
    TCN_ALLOC_CSTRING(file);
    TCN_ALLOC_CSTRING(path);

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);
    if (file == NULL && path == NULL)
        return JNI_FALSE;

   /*
     * Configure Client Authentication details
     */
    if (!ssl_methods.SSL_CTX_load_verify_locations(c->ctx,
                                       J2S(file), J2S(path))) {
        char err[256];
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Unable to configure locations "
                  "for client authentication (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }
    c->store = ssl_methods.SSL_CTX_get_cert_store(c->ctx);
    if (c->mode) {
        STACK_OF(X509_NAME) *ca_certs;
        c->ca_certs++;
        ca_certs = ssl_methods.SSL_CTX_get_client_CA_list(c->ctx);
        if (ca_certs == NULL) {
            ssl_methods.SSL_load_client_CA_file(J2S(file));
            if (ca_certs != NULL)
                ssl_methods.SSL_CTX_set_client_CA_list(c->ctx, ca_certs);
        }
        else {
            if (!ssl_methods.SSL_add_file_cert_subjects_to_stack(ca_certs, J2S(file)))
                ca_certs = NULL;
        }
        if (ca_certs == NULL && c->verify_mode == SSL_CVERIFY_REQUIRE) {
            /*
             * Give a warning when no CAs were configured but client authentication
             * should take place. This cannot work.
             */
            if (c->bio_os) {
                crypto_methods.BIO_printf(c->bio_os,
                            "[WARN] Oops, you want to request client "
                            "authentication, but no CAs are known for "
                            "verification!?");
            }
            else {
                fprintf(stderr,
                        "[WARN] Oops, you want to request client "
                        "authentication, but no CAs are known for "
                        "verification!?");
            }

        }
    }
cleanup:
    TCN_FREE_CSTRING(file);
    TCN_FREE_CSTRING(path);
    return rv;
}

TCN_IMPLEMENT_CALL(void, SSLContext, setVerify)(TCN_STDARGS, jlong ctx,
                                                jint level, jint depth)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    int verify = SSL_VERIFY_NONE;

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);
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

    ssl_methods.SSL_CTX_set_verify(c->ctx, verify, SSL_callback_SSL_verify);
}

static EVP_PKEY *load_pem_key(tcn_ssl_ctxt_t *c, const char *file)
{
    BIO *bio = NULL;
    EVP_PKEY *key = NULL;
    tcn_pass_cb_t *cb_data = c->cb_data;
    int i;

    if ((bio = crypto_methods.BIO_new(crypto_methods.BIO_s_file())) == NULL) {
        return NULL;
    }
    if (crypto_methods.BIO_read_filename(bio, file) <= 0) {
        crypto_methods.BIO_free(bio);
        return NULL;
    }
    if (!cb_data)
        cb_data = &tcn_password_callback;
    for (i = 0; i < 3; i++) {
        key = crypto_methods.PEM_read_bio_PrivateKey(bio, NULL,
                    (pem_password_cb *)SSL_password_callback,
                    (void *)cb_data);
        if (key)
            break;
        cb_data->password[0] = '\0';
        crypto_methods.BIO_ctrl(bio, BIO_CTRL_RESET, 0, NULL);
    }
    crypto_methods.BIO_free(bio);
    return key;
}

static X509 *load_pem_cert(tcn_ssl_ctxt_t *c, const char *file)
{
    BIO *bio = NULL;
    X509 *cert = NULL;
    tcn_pass_cb_t *cb_data = c->cb_data;

    if ((bio = crypto_methods.BIO_new(crypto_methods.BIO_s_file())) == NULL) {
        return NULL;
    }
    if (crypto_methods.BIO_read_filename(bio, file) <= 0) {
        crypto_methods.BIO_free(bio);
        return NULL;
    }
    if (!cb_data)
        cb_data = &tcn_password_callback;
    cert = PEM_read_bio_X509_AUX(bio, NULL,
                (pem_password_cb *)SSL_password_callback,
                (void *)cb_data);
    if (cert == NULL &&
       (ERR_GET_REASON(ERR_peek_last_error()) == PEM_R_NO_START_LINE)) {
        ERR_clear_error();
        crypto_methods.BIO_ctrl(bio, BIO_CTRL_RESET, 0, NULL);
        cert = crypto_methods.d2i_X509_bio(bio, NULL);
    }
    crypto_methods.BIO_free(bio);
    return cert;
}

static int ssl_load_pkcs12(tcn_ssl_ctxt_t *c, const char *file,
                           EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
    const char *pass;
    char        buff[PEM_BUFSIZE];
    int         len, rc = 0;
    PKCS12     *p12;
    BIO        *in;
    tcn_pass_cb_t *cb_data = c->cb_data;

    if ((in = crypto_methods.BIO_new(crypto_methods.BIO_s_file())) == 0)
        return 0;
    if (crypto_methods.BIO_read_filename(in, file) <= 0) {
        crypto_methods.BIO_free(in);
        return 0;
    }
    p12 = d2i_PKCS12_bio(in, 0);
    if (p12 == 0) {
        /* Error loading PKCS12 file */
        goto cleanup;
    }
    /* See if an empty password will do */
    if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, 0, 0)) {
        pass = "";
    }
    else {
        if (!cb_data)
            cb_data = &tcn_password_callback;
            // TODO dynload
        len = SSL_password_callback(buff, PEM_BUFSIZE, 0, cb_data);
        if (len < 0) {
            /* Passpharse callback error */
            goto cleanup;
        }
        if (!PKCS12_verify_mac(p12, buff, len)) {
            /* Mac verify error (wrong password?) in PKCS12 file */
            goto cleanup;
        }
        pass = buff;
    }
    rc = PKCS12_parse(p12, pass, pkey, cert, ca);
cleanup:
    if (p12 != 0)
        PKCS12_free(p12);
    crypto_methods.BIO_free(in);
    return rc;
}

TCN_IMPLEMENT_CALL(jboolean, SSLContext, setCertificate)(TCN_STDARGS,jlong ctx,
                                                       jbyteArray javaCert,
                                                       jbyteArray javaKey, jint idx)
{
    /* we get the key contents into a byte array */
    jbyte* bufferPtr = (*e)->GetByteArrayElements(e, javaKey, NULL);
    jsize lengthOfKey = (*e)->GetArrayLength(e, javaKey);
    unsigned char* key = malloc(lengthOfKey);
    memcpy(key, bufferPtr, lengthOfKey);
    (*e)->ReleaseByteArrayElements(e, javaKey, bufferPtr, 0);

    bufferPtr = (*e)->GetByteArrayElements(e, javaCert, NULL);
    jsize lengthOfCert = (*e)->GetArrayLength(e, javaCert);
    unsigned char* cert = malloc(lengthOfCert);
    memcpy(cert, bufferPtr, lengthOfCert);
    (*e)->ReleaseByteArrayElements(e, javaCert, bufferPtr, 0);

    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jboolean rv = JNI_TRUE;
    char err[256];

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);

    if (idx < 0 || idx >= SSL_AIDX_MAX) {
        throwIllegalStateException(e, "Invalid key type");
        rv = JNI_FALSE;
        goto cleanup;
    }
    const unsigned char *tmp = (const unsigned char *)cert;
    if ((c->certs[idx] = crypto_methods.d2i_X509(NULL, &tmp, lengthOfCert)) == NULL) {
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        throwIllegalStateException(e, err);
        rv = JNI_FALSE;
        goto cleanup;
    }

    EVP_PKEY * evp = malloc(sizeof(EVP_PKEY));
    memset(evp, 0, sizeof(EVP_PKEY));
    if(c->keys[idx] != NULL) {
        free(c->keys[idx]);
    }
    c->keys[idx] = evp;

    BIO * bio = crypto_methods.BIO_new(crypto_methods.BIO_s_mem());
    crypto_methods.BIO_write(bio, key, lengthOfKey);

    c->keys[idx] = crypto_methods.PEM_read_bio_PrivateKey(bio, NULL, 0, NULL);
    crypto_methods.BIO_free(bio);
    if (c->keys[idx] == NULL) {
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        throwIllegalStateException(e, err);
        rv = JNI_FALSE;
        goto cleanup;
    }

    if (ssl_methods.SSL_CTX_use_certificate(c->ctx, c->certs[idx]) <= 0) {
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Error setting certificate (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }
    if (ssl_methods.SSL_CTX_use_PrivateKey(c->ctx, c->keys[idx]) <= 0) {
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Error setting private key (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }
    if (ssl_methods.SSL_CTX_check_private_key(c->ctx) <= 0) {
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Private key does not match the certificate public key (%s)",
                  err);
        rv = JNI_FALSE;
        goto cleanup;
    }
    /* TODO: read DH and ECC params? */

cleanup:
    free(key);
    free(cert);
    return rv;
}

TCN_IMPLEMENT_CALL(jboolean, SSLContext, setCertificateRaw)(TCN_STDARGS, jlong ctx,
                                                         jbyteArray javaCert, jbyteArray javaKey, jint idx)
{
#ifdef HAVE_ECC
#if defined(ssl_methods.SSL_CTX_set_ecdh_auto)
    EC_KEY *eckey = NULL;
#endif
#endif
    jsize lengthOfCert;
    unsigned char* cert;
    X509 * certs;
    EVP_PKEY * evp;
    const unsigned char *tmp;
    BIO * bio;

    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jboolean rv = JNI_TRUE;
    char err[256];

    /* we get the key contents into a byte array */
    jbyte* bufferPtr = (*e)->GetByteArrayElements(e, javaKey, NULL);
    jsize lengthOfKey = (*e)->GetArrayLength(e, javaKey);
    unsigned char* key = malloc(lengthOfKey);
    memcpy(key, bufferPtr, lengthOfKey);
    (*e)->ReleaseByteArrayElements(e, javaKey, bufferPtr, 0);

    bufferPtr = (*e)->GetByteArrayElements(e, javaCert, NULL);
    lengthOfCert = (*e)->GetArrayLength(e, javaCert);
    cert = malloc(lengthOfCert);
    memcpy(cert, bufferPtr, lengthOfCert);
    (*e)->ReleaseByteArrayElements(e, javaCert, bufferPtr, 0);

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);

    if (idx < 0 || idx >= SSL_AIDX_MAX) {
        tcn_Throw(e, "Invalid key type");
        rv = JNI_FALSE;
        goto cleanup;
    }

    tmp = (const unsigned char *)cert;
    certs = crypto_methods.d2i_X509(NULL, &tmp, lengthOfCert);
    if (certs == NULL) {
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Error reading certificat (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }
    if(c->certs[idx] != NULL) {
        free(c->certs[idx]);
    }
    c->certs[idx] = certs;

    bio = crypto_methods.BIO_new(crypto_methods.BIO_s_mem());
    crypto_methods.BIO_write(bio, key, lengthOfKey);

    evp = crypto_methods.PEM_read_bio_PrivateKey(bio, NULL, 0, NULL);
    if (evp == NULL) {
        crypto_methods.BIO_free(bio);
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Error reading private key (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }
    crypto_methods.BIO_free(bio);
    if(c->keys[idx] != NULL) {
        free(c->keys[idx]);
    }
    c->keys[idx] = evp;

    if (ssl_methods.SSL_CTX_use_certificate(c->ctx, c->certs[idx]) <= 0) {
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Error setting certificate (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }
    if (ssl_methods.SSL_CTX_use_PrivateKey(c->ctx, c->keys[idx]) <= 0) {
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Error setting private key (%s)", err);
        rv = JNI_FALSE;
        goto cleanup;
    }
    if (ssl_methods.SSL_CTX_check_private_key(c->ctx) <= 0) {
        crypto_methods.ERR_error_string(crypto_methods.ERR_get_error(), err);
        tcn_Throw(e, "Private key does not match the certificate public key (%s)",
                  err);
        rv = JNI_FALSE;
        goto cleanup;
    }

    /*
     * TODO Try to read DH parameters from somewhere...
     */

#ifdef HAVE_ECC
    /*
     * TODO try to read the ECDH curve name from somewhere...
     */
#if defined(ssl_methods.SSL_CTX_set_ecdh_auto)
    ssl_methods.SSL_CTX_set_ecdh_auto(c->ctx, 1);
#else
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    ssl_methods.SSL_CTX_set_tmp_ecdh(c->ctx, eckey);
    EC_KEY_free(eckey);
#endif
#endif
    ssl_methods.SSL_CTX_set_tmp_dh_callback(c->ctx, SSL_callback_tmp_DH);
cleanup:
    free(key);
    free(cert);
    return rv;
}

/*
 * This callback function is executed when the TLS Application Layer
 * Protocol Negotiate Extension (ALPN, RFC 7301) is triggered by the client
 * hello, giving a list of desired protocol names (in descending preference)
 * to the server.
 * The callback has to select a protocol name or return an error if none of
 * the clients preferences is supported.
 * The selected protocol does not have to be on the client list, according
 * to RFC 7301, so no checks are performed.
 * The client protocol list is serialized as length byte followed by ascii
 * characters (not null-terminated), followed by the next protocol name.
 */

int cb_server_alpn(SSL *ssl,
                   const unsigned char **out, unsigned char *outlen,
                   const unsigned char *in, unsigned int inlen, void *arg)
{
    /* Taken from SSL_callback_alpn_select_proto.
       TODO take full alpn.c? */

    /* TODO dynload */
    tcn_ssl_conn_t *con = (tcn_ssl_conn_t *)SSL_get_ex_data(ssl, 0);

    if(con->alpn_selection_callback == NULL) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    /* Get the JNI environment for this callback */
    JavaVM *javavm = tcn_get_java_vm();
    JNIEnv *e;
    (*javavm)->AttachCurrentThread(javavm, (void **)&e, NULL);

    const unsigned char *p;
    const unsigned char *end;
    const unsigned char *proto;
    unsigned char proto_len;

    /* TODO: Cache references to these e.g. in some init function */
    jclass sClazz = (*e)->FindClass(e, "java/lang/String");
    jclass stringClass = (jclass) (*e)->NewGlobalRef(e, sClazz);
    jmethodID stringEquals = (*e)->GetMethodID(e, stringClass, "equals", "(Ljava/lang/Object;)Z");
    /* ENDTODO */

    p = in;
    end = in + inlen;
    /* first we count them */
    int count = 0;
    while (p < end) {
        proto_len = *p;
        proto = ++p;
        if (proto + proto_len <= end) {
            count++;
        }
        /* Move on to the next protocol. */
        p += proto_len;
    }
    /* now we allocate an array */
    jobjectArray array = (*e)->NewObjectArray(e, count, stringClass, NULL);
    jobject nativeArray[count];
    p = in;
    end = in + inlen;
    int c = 0;

    while (p < end) {
        proto_len = *p;
        proto = ++p;
        if (proto + proto_len <= end) {
            jobject string = tcn_new_stringn(e, (const char*)proto, proto_len);
            nativeArray[c] = string;
            (*e)->SetObjectArrayElement(e, array, c++, string);
        }
        /* Move on to the next protocol. */
        p += proto_len;
    }

    jclass clazz = (*e)->GetObjectClass(e, con->alpn_selection_callback);
    jmethodID method = (*e)->GetMethodID(e, clazz, "select", "([Ljava/lang/String;)Ljava/lang/String;");
    jobject result = (*e)->CallObjectMethod(e, con->alpn_selection_callback, method, array);

    if(result == NULL) {
        (*javavm)->DetachCurrentThread(javavm);
        return SSL_TLSEXT_ERR_NOACK;
    }

    p = in;
    end = in + inlen;
    c = 0;
    while (p < end) {
        proto_len = *p;
        proto = ++p;
        if (proto + proto_len <= end) {
            jobject string = nativeArray[c++];
            if((*e)->CallBooleanMethod(e, string, stringEquals, result)) {

                /* we have a match */
                *out = proto;
                *outlen = proto_len;
                (*javavm)->DetachCurrentThread(javavm);
                return SSL_TLSEXT_ERR_OK;
            }
        }
        /* Move on to the next protocol. */
        p += proto_len;
    }

    /* it did not return a valid response */
    (*javavm)->DetachCurrentThread(javavm);
    return SSL_TLSEXT_ERR_NOACK;
}


/* Start of netty-tc-native add */

/* Convert protos to wire format */
static int initProtocols(JNIEnv *e, const tcn_ssl_ctxt_t *c, unsigned char **proto_data,
            unsigned int *proto_len, jobjectArray protos) {
    int i;
    unsigned char *p_data;
    /*
     * We start with allocate 128 bytes which should be good enough for most use-cases while still be pretty low.
     * We will call realloc to increate this if needed.
     */
    size_t p_data_size = 128;
    size_t p_data_len = 0;
    jstring proto_string;
    const char *proto_chars;
    size_t proto_chars_len;
    int cnt;

    if (protos == NULL) {
        // Guard against NULL protos.
        return -1;
    }

    cnt = (*e)->GetArrayLength(e, protos);

    if (cnt == 0) {
        // if cnt is 0 we not need to continue and can just fail fast.
        return -1;
    }

    p_data = (unsigned char *) malloc(p_data_size);
    if (p_data == NULL) {
        // Not enough memory?
        return -1;
    }

    for (i = 0; i < cnt; ++i) {
         proto_string = (jstring) (*e)->GetObjectArrayElement(e, protos, i);
         proto_chars = (*e)->GetStringUTFChars(e, proto_string, 0);

         proto_chars_len = strlen(proto_chars);
         if (proto_chars_len > 0 && proto_chars_len <= MAX_ALPN_NPN_PROTO_SIZE) {
            // We need to add +1 as each protocol is prefixed by it's length (unsigned char).
            // For all except of the last one we already have the extra space as everything is
            // delimited by ','.
            p_data_len += 1 + proto_chars_len;
            if (p_data_len > p_data_size) {
                // double size
                p_data_size <<= 1;
                p_data = realloc(p_data, p_data_size);
                if (p_data == NULL) {
                    // Not enough memory?
                    (*e)->ReleaseStringUTFChars(e, proto_string, proto_chars);
                    break;
                }
            }
            // Write the length of the protocol and then increment before memcpy the protocol itself.
            *p_data = proto_chars_len;
            ++p_data;
            memcpy(p_data, proto_chars, proto_chars_len);
            p_data += proto_chars_len;
         }

         // Release the string to prevent memory leaks
         (*e)->ReleaseStringUTFChars(e, proto_string, proto_chars);
    }

    if (p_data == NULL) {
        // Something went wrong so update the proto_len and return -1
        *proto_len = 0;
        return -1;
    } else {
        if (*proto_data != NULL) {
            // Free old data
            free(*proto_data);
        }
        // Decrement pointer again as we incremented it while creating the protocols in wire format.
        p_data -= p_data_len;
        *proto_data = p_data;
        *proto_len = p_data_len;
        return 0;
    }
}

TCN_IMPLEMENT_CALL(void, SSLContext, setNpnProtos)(TCN_STDARGS, jlong ctx, jobjectArray next_protos,
        jint selectorFailureBehavior)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);

    TCN_ASSERT(ctx != 0);
    UNREFERENCED(o);

    if (initProtocols(e, c, &c->next_proto_data, &c->next_proto_len, next_protos) == 0) {
        c->next_selector_failure_behavior = selectorFailureBehavior;

        // depending on if it's client mode or not we need to call different functions.
        if (c->mode == SSL_MODE_CLIENT)  {
            ssl_methods.SSL_CTX_set_next_proto_select_cb(c->ctx, SSL_callback_select_next_proto, (void *)c);
        } else {
            ssl_methods.SSL_CTX_set_next_protos_advertised_cb(c->ctx, SSL_callback_next_protos, (void *)c);
        }
    }
}

TCN_IMPLEMENT_CALL(void, SSLContext, setAlpnProtos)(TCN_STDARGS, jlong ctx, jobjectArray alpn_protos,
        jint selectorFailureBehavior)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);

    TCN_ASSERT(ctx != 0);
    UNREFERENCED(o);

    if (initProtocols(e, c, &c->alpn_proto_data, &c->alpn_proto_len, alpn_protos) == 0) {
        c->alpn_selector_failure_behavior = selectorFailureBehavior;

        // depending on if it's client mode or not we need to call different functions.
        if (c->mode == SSL_MODE_CLIENT)  {
            ssl_methods.SSL_CTX_set_alpn_protos(c->ctx, c->alpn_proto_data, c->alpn_proto_len);
        } else {
            ssl_methods.SSL_CTX_set_alpn_select_cb(c->ctx, SSL_callback_alpn_select_proto, (void *) c);

        }
    }
}

TCN_IMPLEMENT_CALL(void, SSLContext, enableAlpn)(TCN_STDARGS, jlong ctx)
{

    if(ssl_methods.SSL_CTX_set_alpn_protos == NULL) {
        return;
    }
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);

    TCN_ASSERT(ctx != 0);
    UNREFERENCED(o);

    ssl_methods.SSL_CTX_set_alpn_select_cb(c->ctx, SSL_callback_alpn_select_proto, (void *) c);

}

TCN_IMPLEMENT_CALL(void, SSLContext, setServerALPNCallback)(TCN_STDARGS, jlong ssl, jobject callback) {
    if(ssl_methods.SSL_CTX_set_alpn_protos == NULL) {
        return;
    }
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        throwIllegalStateException(e, "ssl is null");
        return;
    }
    tcn_ssl_conn_t *con = (tcn_ssl_conn_t *) ssl_methods.SSL_get_ex_data(ssl_, 0);

    con->alpn_selection_callback = (*e)->NewGlobalRef(e, callback);
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, setSessionCacheMode)(TCN_STDARGS, jlong ctx, jlong mode)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    return ssl_methods.SSL_CTX_set_session_cache_mode(c->ctx, mode);
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, getSessionCacheMode)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    return ssl_methods.SSL_CTX_get_session_cache_mode(c->ctx);
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, setSessionCacheTimeout)(TCN_STDARGS, jlong ctx, jlong timeout)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_set_timeout(c->ctx, timeout);
    return rv;
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, getSessionCacheTimeout)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    return ssl_methods.SSL_CTX_get_timeout(c->ctx);
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, setSessionCacheSize)(TCN_STDARGS, jlong ctx, jlong size)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = 0;

    // Also allow size of 0 which is unlimited
    if (size >= 0) {
      ssl_methods.SSL_CTX_set_session_cache_mode(c->ctx, SSL_SESS_CACHE_SERVER);
      rv = ssl_methods.SSL_CTX_sess_set_cache_size(c->ctx, size);
    }

    return rv;
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, getSessionCacheSize)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    return ssl_methods.SSL_CTX_sess_get_cache_size(c->ctx);
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, sessionNumber)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_sess_number(c->ctx);
    return rv;
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, sessionConnect)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_sess_connect(c->ctx);
    return rv;
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, sessionConnectGood)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_sess_connect_good(c->ctx);
    return rv;
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, sessionConnectRenegotiate)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_sess_connect_renegotiate(c->ctx);
    return rv;
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, sessionAccept)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_sess_accept(c->ctx);
    return rv;
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, sessionAcceptGood)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_sess_accept_good(c->ctx);
    return rv;
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, sessionAcceptRenegotiate)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_sess_accept_renegotiate(c->ctx);
    return rv;
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, sessionHits)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_sess_hits(c->ctx);
    return rv;
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, sessionCbHits)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_sess_cb_hits(c->ctx);
    return rv;
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, sessionMisses)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_sess_misses(c->ctx);
    return rv;
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, sessionTimeouts)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_sess_timeouts(c->ctx);
    return rv;
}

TCN_IMPLEMENT_CALL(jlong, SSLContext, sessionCacheFull)(TCN_STDARGS, jlong ctx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jlong rv = ssl_methods.SSL_CTX_sess_cache_full(c->ctx);
    return rv;
}

#define TICKET_KEYS_SIZE 48
TCN_IMPLEMENT_CALL(void, SSLContext, setSessionTicketKeys)(TCN_STDARGS, jlong ctx, jbyteArray keys)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    jbyte* b;

    if ((*e)->GetArrayLength(e, keys) != TICKET_KEYS_SIZE) {
        if (c->bio_os) {
            crypto_methods.BIO_printf(c->bio_os, "[ERROR] Session ticket keys provided were wrong size.");
        }
        else {
            fprintf(stderr, "[ERROR] Session ticket keys provided were wrong size.");
        }
        exit(1);
    }

    b = (*e)->GetByteArrayElements(e, keys, NULL);
    ssl_methods.SSL_CTX_set_tlsext_ticket_keys(c->ctx, b, TICKET_KEYS_SIZE);
    (*e)->ReleaseByteArrayElements(e, keys, b, 0);
}


/*
 * Adapted from OpenSSL:
 * http://osxr.org/openssl/source/ssl/ssl_locl.h#0291
 */
/* Bits for algorithm_mkey (key exchange algorithm) */
#define SSL_kRSA        0x00000001L /* RSA key exchange */
#define SSL_kDHr        0x00000002L /* DH cert, RSA CA cert */ /* no such ciphersuites supported! */
#define SSL_kDHd        0x00000004L /* DH cert, DSA CA cert */ /* no such ciphersuite supported! */
#define SSL_kEDH        0x00000008L /* tmp DH key no DH cert */
#define SSL_kKRB5       0x00000010L /* Kerberos5 key exchange */
#define SSL_kECDHr      0x00000020L /* ECDH cert, RSA CA cert */
#define SSL_kECDHe      0x00000040L /* ECDH cert, ECDSA CA cert */
#define SSL_kEECDH      0x00000080L /* ephemeral ECDH */
#define SSL_kPSK        0x00000100L /* PSK */
#define SSL_kGOST       0x00000200L /* GOST key exchange */
#define SSL_kSRP        0x00000400L /* SRP */

/* Bits for algorithm_auth (server authentication) */
#define SSL_aRSA        0x00000001L /* RSA auth */
#define SSL_aDSS        0x00000002L /* DSS auth */
#define SSL_aNULL       0x00000004L /* no auth (i.e. use ADH or AECDH) */
#define SSL_aDH         0x00000008L /* Fixed DH auth (kDHd or kDHr) */ /* no such ciphersuites supported! */
#define SSL_aECDH       0x00000010L /* Fixed ECDH auth (kECDHe or kECDHr) */
#define SSL_aKRB5       0x00000020L /* KRB5 auth */
#define SSL_aECDSA      0x00000040L /* ECDSA auth*/
#define SSL_aPSK        0x00000080L /* PSK auth */
#define SSL_aGOST94     0x00000100L /* GOST R 34.10-94 signature auth */
#define SSL_aGOST01     0x00000200L /* GOST R 34.10-2001 signature auth */

/* OpenSSL end */

/*
 * Adapted from Android:
 * https://android.googlesource.com/platform/external/openssl/+/master/patches/0003-jsse.patch
 */
const char* SSL_CIPHER_authentication_method(const SSL_CIPHER* cipher){
    switch (cipher->algorithm_mkey)
        {
    case SSL_kRSA:
        return SSL_TXT_RSA;
    case SSL_kDHr:
        return SSL_TXT_DH "_" SSL_TXT_RSA;
    case SSL_kDHd:
        return SSL_TXT_DH "_" SSL_TXT_DSS;
    case SSL_kEDH:
        switch (cipher->algorithm_auth)
            {
        case SSL_aDSS:
            return "DHE_" SSL_TXT_DSS;
        case SSL_aRSA:
            return "DHE_" SSL_TXT_RSA;
        case SSL_aNULL:
            return SSL_TXT_DH "_anon";
        default:
            return "UNKNOWN";
            }
    case SSL_kKRB5:
        return SSL_TXT_KRB5;
    case SSL_kECDHr:
        return SSL_TXT_ECDH "_" SSL_TXT_RSA;
    case SSL_kECDHe:
        return SSL_TXT_ECDH "_" SSL_TXT_ECDSA;
    case SSL_kEECDH:
        switch (cipher->algorithm_auth)
            {
        case SSL_aECDSA:
            return "ECDHE_" SSL_TXT_ECDSA;
        case SSL_aRSA:
            return "ECDHE_" SSL_TXT_RSA;
        case SSL_aNULL:
            return SSL_TXT_ECDH "_anon";
        default:
            return "UNKNOWN";
            }
    default:
        return "UNKNOWN";
    }
}

static const char* SSL_authentication_method(const SSL* ssl) {
{
    switch (ssl->version)
        {
        case SSL2_VERSION:
            return SSL_TXT_RSA;
        default:
            return SSL_CIPHER_authentication_method(ssl->s3->tmp.new_cipher);
        }
    }
}
/* Android end */

static int SSL_cert_verify(X509_STORE_CTX *ctx, void *arg) {
    /* Get Apache context back through OpenSSL context */
    SSL *ssl = crypto_methods.X509_STORE_CTX_get_ex_data(ctx, ssl_methods.SSL_get_ex_data_X509_STORE_CTX_idx());
    tcn_ssl_ctxt_t *c = SSL_get_app_data2(ssl);


    // Get a stack of all certs in the chain
    STACK_OF(X509) *sk = ctx->untrusted;

    int len = sk_X509_num(sk);
    unsigned i;
    X509 *cert;
    int length;
    unsigned char *buf;
    JNIEnv *e;
    jbyteArray array;
    jbyteArray bArray;
    const char *authMethod;
    jstring authMethodString;
    jboolean result;
    int r;
    tcn_get_java_env(&e);

    // Create the byte[][] array that holds all the certs
    array = (*e)->NewObjectArray(e, len, byteArrayClass, NULL);

    for(i = 0; i < len; i++) {
        cert = (X509*) sk_X509_value(sk, i);

        buf = NULL;
        length = crypto_methods.i2d_X509(cert, &buf);
        if (length < 0) {
            // In case of error just return an empty byte[][]
            array = (*e)->NewObjectArray(e, 0, byteArrayClass, NULL);
            // We need to delete the local references so we not leak memory as this method is called via callback.
            OPENSSL_free(buf);
            break;
        }
        bArray = (*e)->NewByteArray(e, length);
        (*e)->SetByteArrayRegion(e, bArray, 0, length, (jbyte*) buf);
        (*e)->SetObjectArrayElement(e, array, i, bArray);

        // Delete the local reference as we not know how long the chain is and local references are otherwise
        // only freed once jni method returns.
        (*e)->DeleteLocalRef(e, bArray);
        OPENSSL_free(buf);
    }

    authMethod = SSL_authentication_method(ssl); // TODO dynload
    authMethodString = (*e)->NewStringUTF(e, authMethod);

    result = (*e)->CallBooleanMethod(e, c->verifier, c->verifier_method, P2J(ssl), array,
            authMethodString);

    r = result == JNI_TRUE ? 1 : 0;

    // We need to delete the local references so we not leak memory as this method is called via callback.
    (*e)->DeleteLocalRef(e, authMethodString);
    (*e)->DeleteLocalRef(e, array);
    return r;
}


TCN_IMPLEMENT_CALL(void, SSLContext, setCertVerifyCallback)(TCN_STDARGS, jlong ctx, jobject verifier)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);

    if (verifier == NULL) {
        ssl_methods.SSL_CTX_set_cert_verify_callback(c->ctx, NULL, NULL);
    } else {
        jclass verifier_class = (*e)->GetObjectClass(e, verifier);
        jmethodID method = (*e)->GetMethodID(e, verifier_class, "verify", "(J[[BLjava/lang/String;)Z");

        if (method == NULL) {
            return;
        }
        // Delete the reference to the previous specified verifier if needed.
        if (c->verifier != NULL) {
            (*e)->DeleteLocalRef(e, c->verifier);
        }
        c->verifier = (*e)->NewGlobalRef(e, verifier);
        c->verifier_method = method;

        ssl_methods.SSL_CTX_set_cert_verify_callback(c->ctx, SSL_cert_verify, NULL);
    }
}

TCN_IMPLEMENT_CALL(jboolean, SSLContext, setSessionIdContext)(TCN_STDARGS, jlong ctx, jbyteArray sidCtx)
{
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
    int len = (*e)->GetArrayLength(e, sidCtx);
    unsigned char *buf;
    int res;

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);

    buf = malloc(len);

    (*e)->GetByteArrayRegion(e, sidCtx, 0, len, (jbyte*) buf);

    res = ssl_methods.SSL_CTX_set_session_id_context(c->ctx, buf, len);
    free(buf);

    if (res == 1) {
        return JNI_TRUE;
    }
    return JNI_FALSE;
}

/* End of netty-tc-native add */
#else
/* TODO COMPILE ERROR: OpenSSL is not supported.*/
#endif
