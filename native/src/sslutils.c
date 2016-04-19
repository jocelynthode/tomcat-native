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

/** SSL Utilities
 */

#include "tcn.h"

#ifdef HAVE_OPENSSL
#include "ssl_private.h"

#ifdef WIN32
extern int WIN32_SSL_password_prompt(tcn_pass_cb_t *data);
#endif

#ifdef HAVE_OCSP_STAPLING
#include <openssl/bio.h>
#include <openssl/ocsp.h>
/* defines with the values as seen by the asn1parse -dump openssl command */
#define ASN1_SEQUENCE 0x30
#define ASN1_OID      0x06
#define ASN1_STRING   0x86
static int ssl_verify_OCSP(int ok, X509_STORE_CTX *ctx);
static int ssl_ocsp_request(X509 *cert, X509 *issuer);
#endif

/*  _________________________________________________________________
**
**  Additional High-Level Functions for OpenSSL
**  _________________________________________________________________
*/

/* we initialize this index at startup time
 * and never write to it at request time,
 * so this static is thread safe.
 * also note that OpenSSL increments at static variable when
 * SSL_get_ex_new_index() is called, so we _must_ do this at startup.
 */
static int SSL_app_data2_idx = -1;
static int SSL_app_data3_idx = -1;

void SSL_init_app_data2_3_idx(void)
{
    int i;

    if (SSL_app_data2_idx > -1) {
        return;
    }

    /* we _do_ need to call this twice */
    for (i = 0; i <= 1; i++) {
        SSL_app_data2_idx =
            SSL_get_ex_new_index(0,
                                 "Second Application Data for SSL",
                                 NULL, NULL, NULL);
    }

    if (SSL_app_data3_idx > -1) {
        return;
    }

    SSL_app_data3_idx =
            SSL_get_ex_new_index(0,
                                 "Third Application Data for SSL",
                                  NULL, NULL, NULL);

}

tcn_ssl_ctxt_t *SSL_get_app_data2(SSL *ssl)
{
    return (tcn_ssl_ctxt_t *)SSL_get_ex_data(ssl, SSL_app_data2_idx);
}

void SSL_set_app_data2(SSL *ssl, void *arg)
{
    SSL_set_ex_data(ssl, SSL_app_data2_idx, (char *)arg);
    return;
}


void *SSL_get_app_data3(const SSL *ssl)
{
    return SSL_get_ex_data(ssl, SSL_app_data3_idx);
}

void SSL_set_app_data3(SSL *ssl, void *arg)
{
    SSL_set_ex_data(ssl, SSL_app_data3_idx, arg);
}

/* Simple echo password prompting */
int SSL_password_prompt(tcn_pass_cb_t *data)
{
    int rv = 0;
    data->password[0] = '\0';
    if (data->cb.obj) {
        JNIEnv *e;
        jobject  o;
        jstring  prompt;
        tcn_get_java_env(&e);
        prompt = AJP_TO_JSTRING(data->prompt);
        if ((o = (*e)->CallObjectMethod(e, data->cb.obj,
                            data->cb.mid[0], prompt))) {
            TCN_ALLOC_CSTRING(o);
            if (J2S(o)) {
                strncpy(data->password, J2S(o), SSL_MAX_PASSWORD_LEN);
                data->password[SSL_MAX_PASSWORD_LEN-1] = '\0';
                rv = (int)strlen(data->password);
            }
            TCN_FREE_CSTRING(o);
        }
    }
    else {
#ifdef WIN32
        rv = WIN32_SSL_password_prompt(data);
#else
        EVP_read_pw_string(data->password, SSL_MAX_PASSWORD_LEN,
                           data->prompt, 0);
#endif
        rv = (int)strlen(data->password);
    }
    if (rv > 0) {
        /* Remove LF char if present */
        char *r = strchr(data->password, '\n');
        if (r) {
            *r = '\0';
            rv--;
        }
#ifdef WIN32
        if ((r = strchr(data->password, '\r'))) {
            *r = '\0';
            rv--;
        }
#endif
    }
    return rv;
}

int SSL_password_callback(char *buf, int bufsiz, int verify,
                          void *cb)
{
    tcn_pass_cb_t *cb_data = (tcn_pass_cb_t *)cb;

    if (buf == NULL)
        return 0;
    *buf = '\0';
    if (cb_data == NULL)
        cb_data = &tcn_password_callback;
    if (!cb_data->prompt)
        cb_data->prompt = SSL_DEFAULT_PASS_PROMPT;
    if (cb_data->password[0]) {
        /* Return already obtained password */
        strncpy(buf, cb_data->password, bufsiz);
        buf[bufsiz - 1] = '\0';
        return (int)strlen(buf);
    }
    else {
        if (SSL_password_prompt(cb_data) > 0)
            strncpy(buf, cb_data->password, bufsiz);
    }
    buf[bufsiz - 1] = '\0';
    return (int)strlen(buf);
}

/*  _________________________________________________________________
**
**  Custom (EC)DH parameter support
**  _________________________________________________________________
*/
DH *SSL_dh_GetParamFromFile(const char *file)
{
    DH *dh = NULL;
    BIO *bio;

    if ((bio = BIO_new_file(file, "r")) == NULL)
        return NULL;
    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return dh;
}

#ifdef HAVE_ECC
EC_GROUP *SSL_ec_GetParamFromFile(const char *file)
{
    EC_GROUP *group = NULL;
    BIO *bio;

    if ((bio = BIO_new_file(file, "r")) == NULL)
        return NULL;
    group = PEM_read_bio_ECPKParameters(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return (group);
}
#endif

/*
 * Hand out standard DH parameters, based on the authentication strength
 */
DH *SSL_callback_tmp_DH(SSL *ssl, int export, int keylen)
{
    EVP_PKEY *pkey = SSL_get_privatekey(ssl);
    int type = pkey != NULL ? EVP_PKEY_base_id(pkey) : EVP_PKEY_NONE;

    /*
     * OpenSSL will call us with either keylen == 512 or keylen == 1024
     * (see the definition of SSL_EXPORT_PKEYLENGTH in ssl_locl.h).
     * Adjust the DH parameter length according to the size of the
     * RSA/DSA private key used for the current connection, and always
     * use at least 1024-bit parameters.
     * Note: This may cause interoperability issues with implementations
     * which limit their DH support to 1024 bit - e.g. Java 7 and earlier.
     * In this case, SSLCertificateFile can be used to specify fixed
     * 1024-bit DH parameters (with the effect that OpenSSL skips this
     * callback).
     */
    if ((type == EVP_PKEY_RSA) || (type == EVP_PKEY_DSA)) {
        keylen = EVP_PKEY_bits(pkey);
    }
    return SSL_get_dh_params(keylen);
}

/*
 * Read a file that optionally contains the server certificate in PEM
 * format, possibly followed by a sequence of CA certificates that
 * should be sent to the peer in the SSL Certificate message.
 */
int SSL_CTX_use_certificate_chain(SSL_CTX *ctx, const char *file,
                                  int skipfirst)
{
    BIO *bio;
    X509 *x509;
    unsigned long err;
    int n;

    if ((bio = BIO_new(BIO_s_file())) == NULL)
        return -1;
    if (BIO_read_filename(bio, file) <= 0) {
        BIO_free(bio);
        return -1;
    }
    /* optionally skip a leading server certificate */
    if (skipfirst) {
        if ((x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) == NULL) {
            BIO_free(bio);
            return -1;
        }
        X509_free(x509);
    }

    /* free a perhaps already configured extra chain */
    SSL_CTX_clear_extra_chain_certs(ctx);

    /* create new extra chain by loading the certs */
    n = 0;
    while ((x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        if (!SSL_CTX_add_extra_chain_cert(ctx, x509)) {
            X509_free(x509);
            BIO_free(bio);
            return -1;
        }
        n++;
    }
    /* Make sure that only the error is just an EOF */
    if ((err = ERR_peek_error()) > 0) {
        if (!(   ERR_GET_LIB(err) == ERR_LIB_PEM
              && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)) {
            BIO_free(bio);
            return -1;
        }
        while (ERR_get_error() > 0) ;
    }
    BIO_free(bio);
    return n;
}

/*
 * This OpenSSL callback function is called when OpenSSL
 * does client authentication and verifies the certificate chain.
 */


int SSL_callback_SSL_verify(int ok, X509_STORE_CTX *ctx)
{
   /* Get Apache context back through OpenSSL context */
    SSL *ssl = X509_STORE_CTX_get_ex_data(ctx,
                                          SSL_get_ex_data_X509_STORE_CTX_idx());
    tcn_ssl_conn_t *con = (tcn_ssl_conn_t *)SSL_get_app_data(ssl);
    /* Get verify ingredients */
    int errnum   = X509_STORE_CTX_get_error(ctx);
    int errdepth = X509_STORE_CTX_get_error_depth(ctx);
    int verify   = con->ctx->verify_mode;
    int depth    = con->ctx->verify_depth;

    if (verify == SSL_CVERIFY_UNSET ||
        verify == SSL_CVERIFY_NONE)
        return 1;

    if (SSL_VERIFY_ERROR_IS_OPTIONAL(errnum) &&
        (verify == SSL_CVERIFY_OPTIONAL_NO_CA)) {
        ok = 1;
        SSL_set_verify_result(ssl, X509_V_OK);
    }

    /*
     * Expired certificates vs. "expired" CRLs: by default, OpenSSL
     * turns X509_V_ERR_CRL_HAS_EXPIRED into a "certificate_expired(45)"
     * SSL alert, but that's not really the message we should convey to the
     * peer (at the very least, it's confusing, and in many cases, it's also
     * inaccurate, as the certificate itself may very well not have expired
     * yet). We set the X509_STORE_CTX error to something which OpenSSL's
     * s3_both.c:ssl_verify_alarm_type() maps to SSL_AD_CERTIFICATE_UNKNOWN,
     * i.e. the peer will receive a "certificate_unknown(46)" alert.
     * We do not touch errnum, though, so that later on we will still log
     * the "real" error, as returned by OpenSSL.
     */
    if (!ok && errnum == X509_V_ERR_CRL_HAS_EXPIRED) {
        X509_STORE_CTX_set_error(ctx, -1);
    }

#ifdef HAVE_OCSP_STAPLING
    /* First perform OCSP validation if possible */
    if (ok) {
        /* If there was an optional verification error, it's not
         * possible to perform OCSP validation since the issuer may be
         * missing/untrusted.  Fail in that case.
         */
        if (SSL_VERIFY_ERROR_IS_OPTIONAL(errnum)) {
            X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
            errnum = X509_V_ERR_APPLICATION_VERIFICATION;
            ok = 0;
        }
        else {
            // int ocsp_response = ssl_verify_OCSP(ok, ctx);
               int ocsp_response = OCSP_STATUS_UNKNOWN; /* TODO: Reimplement ssl_verify_OCSP() */
            if (ocsp_response == OCSP_STATUS_REVOKED) {
                ok = 0 ;
                errnum = X509_STORE_CTX_get_error(ctx);
            }
            else if (ocsp_response == OCSP_STATUS_UNKNOWN) {
                /* TODO: do nothing for time being */
                ;
            }
        }
    }
#endif
    /*
     * If we already know it's not ok, log the real reason
     */
    if (!ok) {
        /* TODO: Some logging
         * Certificate Verification: Error
         */
        if (con->peer) {
            X509_free(con->peer);
            con->peer = NULL;
        }
    }
    if (errdepth > depth) {
        /* TODO: Some logging
         * Certificate Verification: Certificate Chain too long
         */
        ok = 0;
    }
    return ok;
}

/*
 * This callback function is executed while OpenSSL processes the SSL
 * handshake and does SSL record layer stuff.  It's used to trap
 * client-initiated renegotiations, and for dumping everything to the
 * log.
 */
void SSL_callback_handshake(const SSL *ssl, int where, int rc)
{
    tcn_ssl_conn_t *con = (tcn_ssl_conn_t *)SSL_get_app_data(ssl);

    /* Retrieve the conn_rec and the associated SSLConnRec. */
    if (con == NULL) {
        return;
    }


    /* If the reneg state is to reject renegotiations, check the SSL
     * state machine and move to ABORT if a Client Hello is being
     * read. */
    if ((where & SSL_CB_HANDSHAKE_START) &&
         con->reneg_state == RENEG_REJECT) {
        con->reneg_state = RENEG_ABORT;
    }
    /* If the first handshake is complete, change state to reject any
     * subsequent client-initated renegotiation. */
    else if ((where & SSL_CB_HANDSHAKE_DONE) && con->reneg_state == RENEG_INIT) {
        con->reneg_state = RENEG_REJECT;
    }

}

/* callback from ssl-experiment, to be mergend in TCN */
int SSL_callback_alpn_select_proto(SSL* ssl, const unsigned char **out, unsigned char *outlen,
        const unsigned char *in, unsigned int inlen, void *arg) {

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
    /* TODO END */

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

/* To be replaced by common callback (between TC and Undertow) */
/* int SSL_callback_alpn_select_proto(SSL* ssl, const unsigned char **out, unsigned char *outlen,
        const unsigned char *in, unsigned int inlen, void *arg) {
    tcn_ssl_ctxt_t *ssl_ctxt = arg;
    return select_next_proto(ssl, out, outlen, in, inlen, ssl_ctxt->alpn_proto_data, ssl_ctxt->alpn_proto_len, ssl_ctxt->alpn_selector_failure_behavior);
} */

int select_next_proto(SSL *ssl, const unsigned char **out, unsigned char *outlen,
        const unsigned char *in, unsigned int inlen, unsigned char *supported_protos,
        unsigned int supported_protos_len, int failure_behavior) {

    unsigned int i = 0;
    unsigned char target_proto_len;
    const unsigned char *p;
    const unsigned char *end;
    const unsigned char *proto;
    unsigned char proto_len = '\0';

    while (i < supported_protos_len) {
        target_proto_len = *supported_protos;
        ++supported_protos;

        p = in;
        end = in + inlen;

        while (p < end) {
            proto_len = *p;
            proto = ++p;

            if (proto + proto_len <= end && target_proto_len == proto_len &&
                    memcmp(supported_protos, proto, proto_len) == 0) {

                // We found a match, so set the output and return with OK!
                *out = proto;
                *outlen = proto_len;

                return SSL_TLSEXT_ERR_OK;
            }
            // Move on to the next protocol.
            p += proto_len;
        }

        // increment len and pointers.
        i += target_proto_len;
        supported_protos += target_proto_len;
    }

    if (supported_protos_len > 0 && inlen > 0 && failure_behavior == SSL_SELECTOR_FAILURE_CHOOSE_MY_LAST_PROTOCOL) {
         // There were no match but we just select our last protocol and hope the other peer support it.
         //
         // decrement the pointer again so the pointer points to the start of the protocol.
         p -= proto_len;
         *out = p;
         *outlen = proto_len;
         return SSL_TLSEXT_ERR_OK;
    }
    // TODO: OpenSSL currently not support to fail with fatal error. Once this changes we can also support it here.
    //       Issue https://github.com/openssl/openssl/issues/188 has been created for this.
    // Nothing matched so not select anything and just accept.
    return SSL_TLSEXT_ERR_NOACK;
}

#endif /* HAVE_OPENSSL  */
