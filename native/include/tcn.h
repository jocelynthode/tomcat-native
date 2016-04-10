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

#ifndef TCN_H
#define TCN_H

#if defined(DEBUG) || defined(_DEBUG)
/* On -DDEBUG use the statistics */
#ifndef TCN_DO_STATISTICS
#define TCN_DO_STATISTICS
#endif
#endif
#include <stdio.h>
#include <stdlib.h>
#if defined(_WIN32) && !defined(__CYGWIN__)
#include <process.h>
#else
#include <unistd.h>
#endif

#include "tcn_api.h"


#if defined(_DEBUG) || defined(DEBUG)
#include <assert.h>
#define TCN_ASSERT(x)  assert((x))
#else
#define TCN_ASSERT(x) (void)0
#endif

#ifndef APR_MAX_IOVEC_SIZE
#define APR_MAX_IOVEC_SIZE 1024
#endif

#define TCN_TIMEUP      APR_OS_START_USERERR + 1
#define TCN_EAGAIN      APR_OS_START_USERERR + 2
#define TCN_EINTR       APR_OS_START_USERERR + 3
#define TCN_EINPROGRESS APR_OS_START_USERERR + 4
#define TCN_ETIMEDOUT   APR_OS_START_USERERR + 5

#define TCN_LOG_EMERG  1
#define TCN_LOG_ERROR  2
#define TCN_LOG_NOTICE 3
#define TCN_LOG_WARN   4
#define TCN_LOG_INFO   5
#define TCN_LOG_DEBUG  6

#define TCN_ERROR_WRAP(E)                   \
    if (APR_STATUS_IS_TIMEUP(E))            \
        (E) = TCN_TIMEUP;                   \
    else if (APR_STATUS_IS_EAGAIN(E))       \
        (E) = TCN_EAGAIN;                   \
    else if (APR_STATUS_IS_EINTR(E))        \
        (E) = TCN_EINTR;                    \
    else if (APR_STATUS_IS_EINPROGRESS(E))  \
        (E) = TCN_EINPROGRESS;              \
    else if (APR_STATUS_IS_ETIMEDOUT(E))    \
        (E) = TCN_ETIMEDOUT;                \
    else                                    \
        (E) = (E)

#define TCN_CLASS_PATH  "org/apache/tomcat/jni/"
#define TCN_ERROR_CLASS TCN_CLASS_PATH "Error"
#define TCN_PARENT_IDE  "TCN_PARENT_ID"

#define UNREFERENCED(P)      (P) = (P)
#define UNREFERENCED_STDARGS (e) = (e);(o) = (o);
// Use "weak" to redeclare optional features
// TODO: Check if needed
#define weak __attribute__((weak))
#ifdef WIN32
#define LLT(X) (X)
#else
#define LLT(X) ((long)(X))
#endif
#define P2J(P)          ((jlong)LLT(P))
#define J2P(P, T)       ((T)LLT((jlong)P))
/* On stack buffer size */
#define TCN_BUFFER_SZ   8192
#define TCN_STDARGS     JNIEnv *e, jobject o
#define TCN_IMPARGS     JNIEnv *e, jobject o, void *sock
#define TCN_IMPCALL(X)  e, o, X->opaque

//TODO: Java_org_apache_tcn2_##CL##_##FN
#define TCN_IMPLEMENT_CALL(RT, CL, FN)  \
    JNIEXPORT RT JNICALL Java_org_apache_tomcat_jni_##CL##_##FN

#define TCN_IMPLEMENT_METHOD(RT, FN)    \
    static RT method_##FN

#define TCN_GETNET_METHOD(FN)  method_##FN

/* Private helper functions */
void tcn_Throw(JNIEnv *env, char *fmt, ...);
jint throwIllegalStateException( JNIEnv *env, char *message);
jint throwIllegalArgumentException( JNIEnv *env, char *message);
jint tcn_get_java_env(JNIEnv **env);
JavaVM * tcn_get_java_vm();

jstring tcn_new_string(JNIEnv *env, const char *str);
jstring tcn_new_stringn(JNIEnv *env, const char *str, size_t l);


void setup_session_context(JNIEnv *e, tcn_ssl_ctxt_t *c);
/*thread setup function*/
void ssl_thread_setup();

void alpn_init(JNIEnv *e);
void session_init(JNIEnv *e);


#define J2S(V)  c##V
#define J2L(V)  p##V

#define J2T(T) (apr_time_t)((T))

#define TCN_BEGIN_MACRO     if (1) {
#define TCN_END_MACRO       } else (void)(0)

#define TCN_ALLOC_CSTRING(V)     \
    const char *c##V = V ? (const char *)((*e)->GetStringUTFChars(e, V, 0)) : NULL

#define TCN_FREE_CSTRING(V)      \
    if (c##V) (*e)->ReleaseStringUTFChars(e, V, c##V)

#define AJP_TO_JSTRING(V)   (*e)->NewStringUTF((e), (V))

#define TCN_FREE_JSTRING(V)      \
    TCN_BEGIN_MACRO              \
        if (c##V)                \
            free(c##V);          \
    TCN_END_MACRO


#define TCN_LOAD_CLASS(E, C, N, R)                  \
    TCN_BEGIN_MACRO                                 \
        jclass _##C = (*(E))->FindClass((E), N);    \
        if (_##C == NULL) {                         \
            (*(E))->ExceptionClear((E));            \
            return R;                               \
        }                                           \
        C = (*(E))->NewGlobalRef((E), _##C);        \
        (*(E))->DeleteLocalRef((E), _##C);          \
    TCN_END_MACRO

#define TCN_UNLOAD_CLASS(E, C)                      \
        (*(E))->DeleteGlobalRef((E), (C))

#define TCN_IS_NULL(E, O)                           \
        ((*(E))->IsSameObject((E), (O), NULL) == JNI_TRUE)

#define TCN_GET_METHOD(E, C, M, N, S, R)            \
    TCN_BEGIN_MACRO                                 \
        M = (*(E))->GetMethodID((E), C, N, S);      \
        if (M == NULL) {                            \
            return R;                               \
        }                                           \
    TCN_END_MACRO

#define TCN_MAX_METHODS 8

typedef struct {
    jobject     obj;
    jmethodID   mid[TCN_MAX_METHODS];
    void        *opaque;
} tcn_callback_t;

#ifdef WIN32
#define TCN_ALLOC_WSTRING(V)     \
    jsize wl##V = (*e)->GetStringLength(e, V);   \
    const jchar *ws##V = V ? (const jchar *)((*e)->GetStringChars(e, V, 0)) : NULL; \
    jchar *w##V = NULL

#define TCN_INIT_WSTRING(V)                                     \
        w##V = (jchar *)malloc((wl##V + 1) * sizeof(jchar));    \
        wcsncpy(w##V, ws##V, wl##V);                        \
        w##V[wl##V] = 0

#define TCN_FREE_WSTRING(V)      \
    if (ws##V) (*e)->ReleaseStringChars(e, V, ws##V); \
    if (ws##V) free (w##V)

#define J2W(V)  w##V

#endif
