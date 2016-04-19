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

#include "tcn.h"

#include "tcn_version.h"

#ifdef TCN_DO_STATISTICS
extern void sp_poll_dump_statistics();
extern void sp_network_dump_statistics();
#endif

static JavaVM     *tcn_global_vm = NULL;

static jclass    jString_class;
static jmethodID jString_init;
static jmethodID jString_getBytes;
extern void ssl_network_dump_statistics();
tcn_status_t ssl_init_cleanup();

int tcn_parent_pid = 0;

/* Called by the JVM when APR_JAVA is loaded */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env;
    void   *ppe;

    if ((*vm)->GetEnv(vm, &ppe, JNI_VERSION_1_4)) {
        return JNI_ERR;
    }
    tcn_global_vm = vm;
    env           = (JNIEnv *)ppe;

    /* Initialize global java.lang.String class */
    TCN_LOAD_CLASS(env, jString_class, "java/lang/String", JNI_ERR);

    TCN_GET_METHOD(env, jString_class, jString_init,
                   "<init>", "([B)V", JNI_ERR);
    TCN_GET_METHOD(env, jString_class, jString_getBytes,
                   "getBytes", "()[B", JNI_ERR);
#ifdef WIN32
    {
        char *ppid = getenv(TCN_PARENT_IDE);
        if (ppid)
            tcn_parent_pid = atoi(ppid);
    }
#else
    tcn_parent_pid = getppid();
#endif

    return  JNI_VERSION_1_4;
}


/* Called by the JVM before the APR_JAVA is unloaded */
JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
    JNIEnv *env;
    void   *ppe;

    UNREFERENCED(reserved);

    if ((*vm)->GetEnv(vm, &ppe, JNI_VERSION_1_2)) {
        return;
    }
    if (jString_class) {
        env  = (JNIEnv *)ppe;
        TCN_UNLOAD_CLASS(env, jString_class);
    }
}

jstring tcn_new_stringn(JNIEnv *env, const char *str, size_t l)
{
    jstring result;
    jbyteArray bytes = 0;

    if (!str)
        return NULL;
    if ((*env)->EnsureLocalCapacity(env, 2) < 0) {
        return NULL; /* out of memory error */
    }
    bytes = (*env)->NewByteArray(env, l);
    if (bytes != NULL) {
        (*env)->SetByteArrayRegion(env, bytes, 0, l, (jbyte *)str);
        result = (*env)->NewObject(env, jString_class, jString_init, bytes);
        (*env)->DeleteLocalRef(env, bytes);
        return result;
    } /* else fall through */
    return NULL;
}


jstring tcn_new_string(JNIEnv *env, const char *str)
{
    if (!str)
        return NULL;
    else
        return (*env)->NewStringUTF(env, str);
}

jint throwIllegalStateException( JNIEnv *env, char *message )
{
    jclass exClass;
    char *className = "java/lang/IllegalStateException";

    exClass = (*env)->FindClass( env, className);
    return (*env)->ThrowNew( env, exClass, message );
}


jint throwIllegalArgumentException( JNIEnv *env, char *message )
{
    jclass exClass;
    char *className = "java/lang/IllegalArgumentException";

    exClass = (*env)->FindClass( env, className);
    return (*env)->ThrowNew( env, exClass, message );
}

void tcn_Throw(JNIEnv *env, char *fmt, ...) {
    char msg[8124] = {'\0'};
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, 8124, fmt, ap);
    throwIllegalStateException(env, msg);
    va_end(ap);
}

TCN_IMPLEMENT_CALL(jint, Library, version)(TCN_STDARGS, jint what)
{

    UNREFERENCED_STDARGS;

    switch (what) {
        case 0x01:
            return TCN_MAJOR_VERSION;
        break;
        case 0x02:
            return TCN_MINOR_VERSION;
        break;
        case 0x03:
            return TCN_PATCH_VERSION;
        break;
        case 0x04:
            return TCN_IS_DEV_VERSION;
        break;
    }
    return 0;
}

TCN_IMPLEMENT_CALL(jstring, Library, versionString)(TCN_STDARGS)
{
    UNREFERENCED(o);
    return AJP_TO_JSTRING(TCN_VERSION_STRING);
}

JavaVM * tcn_get_java_vm()
{
    return tcn_global_vm;
}

TCN_IMPLEMENT_CALL(void, Library, terminate)(TCN_STDARGS)
{

    UNREFERENCED_STDARGS;
    ssl_init_cleanup();
}

jint tcn_get_java_env(JNIEnv **env)
{
    if ((*tcn_global_vm)->GetEnv(tcn_global_vm, (void **)env,
                                 JNI_VERSION_1_4)) {
        return JNI_ERR;
    }
    return JNI_OK;
}
