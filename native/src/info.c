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

#define DECLARE_FINFO_FIELD(name) static jfieldID _fid##name = NULL
#define FINFO_FIELD(name)         _fid##name

#define GET_FINFO_I(N)      \
    _fid##N = (*e)->GetFieldID(e, finfo, #N, "I");  \
    if (_fid##N == NULL) {                          \
        (*e)->ExceptionClear(e);                    \
        goto cleanup;                               \
    } else (void)(0)

#define GET_FINFO_J(N)      \
    _fid##N = (*e)->GetFieldID(e, finfo, #N, "J");  \
    if (_fid##N == NULL) {                          \
        (*e)->ExceptionClear(e);                    \
        goto cleanup;                               \
    } else (void)(0)

#define GET_FINFO_S(N)      \
    _fid##N = (*e)->GetFieldID(e, finfo, #N,        \
                             "Ljava/lang/String;"); \
    if (_fid##N == NULL) {                          \
        (*e)->ExceptionClear(e);                    \
        goto cleanup;                               \
    } else (void)(0)

#define SET_FINFO_I(N, V)  \
    (*e)->SetIntField(e, obj, _fid##N, (jint)(V))

#define SET_FINFO_J(N, V)  \
    (*e)->SetLongField(e, obj, _fid##N, (jlong)(V))

#define SET_FINFO_S(N, V)                 \
    (*e)->SetObjectField(e, obj, _fid##N, \
        (V) ? AJP_TO_JSTRING((V)) : NULL)


#define DECLARE_AINFO_FIELD(name) static jfieldID _aid##name = NULL
#define AINFO_FIELD(name)         _aid##name

#define GET_AINFO_I(N)      \
    _aid##N = (*e)->GetFieldID(e, ainfo, #N, "I");  \
    if (_aid##N == NULL) {                          \
        (*e)->ExceptionClear(e);                    \
        goto cleanup;                               \
    } else (void)(0)

#define GET_AINFO_J(N)      \
    _aid##N = (*e)->GetFieldID(e, ainfo, #N, "J");  \
    if (_aid##N == NULL) {                          \
        (*e)->ExceptionClear(e);                    \
        goto cleanup;                               \
    } else (void)(0)

#define GET_AINFO_S(N)      \
    _aid##N = (*e)->GetFieldID(e, ainfo, #N,        \
                             "Ljava/lang/String;"); \
    if (_aid##N == NULL) {                          \
        (*e)->ExceptionClear(e);                    \
        goto cleanup;                               \
    } else (void)(0)

#define SET_AINFO_I(N, V)  \
    (*e)->SetIntField(e, obj, _aid##N, (jint)(V))

#define SET_AINFO_J(N, V)  \
    (*e)->SetLongField(e, obj, _aid##N, (jlong)(V))

#define SET_AINFO_S(N, V)                 \
    (*e)->SetObjectField(e, obj, _aid##N, \
        (V) ? AJP_TO_JSTRING((V)) : NULL)


DECLARE_FINFO_FIELD(pool);
DECLARE_FINFO_FIELD(valid);
DECLARE_FINFO_FIELD(protection);
DECLARE_FINFO_FIELD(filetype);
DECLARE_FINFO_FIELD(user);
DECLARE_FINFO_FIELD(group);
DECLARE_FINFO_FIELD(inode);
DECLARE_FINFO_FIELD(device);
DECLARE_FINFO_FIELD(nlink);
DECLARE_FINFO_FIELD(size);
DECLARE_FINFO_FIELD(csize);
DECLARE_FINFO_FIELD(atime);
DECLARE_FINFO_FIELD(mtime);
DECLARE_FINFO_FIELD(ctime);
DECLARE_FINFO_FIELD(fname);
DECLARE_FINFO_FIELD(name);
DECLARE_FINFO_FIELD(filehand);

DECLARE_AINFO_FIELD(pool);
DECLARE_AINFO_FIELD(hostname);
DECLARE_AINFO_FIELD(servname);
DECLARE_AINFO_FIELD(port);
DECLARE_AINFO_FIELD(family);
DECLARE_AINFO_FIELD(next);

static int finfo_class_initialized = 0;
static int ainfo_class_initialized = 0;
static jmethodID finfo_class_init = NULL;
static jmethodID ainfo_class_init = NULL;
static jclass finfo_class = NULL;
static jclass ainfo_class = NULL;

apr_status_t tcn_load_finfo_class(JNIEnv *e, jclass finfo)
{
    GET_FINFO_J(pool);
    GET_FINFO_I(valid);
    GET_FINFO_I(protection);
    GET_FINFO_I(filetype);
    GET_FINFO_I(user);
    GET_FINFO_I(group);
    GET_FINFO_I(inode);
    GET_FINFO_I(device);
    GET_FINFO_I(nlink);
    GET_FINFO_J(size);
    GET_FINFO_J(csize);
    GET_FINFO_J(atime);
    GET_FINFO_J(mtime);
    GET_FINFO_J(ctime);
    GET_FINFO_S(fname);
    GET_FINFO_S(name);
    GET_FINFO_J(filehand);
    
    finfo_class_init = (*e)->GetMethodID(e, finfo,
                                      "<init>", "()V");
    if (finfo_class_init == NULL)
        goto cleanup;
    finfo_class_initialized = 1;
    finfo_class = finfo;
cleanup:
    return APR_SUCCESS;
}

apr_status_t tcn_load_ainfo_class(JNIEnv *e, jclass ainfo)
{
    GET_AINFO_J(pool);
    GET_AINFO_S(hostname);
    GET_AINFO_S(servname);
    GET_AINFO_I(port);
    GET_AINFO_I(family);
    GET_AINFO_J(next);
    ainfo_class_init = (*e)->GetMethodID(e, ainfo,
                                      "<init>", "()V");

    if (ainfo_class_init == NULL)
        goto cleanup;
    ainfo_class_initialized = 1;
    ainfo_class = ainfo;
cleanup:
    return APR_SUCCESS;
}

static void fill_finfo(JNIEnv *e, jobject obj, apr_finfo_t *info)
{

    SET_FINFO_J(pool, P2J(info->pool));
    SET_FINFO_I(valid, info->valid);
    SET_FINFO_I(protection, info->protection);
    SET_FINFO_I(filetype, info->filetype);
    SET_FINFO_I(user, ((jlong)info->user));
    SET_FINFO_I(group, ((jlong)info->group));
    SET_FINFO_I(inode, info->inode);
    SET_FINFO_I(device, info->device);
    SET_FINFO_I(nlink, info->nlink);
    SET_FINFO_J(size, info->size);
    SET_FINFO_J(csize, info->csize);
    SET_FINFO_J(atime, info->atime);
    SET_FINFO_J(mtime, info->mtime);
    SET_FINFO_J(ctime, info->ctime);
    SET_FINFO_S(fname, info->fname);
    SET_FINFO_S(name, info->name);
    SET_FINFO_J(filehand, P2J(info->filehand));
}