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


TCN_IMPLEMENT_CALL(jobject, Buffer, create)(TCN_STDARGS, jlong addr,
                                            jint size)
{
    void *mem = J2P(addr, void *);

    UNREFERENCED(o);
    TCN_ASSERT(mem  != 0);
    TCN_ASSERT(size != 0);

    if (mem && size)
        return (*e)->NewDirectByteBuffer(e, mem, (jlong)size);
    else
        return NULL;
}

TCN_IMPLEMENT_CALL(void, Buffer, free)(TCN_STDARGS, jobject bb)
{
    void *mem;

    UNREFERENCED(o);
    if ((mem = (*e)->GetDirectBufferAddress(e, bb)) != NULL) {
        free(mem);
    }
}

TCN_IMPLEMENT_CALL(jlong, Buffer, address)(TCN_STDARGS, jobject bb)
{
    UNREFERENCED(o);
    return P2J((*e)->GetDirectBufferAddress(e, bb));
}

TCN_IMPLEMENT_CALL(jlong, Buffer, size)(TCN_STDARGS, jobject bb)
{
    UNREFERENCED(o);
    return (*e)->GetDirectBufferCapacity(e, bb);
}
