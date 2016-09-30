/*
 * ---------------------------------------------------------------------------
 * OpenAES License
 * ---------------------------------------------------------------------------
 * Copyright (c) 2013, Nabil S. Al Ramli, www.nalramli.com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ---------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <android/log.h>
#include <jni.h>

#include "oaes_lib.h"

#ifndef JNIEXPORT
#define JNIEXPORT __attribute__ ((visibility("default")))
#endif //end JNIEXPORT

#define LOGE(format, ...) __android_log_print(ANDROID_LOG_ERROR, "OpenAES", format, ##__VA_ARGS__);

/*
 * Class:     com_github_openaes_OpenAES
 * Method:    encrypt
 * Signature: ([B[B)[B
 */
jbyteArray native_aes_encrypt(JNIEnv* env, jobject obj, jbyteArray jkey, jbyteArray jcleartext)
{
    uint8_t *key;
    uint8_t *content;
    int len_k, len_c;
    uint8_t *buf = NULL;
    size_t len_o = 0;

    key = (*env)->GetByteArrayElements(env, jkey, NULL);
    len_k = (*env)->GetArrayLength(env, jkey);
    content = (*env)->GetByteArrayElements(env, jcleartext, JNI_FALSE);
    len_c = (*env)->GetArrayLength(env, jcleartext);

#ifdef OAES_DEBUG
    LOGE("key:[%d, %s]", len_k, key);
    LOGE("content:[%d, %s]", len_c, content);
#endif //end of OAES_DEBUG

    buf = (uint8_t *)calloc(len_c, sizeof(uint8_t));

    //init openaes
    OAES_CTX * ctx = NULL;

    ctx = oaes_alloc();
    if( NULL == ctx )
    {
        LOGE("Error: Failed to initialize OAES.\n");
        return NULL;
    }

    OAES_RET ret = oaes_key_import( ctx, key, len_k );
    if( OAES_RET_SUCCESS != ret)
    {
        LOGE("Error: Import key error(%d).\n", ret);
        oaes_free(&ctx);
        return NULL;
    }

    // encrypt get length
    ret = oaes_encrypt( ctx, content, len_c, NULL, &len_o, NULL, NULL );
#ifdef OAES_DEBUG
    printf("out len:%ld\n", len_o);
#endif //end of OAES_DEBUG

    if( OAES_RET_SUCCESS != ret )
    {
        LOGE("Error: Failed to encrypt.\n");
        oaes_free(&ctx);
        return NULL;
    }

    buf = (uint8_t *) calloc(len_o, sizeof(uint8_t));
    if( NULL == buf )
    {
        LOGE("Error: Failed to allocate memory.\n");
        oaes_free(&ctx);
        return NULL;
    }

    //after get len && malloc, encrypt again
    ret = oaes_encrypt( ctx, content, len_c, buf, &len_o, NULL, NULL );

    //cleanup aes && jni
    if( OAES_RET_SUCCESS !=  oaes_free(&ctx) )
        LOGE("Error: Failed to uninitialize OAES.\n");

    (*env)->ReleaseByteArrayElements(env, jkey, key, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jcleartext, content, JNI_ABORT);

	jbyteArray result = (*env)->NewByteArray(env, len_o);
	(*env)->SetByteArrayRegion(env, result, 0, len_o, buf);

	return result;
}

/*
 * Class:     com_github_openaes_OpenAES
 * Method:    decrypt
 * Signature: ([B[B)[B
 */
jbyteArray native_aes_decrypt(JNIEnv* env, jobject obj, jbyteArray jkey, jbyteArray jciphertext)
{
    uint8_t *key;
    uint8_t *content;
    int len_k, len_c;
    uint8_t *buf = NULL;
    size_t len_o = 0;

    len_k = (*env)->GetArrayLength(env, jkey);
    key = (*env)->GetByteArrayElements(env, jkey, NULL);
    content = (*env)->GetByteArrayElements(env, jciphertext, JNI_FALSE);
    len_c = (*env)->GetArrayLength(env, jciphertext);

#ifdef OAES_DEBUG
    LOGE("key:[%d, %s]", len_k, key);
    LOGE("content:[%d, %s]", len_c, content);
#endif //end of OAES_DEBUG

    buf = (uint8_t *)calloc(len_c, sizeof(uint8_t));

    //init openaes
    OAES_CTX * ctx = NULL;

    ctx = oaes_alloc();
    if( NULL == ctx )
    {
        LOGE("Error: Failed to initialize OAES.\n");
        return NULL;
    }

    OAES_RET ret = oaes_key_import( ctx, key, len_k );
    if( OAES_RET_SUCCESS != ret)
    {
        LOGE("Error: Import key error(%d).\n", ret);
        oaes_free(&ctx);
        return NULL;
    }

    // decrypt get length
    ret = oaes_decrypt( ctx, content, len_c, NULL, &len_o, NULL, NULL );
#ifdef OAES_DEBUG
    printf("out len:%ld\n", len_o);
#endif //end of OAES_DEBUG

    if( OAES_RET_SUCCESS != ret )
    {
        LOGE("Error: Failed to encrypt.\n");
        oaes_free(&ctx);
        return NULL;
    }

    buf = (uint8_t *) calloc(len_o, sizeof(uint8_t));
    if( NULL == buf )
    {
        LOGE("Error: Failed to allocate memory.\n");
        oaes_free(&ctx);
        return NULL;
    }

    //after get len && malloc, decrypt again
    ret = oaes_decrypt( ctx, content, len_c, buf, &len_o, NULL, NULL );

    //cleanup aes && jni
    if( OAES_RET_SUCCESS !=  oaes_free(&ctx) )
        LOGE("Error: Failed to uninitialize OAES.\n");

    (*env)->ReleaseByteArrayElements(env, jkey, key, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jciphertext, content, JNI_ABORT);

	jbyteArray result = (*env)->NewByteArray(env, len_o);
	(*env)->SetByteArrayRegion(env, result, 0, len_o, buf);

	return result;
}

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
	JNIEnv* env;
	if ((*vm)->GetEnv(vm, (void**) &env, JNI_VERSION_1_4) != JNI_OK)
		return -1;

    JNINativeMethod methods[] =
    {
		{ "encrypt", "([B[B)[B", (void *) native_aes_encrypt },
		{ "decrypt", "([B[B)[B", (void *) native_aes_decrypt }
    };

    jclass clz;
    clz = (*env)->FindClass(env, "com/github/openaes/OpenAES");

#define NELEM(x) ((int) (sizeof(x) / sizeof((x)[0])))
    (*env)->RegisterNatives(env, clz, methods, NELEM(methods));

	return JNI_VERSION_1_6;
}
