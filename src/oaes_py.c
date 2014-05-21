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

#include <Python.h>

#include "oaes_lib.h"

static PyObject *OpenaesError;

PyObject* python_oaes_encrypt(PyObject* self, PyObject* args)
{
    uint8_t *key;
    uint8_t *content;
    int len_k, len_c;
    uint8_t *buf = NULL;
    size_t len_o = 0;

    if (!PyArg_ParseTuple(args, "s#s#:encrypt", &key, &len_k, &content, &len_c))
        return NULL;

#ifdef OAES_DEBUG
    printf("content len:%d\n", len_c);
    printf("key len:%d\n", len_k);
#endif //end of OAES_DEBUG
	
    buf = (uint8_t *)calloc(len_c, sizeof(uint8_t));

    //init openaes
    OAES_CTX * ctx = NULL;

    ctx = oaes_alloc();
    if( NULL == ctx )
    {
        PyErr_SetString(OpenaesError, "Failed to initialize OAES.");
        return NULL;
    }

    OAES_RET ret = oaes_key_import( ctx, key, len_k );
    if( OAES_RET_SUCCESS != ret)
    {
        PyErr_SetString(OpenaesError, "Import encrypt key error.");
        oaes_free(&ctx);
        return NULL;
    }

    // encrypt get length
    ret = oaes_encrypt( ctx, content, len_c, NULL, &len_o );
#ifdef OAES_DEBUG
    printf("out len:%ld\n", len_o);
#endif //end of OAES_DEBUG

    if( OAES_RET_SUCCESS != ret )
    {
        PyErr_SetString(OpenaesError, "Failed to encrypt.");
        oaes_free(&ctx);
        return NULL;
    }

    buf = (uint8_t *) calloc(len_o, sizeof(uint8_t));
    if( NULL == buf )
    {
        PyErr_SetString(OpenaesError, "Failed to allocate memory.");
        oaes_free(&ctx);
        return NULL;
    }

    //after get len && malloc, encrypt again
    ret = oaes_encrypt( ctx, content, len_c, buf, &len_o );

    if( OAES_RET_SUCCESS !=  oaes_free(&ctx) )
        PyErr_SetString(OpenaesError, "Failed to uninitialize OAES.");

	PyObject *po = Py_BuildValue("s#", buf, len_o);

    return po;
}

PyObject* python_oaes_decrypt(PyObject* self, PyObject* args)
{
    const uint8_t *key;
    const uint8_t *content;
    unsigned int len_k, len_c;
    uint8_t *buf = NULL;
    size_t len_o = 0;

    if (!PyArg_ParseTuple(args, "s#s#:decrypt", &key, &len_k, &content, &len_c))
        return NULL;
		
#ifdef OAES_DEBUG
    printf("content len:%d\n", len_c);
    printf("key len:%d\n", len_k);
#endif //end of OAES_DEBUG

    buf = (uint8_t *)calloc(len_c, sizeof(uint8_t));

    //init openaes
    OAES_CTX * ctx = NULL;
    OAES_RET ret = OAES_RET_SUCCESS;

    ctx = oaes_alloc();
    if( NULL == ctx )
    {
        PyErr_SetString(OpenaesError, "Failed to initialize OAES.");
        return NULL;
    }

    ret = oaes_key_import( ctx, key, len_k );
    if( OAES_RET_SUCCESS != ret)
    {
        PyErr_SetString(OpenaesError, "Import decrypt key error.");
        oaes_free(&ctx);
        return NULL;
    }

    // decrypt get length
    ret = oaes_decrypt( ctx, content, len_c, NULL, &len_o );
#ifdef OAES_DEBUG
    printf("out len:%ld\n", len_o);
#endif //end of OAES_DEBUG

    if( OAES_RET_SUCCESS != ret )
    {
        PyErr_SetString(OpenaesError, "Failed to decrypt.");
        oaes_free(&ctx);
        return NULL;
    }

    buf = (uint8_t *) calloc(len_o, sizeof(uint8_t));
    if( NULL == buf )
    {
        PyErr_SetString(OpenaesError, "Failed to allocate memory.");
        oaes_free(&ctx);
        return NULL;
    }

    //after get len && malloc, decrypt again
    ret = oaes_decrypt( ctx, content, len_c, buf, &len_o );

    if( OAES_RET_SUCCESS !=  oaes_free(&ctx) )
        PyErr_SetString(OpenaesError, "Failed to uninitialize OAES.");

	PyObject *po = Py_BuildValue("s#", buf, len_o);

    return po;
}

static PyMethodDef openaesMethods[] =
{
    // library methods
    {"encrypt",	 python_oaes_encrypt, METH_VARARGS, "openaes encrypt a string."},
    {"decrypt",	 python_oaes_decrypt, METH_VARARGS, "openaes decrypt a string."},
    {NULL, NULL, 0, NULL}		 // sentinel
};

PyMODINIT_FUNC initopenaes()
{
    // define methods
    PyObject* m = Py_InitModule("openaes", openaesMethods);
    if (m == NULL)
        return;
        
    OpenaesError = PyErr_NewException("openaes.error", NULL, NULL);
    Py_INCREF(OpenaesError);
    PyModule_AddObject(m, "error", OpenaesError);
}
