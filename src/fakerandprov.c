/*
 * Copyright 2020-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Provider source code pulled from providers/nullprov.c as boilerplate
 * -doggopwn
 */

#include <string.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <prov/names.h>

OSSL_provider_init_fn ossl_fakerand_provider_init;

int FAKERAND_DEBUG_ON=0;

void FAKERAND_DEBUG(const char* msg, ...){
	va_list args;
	va_start (args, msg);
	if (FAKERAND_DEBUG_ON == 1){	
		vprintf (msg, args);
	}
	va_end (args);
}


static const OSSL_PARAM fakerand_ctx_param_types[] = {
	OSSL_PARAM_DEFN(OSSL_RAND_PARAM_STATE, OSSL_PARAM_INTEGER, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_RAND_PARAM_STRENGTH, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0),
		OSSL_PARAM_DEFN(OSSL_DRBG_PARAM_RESEED_COUNTER, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM *fakerand_ctx_gettable_params(void* ctx, const OSSL_PROVIDER *provctx){
	return fakerand_ctx_param_types;
}

static int fakerand_ctx_get_params(void* ctx, OSSL_PARAM params[])
{
	FAKERAND_DEBUG("[fakerand] Context get_params called\n");
    OSSL_PARAM *p;

	for (int i = 0; params[i].key != NULL; i++){
    	FAKERAND_DEBUG("(%i) Searching for: %s\n", i+1, params[i].key);
	}
	p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL && !OSSL_PARAM_set_int(p, EVP_RAND_STATE_READY))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_uint(p, 512))
		return 0;
	p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_RESEED_COUNTER);
	if (p != NULL && !OSSL_PARAM_set_uint(p, 0))
		return 0;
    return 1;
}

/* Parameters we provide to the core */
static const OSSL_PARAM fakerand_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *fakerand_gettable_params(const OSSL_PROVIDER *prov)
{
    return fakerand_param_types;
}

static int fakerand_get_params(const OSSL_PROVIDER *provctx, OSSL_PARAM params[])
{
    FAKERAND_DEBUG("[fakerand] Provider get_params called\n");
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Fakerand Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
    return 1;
}

static void* fakerand_newctx(void* provctx, void* parent, const OSSL_DISPATCH* parent_calls){
	return provctx;
}

static void fakerand_freectx(void *ctx){
	return;
}

static int fakerand_instantiate(void *ctx, unsigned int strength, int prediction_resistance, const unsigned char* pstr, size_t pstr_len, const OSSL_PARAM params[]){
	FAKERAND_DEBUG("[fakerand] Instantiate called (strength=%u)\n", strength);
	return 1;
}

static int fakerand_uninstantiate(void *ctx){
	return 1;
}

static int fakerand_generate(void *ctx, unsigned char *out, size_t outlen, unsigned int strength, int prediction_resistance, const unsigned char *addin, size_t addin_len){
	FAKERAND_DEBUG("[fakerand] Generating %zu bytes of fake random\n", outlen);
	for (int i = 0; i < outlen; i++){
		out[i] = (unsigned char)(0xA5 ^ (i & 0xFF));
	}
	return 1;
}

static int fakerand_reseed(void *ctx, int prediction_resistance, const unsigned char *ent, size_t ent_len, const unsigned char *addin, size_t addin_len){
	FAKERAND_DEBUG("[fakerand] Reseed called\n");
	return 1;
}

size_t fakerand_get_seed(void *ctx, unsigned char **buffer, int entropy, size_t min_len, size_t max_len, int prediction_resistance, const unsigned char *adin, size_t adin_len){
	FAKERAND_DEBUG("[fakerand] Generating %i bytes of seed (DRBG strength=%i)\n", min_len, entropy);
	unsigned char* newBuf = OPENSSL_malloc(min_len);
	fakerand_generate(NULL, newBuf, min_len, 0, 0, NULL, 0);
	*buffer = newBuf;
	return min_len;
}

void fakerand_clear_seed(void *ctx, unsigned char *buffer, size_t b_len){
	FAKERAND_DEBUG("[fakerand] Clearing %i bytes of seed\n", b_len);
	OPENSSL_free(buffer);
}

int fakerand_lock(void* ctx){
	FAKERAND_DEBUG("[fakerand] Locking fakerand..\n");
	return 1;
}

void fakerand_unlock(void* ctx){
	FAKERAND_DEBUG("[fakerand] Unlocking fakerand..\n");
}


static const OSSL_DISPATCH fakerand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void(*)(void)) fakerand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void(*)(void)) fakerand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void(*)(void)) fakerand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void(*)(void)) fakerand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void(*)(void)) fakerand_generate },
    { OSSL_FUNC_RAND_RESEED, (void(*)(void)) fakerand_reseed },
	{ OSSL_FUNC_RAND_GET_SEED, (void(*)(void)) fakerand_get_seed },
	{ OSSL_FUNC_RAND_CLEAR_SEED, (void(*)(void)) fakerand_clear_seed },
	{ OSSL_FUNC_RAND_LOCK, (void(*)(void)) fakerand_lock },
	{ OSSL_FUNC_RAND_UNLOCK, (void(*)(void)) fakerand_unlock },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void(*)(void)) fakerand_ctx_gettable_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void(*)(void)) fakerand_ctx_get_params },
    OSSL_DISPATCH_END
	
};

static const OSSL_ALGORITHM fakerand_algorithms[] = {
    { PROV_NAMES_SEED_SRC, "provider=fakerand", fakerand_functions },
    { NULL, NULL, NULL }
};


static const OSSL_ALGORITHM *fakerand_query(OSSL_PROVIDER *prov,
                                          int operation_id,
                                          int *no_cache)
{
	FAKERAND_DEBUG("[fakerand] Query operation for id=%d\n", operation_id);

    *no_cache = 0;
    if (operation_id == OSSL_OP_RAND){
		return fakerand_algorithms;
    }    
    return NULL;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH fakerand_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))fakerand_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))fakerand_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fakerand_query },
	OSSL_DISPATCH_END
};

static void* fake_prov_ctx = NULL;

int ossl_fakerand_provider_init(const OSSL_CORE_HANDLE *handle,
                            const OSSL_DISPATCH *in,
                            const OSSL_DISPATCH **out,
                            void **provctx)
{
    FAKERAND_DEBUG("[fakerand] Provider initialized\n");

    *out = fakerand_dispatch_table;    

    fake_prov_ctx = (void*)0x01;
    *provctx = fake_prov_ctx;
    return 1;
}

void fakerand_enable_debug(){
	FAKERAND_DEBUG_ON=1;
}
