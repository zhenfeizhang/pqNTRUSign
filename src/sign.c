/*
 * sign.c
 *
 *  Created on: Sep 1, 2017
 *      Author: zhenfei
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "pqNTRUSign.h"
#include "param.h"
#include "api.h"
#include "rng/crypto_hash_sha512.h"
#include "packing.h"

int crypto_sign_keypair(
    unsigned char       *pk,
    unsigned char       *sk)
{
    PQ_PARAM_SET    *param;
    param           = pq_get_param_set_by_id(TEST_PARAM_SET);

    int64_t         *mem, *buf;
    int64_t         *f, *g, *g_inv, *h;

    buf = malloc(sizeof(int64_t)*param->padded_N*4);
    mem = malloc(sizeof(int64_t)*param->padded_N*4);

    if (!buf ||!mem)
    {
        printf("malloc error!\n");
        return -1;
    }

    f       = mem;
    g       = f     + param->padded_N;
    g_inv   = g     + param->padded_N;
    h       = g_inv + param->padded_N;

    keygen(f,g,g_inv,h,buf,param);

    pack_public_key(pk, param, h );

    pack_secret_key(sk, param, f, g, g_inv, h);

    memset(buf, 0, sizeof(int64_t)*param->padded_N*4);
    memset(mem, 0, sizeof(int64_t)*param->padded_N*4);
    free(buf);
    free(mem);
    return 0;
}

int crypto_sign(
    unsigned char       *sm,
    unsigned long long  *smlen,
    const unsigned char *m,
    unsigned long long  mlen,
    const unsigned char *sk)
{

    PQ_PARAM_SET    *param;
    param           = pq_get_param_set_by_id(TEST_PARAM_SET);

    int64_t         *mem, *buf;
    int64_t         *f, *g, *g_inv, *h, *sig;

    buf = malloc(sizeof(int64_t)*param->padded_N*11);
    mem = malloc(sizeof(int64_t)*param->padded_N*5);

    if (!buf ||!mem)
    {
        printf("malloc error!\n");
        return -1;
    }
    memset(buf,0, sizeof(int64_t)*param->padded_N*11);
    memset(mem,0, sizeof(int64_t)*param->padded_N*5);

    f       = mem;
    g       = f     + param->padded_N;
    g_inv   = g     + param->padded_N;
    h       = g_inv + param->padded_N;
    sig     = h     + param->padded_N;
    unpack_secret_key(sk, param, f, g, g_inv, h);


    sign(sig, m,mlen, f,g,g_inv,h,buf,param);

    pack_public_key(sm, param, sig);
    *smlen = param->N*4+1;

    memset(buf,0, sizeof(int64_t)*param->padded_N*11);
    memset(mem,0, sizeof(int64_t)*param->padded_N*5);
    free(mem);
    free(buf);

    return 0;
}

int crypto_sign_open(
    const unsigned char *m,
    unsigned long long  *mlen,
    const unsigned char *sm,
    unsigned long long  smlen,
    const unsigned char *pk)
{

    PQ_PARAM_SET    *param;
    param           = pq_get_param_set_by_id(TEST_PARAM_SET);

    int64_t         *mem, *buf;
    int64_t         *f, *g, *g_inv, *h, *sig;

    buf = malloc(sizeof(int64_t)*param->padded_N*7);
    mem = malloc(sizeof(int64_t)*param->padded_N*5);

    if (!buf ||!mem)
    {
        printf("malloc error!\n");
        return -1;
    }
    memset(buf,0, sizeof(int64_t)*param->padded_N*7);
    memset(mem,0, sizeof(int64_t)*param->padded_N*5);

    f       = mem;
    g       = f     + param->padded_N;
    g_inv   = g     + param->padded_N;
    h       = g_inv + param->padded_N;
    sig     = h     + param->padded_N;


    unpack_public_key(pk, param,  h);

    unpack_public_key(sm, param,  sig);

    if(verify(sig, m, *mlen, h,buf,param)!=0)
    {
        printf("verification error\n");

        memset(buf,0, sizeof(int64_t)*param->padded_N*7);
        memset(mem,0, sizeof(int64_t)*param->padded_N*5);

        free(buf);
        free(mem);
        return -1;
    }

    else
    {
        printf("signature verified\n");

        memset(buf,0, sizeof(int64_t)*param->padded_N*7);
        memset(mem,0, sizeof(int64_t)*param->padded_N*5);

        free(buf);
        free(mem);

        return 0;
    }
}

int crypto_sign_keypair_KAT(
    unsigned char       *pk,
    unsigned char       *sk,
    const unsigned char *randomness)
{

    PQ_PARAM_SET    *param;
    param           = pq_get_param_set_by_id(TEST_PARAM_SET);

    int64_t         *mem, *buf;
    int64_t         *f, *g, *g_inv, *h;
    unsigned char   *seed;
    unsigned char   salt[32] = "keygen_KAT|keygen_KAT|keygen_KAT";

    buf     = malloc(sizeof(int64_t)*param->padded_N*4);
    mem     = malloc(sizeof(int64_t)*param->padded_N*4);
    seed    = malloc(LENGTH_OF_HASH);
    if (!buf ||!mem || !seed)
    {
        printf("malloc error!\n");
        return -1;
    }

    memset(buf,0, sizeof(int64_t)*param->padded_N*4);
    memset(mem,0, sizeof(int64_t)*param->padded_N*4);

    f       = mem;
    g       = f     + param->padded_N;
    g_inv   = g     + param->padded_N;
    h       = g_inv + param->padded_N;

    memcpy(seed,    randomness, 32);
    memcpy(seed+32, salt,       32);
    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);

    keygen_KAT(f,g,g_inv,h,buf,param, seed);

    pack_public_key(pk, param, h );

    pack_secret_key(sk, param, f, g, g_inv, h);


    memset(seed, 0, LENGTH_OF_HASH);
    memset(buf, 0, sizeof(int64_t)*param->padded_N*4);
    memset(mem, 0, sizeof(int64_t)*param->padded_N*4);

    free(buf);
    free(mem);
    free(seed);
    return 0;
}

int crypto_sign_KAT(
    unsigned char       *sm,
    unsigned long long  *smlen,
    const unsigned char *m,
    unsigned long long  mlen,
    const unsigned char *sk,
    const unsigned char *randomness)
{


    PQ_PARAM_SET    *param;
    param           = pq_get_param_set_by_id(TEST_PARAM_SET);

    unsigned char   *seed;
    unsigned char   salt[32] = "sign_KAT|sign_KAT|sign_KAT";
    int64_t         *mem, *buf;
    int64_t         *f, *g, *g_inv, *h, *sig;

    buf     = malloc(sizeof(int64_t)*param->padded_N*11);
    mem     = malloc(sizeof(int64_t)*param->padded_N*5);
    seed    = malloc(LENGTH_OF_HASH);
    if (!buf ||!mem || !seed)
    {
      printf("malloc error!\n");
      return -1;
    }
    memset(buf,0, sizeof(int64_t)*param->padded_N*11);
    memset(mem,0, sizeof(int64_t)*param->padded_N*5);

    f       = mem;
    g       = f     + param->padded_N;
    g_inv   = g     + param->padded_N;
    h       = g_inv + param->padded_N;
    sig     = h     + param->padded_N;
    unpack_secret_key(sk, param, f, g, g_inv, h);


    memcpy(seed,    randomness, 32);
    memcpy(seed+32, salt,       32);


    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    sign_KAT(sig, m,mlen, f,g,g_inv,h,buf,param, seed);


    pack_public_key(sm, param, sig);

    *smlen = param->N*4+1;
    memset(buf,0, sizeof(int64_t)*param->padded_N*11);
    memset(mem,0, sizeof(int64_t)*param->padded_N*5);
    memset(seed,0, LENGTH_OF_HASH);
    free(mem);
    free(buf);
    free(seed);

    return 0;
}
