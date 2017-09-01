/*
 * api.h
 *
 *  Created on: Sep 1, 2017
 *      Author: zhenfei
 */

#ifndef API_H_
#define API_H_


#define TEST_Gaussian_512


#ifdef TEST_Gaussian_512
    #define TEST_PARAM_SET  Gaussian_512_107
    #define CRYPTO_SECRETKEYBYTES 515
    #define CRYPTO_PUBLICKEYBYTES 1030
    #define CRYPTO_BYTES 1030
    #define CRYPTO_RANDOMBYTES 32
#endif

#ifdef TEST_uniform_512
    #define TEST_PARAM_SET uniform_512_107
    #define CRYPTO_SECRETKEYBYTES 515
    #define CRYPTO_PUBLICKEYBYTES 1030
    #define CRYPTO_BYTES 1030
    #define CRYPTO_RANDOMBYTES 32
#endif

int crypto_sign_keypair(
    unsigned char       *pk,
    unsigned char       *sk);

int crypto_sign(
    unsigned char       *sm,
    unsigned long long  *smlen,
    const unsigned char *m,
    unsigned long long  mlen,
    const unsigned char *sk);

int crypto_sign_open(
    const unsigned char *m,
    unsigned long long  *mlen,
    const unsigned char *sm,
    unsigned long long  smlen,
    const unsigned char *pk);

int crypto_sign_keypair_KAT(
    unsigned char       *pk,
    unsigned char       *sk,
    const unsigned char *randomness);

int crypto_sign_KAT(
    unsigned char       *sm,
    unsigned long long  *smlen,
    const unsigned char *m,
    unsigned long long  mlen,
    const unsigned char *sk,
    const unsigned char *randomness);

#endif /* API_H_ */
