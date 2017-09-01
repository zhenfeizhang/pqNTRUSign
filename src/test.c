/*
 *  Copyright 2017 Zhenfei Zhang @ onboard security
 *
 *  This file is part of pqNTRUSign signature scheme with bimodal
 *  Gaussian sampler (Gaussian-pqNTRUSign).
 *
 *  This software is released under GPL:
 *  you can redistribute it and/or modify it under the terms of the
 *  GNU General Public License as published by the Free Software
 *  Foundation, either version 2 of the License, or (at your option)
 *  any later version.
 *
 *  You should have received a copy of the GNU General Public License.
 *  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <time.h>

#include "param.h"
#include "poly/poly.h"
#include "pqNTRUSign.h"
#include "rng/fastrandombytes.h"
#include "rng/crypto_hash_sha512.h"
#include "api.h"

/*
 * uncomment VERBOSE to get extra information for testing
 * #define VERBOSE
 */


unsigned char   rndness[32] = "source of randomness";
unsigned char   msg[32]     = "nist submission";

int get_len(unsigned char *c)
{
    int len = 0;
    while(c[len]!='\0')
        len++;
    return len;
}


uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

int test(PQ_PARAM_SET *param)
{

    int64_t   *f, *g, *g_inv, *h, *buf, *sig, *mem;


    uint64_t startc, endc, signtime = 0, verifytime = 0;
    clock_t start, end;
    double cpu_time_used1;
    double cpu_time_used2;
    int i =0;
    int counter = 0;

    unsigned char   *msg;
    unsigned char   *seed   = (unsigned char*) "nist submission";
    size_t          msg_len = 64;

    /* memory to store keys/msgs/ctx */
    mem = malloc (sizeof(int64_t)*param->padded_N * 7);
    /* buffer */
    buf = malloc (sizeof(int64_t)*param->padded_N * 11);
    /* message to be signed */
    msg = malloc (sizeof(unsigned char)*msg_len);


    if (!mem || !buf || !msg)
    {
        printf("malloc error!\n");
        return -1;
    }

    crypto_hash_sha512(msg, seed, msg_len);

    memset(mem, 0, sizeof(int64_t)*param->padded_N * 7);
    memset(buf, 0, sizeof(int64_t)*param->padded_N * 11);


    f       = mem;
    g       = f     + param->padded_N;
    g_inv   = g     + param->padded_N;
    h       = g_inv + param->padded_N;
    sig     = h     + param->padded_N*2;


    /* generate a set of keys */
    printf("=====================================\n");
    printf("=====================================\n");
    printf("=====================================\n");
    printf("testing parameter set %s \n", param->name);


    printf("begin a single signing procedure\n");




    memset(buf, 0, sizeof(int64_t)*param->padded_N * 4);
    keygen(f,g,g_inv,h,buf,param);

#ifdef VERBOSE
    printf("start key generation\n");
    printf("f:\n");
    for (i=0;i<param->padded_N;i++)
        printf("%lld,",(long long)f[i]);
    printf("\ng:\n");
    for (i=0;i<param->padded_N;i++)
        printf("%lld,", (long long)g[i]);
    printf("\ng_inv:\n");
    for (i=0;i<param->padded_N;i++)
        printf("%lld,",(long long)g_inv[i]);
    printf("\nh:\n");
    for (i=0;i<param->padded_N;i++)
        printf("%lld,",(long long)h[i]);
    printf("\n");
    printf("finished key generation\n");
    printf("=====================================\n");
#endif


    /* generate a message vector to sign */
//    pol_gen_flat(msg, param->N, param->d);
//    pol_gen_flat(msg+param->N, param->N, param->d);

    /* sign the msg */
    printf("now signing a message\n");

#ifdef VERBOSE
    for (i=0;i<param->N;i++)
        printf("%lld,",(long long)msg[i]);
    printf("\n");
    for (;i<param->padded_N*2;i++)
        printf("%lld,",(long long)msg[i]);
    printf("\n");
#endif

    memset(buf, 0, sizeof(int64_t)*param->N * 11);
    sign(sig, msg, msg_len,f,g,g_inv,h,buf,param);
#ifdef VERBOSE
    printf("the signature is:\n");
    for (i=0;i<param->N;i++)
        printf("%lld,",(long long)sig[i]);
    printf("\n");
#endif
    printf("=====================================\n");

    printf("now verifying the signature: 0 for valid, -1 for invalid:   ");
    /* verifying the signature */
    memset(buf, 0, sizeof(int64_t)*param->N * 7);
    printf("%d \n", verify(sig, msg, msg_len, h,buf,param));
    printf("=====================================\n");

    printf("benchmark with signing a set of messages\n");

    for (i=0;i<100;i++)
    {
        /* generate a new message to sign */
        crypto_hash_sha512(msg, msg, msg_len);

        /* sign the msg */
        memset(buf, 0, sizeof(int64_t)*param->N * 10);
        start = clock();
        startc = rdtsc();
        counter += sign(sig, msg,msg_len, f,g,g_inv,h,buf,param);
        endc = rdtsc();
        end = clock();
        cpu_time_used1 += (end-start);
        signtime += (endc-startc);

        /* verifying the signature */
        memset(buf, 0, sizeof(int64_t)*param->N * 7);
        startc = rdtsc();
        start = clock();

        if(verify(sig, msg,msg_len, h,buf,param)!=0)
            printf("%d verification error\n", i);
        end = clock();
        cpu_time_used2 += (end-start);
        endc = rdtsc();
        verifytime += (endc-startc);
    }
    printf("it takes %d samples to generate %d number of signatures!\n", counter, i);
    printf("average signing time: %f clock cycles or %f seconds!\n", (double)signtime/i, cpu_time_used1/i/CLOCKS_PER_SEC);
    printf("average verification time:  %f clock cycles or %f seconds!\n", (double)verifytime/i, cpu_time_used2/i/CLOCKS_PER_SEC);

    free(mem);
    free(buf);
	return 0;
}

int test_basic(void)
{
    uint16_t i;
    PQ_PARAM_SET_ID plist[] =
    {
        uniform_512_107,
        uniform_761_107,
        Gaussian_512_107,
        Gaussian_761_107,
    };
    size_t numParams = sizeof(plist)/sizeof(PQ_PARAM_SET_ID);

    for(i = 0; i<numParams; i++)
    {
      test(pq_get_param_set_by_id(plist[i]));
    }

    rng_cleanup();
    exit(EXIT_SUCCESS);
}

int test_nist_api()
{


    unsigned char       *sig;
    unsigned char       *pk, *sk;
    unsigned long long  siglen;
    unsigned long long  mlen;

    pk  = malloc(sizeof(unsigned char)* 5000);
    sk  = malloc(sizeof(unsigned char)* 10000);
    sig = malloc(sizeof(unsigned char)* 5000);


    mlen = get_len(msg);


    /* generate a set of keys */
    printf("=====================================\n");
    printf("=====================================\n");
    printf("=====================================\n");

    int i=0;
    crypto_sign_keypair(pk, sk);

    printf("key generated, public key:\n");

    for(i=0;i<32;i++)
        printf("%d,",sk[i]);
    printf("\n");

    printf("begin a single signing procedure\n");

    crypto_sign(sig, &siglen, msg, mlen, sk);

    printf("signature of length %d:", (int)siglen);
    for(i=0;i<32;i++)
        printf("%d,",sig[i]);
    printf("\n");
    printf("check correctness\n");
    crypto_sign_open( msg, &mlen, sig, siglen, pk);

    return 0;

}

int test_nist_api_KAT()
{

    int i;
    unsigned char       *sig;
    unsigned char       *pk, *sk;
    unsigned long long  siglen;
    unsigned long long  mlen;

    pk  = malloc(sizeof(unsigned char)* 5000);
    sk  = malloc(sizeof(unsigned char)* 10000);
    sig = malloc(sizeof(unsigned char)* 5000);



    mlen = get_len(msg);





    /* generate a set of keys */
    printf("=====================================\n");
    printf("=====================================\n");
    printf("=====================================\n");

    crypto_sign_keypair_KAT(pk, sk, rndness);


    printf("key generated, public key:\n");

    for(i=0;i<32;i++)
    printf("%d,",pk[i]);
    printf("\n");
    printf("begin a single signing procedure\n");

    crypto_sign_KAT(sig, &siglen, msg, mlen, sk, rndness);


    printf("signature of length %d:", (int)siglen);
    for(i=0;i<32;i++)
        printf("%d,",sig[i]);
    printf("\n");

    printf("check correctness\n");
    crypto_sign_open(msg, &mlen, sig, siglen, pk);

    return 0;

}



int main(void)
{
//    test_basic();
    test_nist_api();
    test_nist_api_KAT();

    printf("Hello onboard security\n");
}
