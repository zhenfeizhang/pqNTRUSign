/*
 * KAT.c
 *
 *  Created on: Sep 1, 2017
 *      Author: zhenfei
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include "pqNTRUSign.h"
#include "param.h"
#include "poly/poly.h"
#include "rng/fastrandombytes.h"
#include "rng/crypto_hash_sha512.h"



/* generate a trinary polynomial with fixed number of +/- 1s */
void
pol_gen_flat_KAT(
          int64_t  *ai,
    const uint16_t  N,
    const uint16_t  d,
    unsigned char   *seed)
{
    uint64_t r, *tmp;
    int16_t count,i,j, coeff[6];

    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    tmp = (uint64_t *)seed;

    memset(ai, 0, sizeof(int64_t)*N);
    count = 0;
    j = 0;
    while(count < d+1)
    {
        r  = tmp[j++];
        if(j==8)
        {
            crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
            j = 0;
        }

        for (i =0;i<6;i++)
        {
            coeff[i] = r & 0x3FF;
            r = (r - coeff[i])>>10;
            if (coeff[i]<N)
            {
                if (ai[coeff[i]]==0)
                {
                    ai[coeff[i]]=1;
                    count++;
                }
            }
        }
    }
    count = 0;
    while(count < d)
    {
        r  = tmp[j++];
        if(j==8)
        {
            crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
            j = 0;
        }
        for (i =0;i<6;i++)
        {
            coeff[i] = r & 0x3FF;
            r = (r - coeff[i])>>10;
            if (coeff[i]<N)
            {
                if (ai[coeff[i]]==0)
                {
                    ai[coeff[i]]=-1;
                    count++;
                }
            }
        }
    }
    return;
}


/*
 * generate a set of private/public key pairs.
 * requires a buffer for 4 padded polynomials
 */

void keygen_KAT(
            int64_t     *f,         /* output - secret key */
            int64_t     *g,         /* output - secret key */
            int64_t     *g_inv,     /* output - secret key */
            int64_t     *h,         /* output - public key */
            int64_t     *buf,       /* input  - buffer     */
    const   PQ_PARAM_SET*param,     /* input  - parameters */
    unsigned char       *seed)
{
    int64_t i;
    int64_t *fntt = buf;
    int64_t *gntt = buf  + param->padded_N;
    int64_t *hntt = gntt + param->padded_N;
    int64_t *tmp  = hntt + param->padded_N;  ;


    memset(buf, 0, sizeof(int64_t)*param->padded_N*4);
    /*
     * generate flat trianry polynomials f and g
     * also compute g^-1 mod 2
     */
    pol_gen_flat_KAT(f, param->N, param->d,seed);
    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);

    do{
        pol_gen_flat_KAT(g, param->N, param->d, seed);
        crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    }while (pol_inv_mod2(g_inv, g, param->N) == -1);

    /* set f = pf */
    for (i=0;i<param->N;i++)
        tmp[i] = 2*f[i];

    /* convert f and g into NTT form */
    NTT(param,  tmp,    fntt);
    NTT(param,  g,      gntt);

    for (i=0;i<param->N;i++)
    {
        /* compute f^-1 mod q */
        fntt[i] = InvMod(fntt[i],param->q);
        /* compute h = gf^-1 mod q */
        hntt[i] = gntt[i]*fntt[i] % param->q;
    }

    Inv_NTT(param, h, hntt);
    return;
}

/*
 * rejection sampling on a bimodal sample
 * "sig" with sig = r \pm sec for r sampled from Gaussian
 * reject into a Gaussian
 */

int rejection_sampling_with_seed(
    const   int64_t     *sec,
    const   int64_t     *sig,
    const   PQ_PARAM_SET*param,
    unsigned char       *seed)
{
    uint64_t    t;
    uint64_t    norm;
    uint64_t    scala;
    double      rate    = param->Ms;
    long        bignum  = 0xfffffff;
    uint64_t    *ptr    = (uint64_t*) seed;




    /* reject if |af|_2 > B_s */
    norm    = get_scala (sec, sec, param->N);
    if (norm> param->B_s*param->B_s)
        return 0;

    scala   = abs(get_scala (sec, sig, param->N));

    /*
     * rate = 1/ M / exp(-norm/sigma^2/2) / cosh(scala/sigma^2)
     */
    rate *= exp(-(double)norm/(double)param->stdev/(double)param->stdev/2);
    rate *= cosh(scala/(double)param->stdev/(double)param->stdev);
    rate = 1/rate;

    /*
     * sample a random float between 0 and 1
     * accept if this float is small than rate
     */

    crypto_hash_sha512(seed,seed, LENGTH_OF_HASH);
    t = ptr[0];
    if ((1+(t&bignum))/((double)bignum+1)< rate)
        return 1;
    else
        return 0;   /* reject */
}



/*
 * sign a message using rejection sampling method
 * returns the number of repetitions
 * buf memory requirement: 11 polynomials.
 */
int sign_KAT(
            int64_t     *sig,       /* output - signature  */
    const unsigned char *msg,       /* input  - message    */
    const   size_t      msg_len,    /* input  - length of msg */
    const   int64_t     *f,         /* input  - secret key */
    const   int64_t     *g,         /* input  - secret key */
    const   int64_t     *g_inv,     /* input  - secret key */
    const   int64_t     *h,         /* input  - public key */
            int64_t     *buf,       /* input  - buffer     */
    const   PQ_PARAM_SET*param,     /* input  - parameters */
    unsigned char       *seed)
{

    int64_t i;
    int64_t *r      = buf;
    int64_t *u1     = r      +  param->padded_N;
    int64_t *v1     = u1     +  param->padded_N;
    int64_t *v      = v1     +  param->padded_N;
    int64_t *a      = v      +  param->padded_N;
    int64_t *b      = a      +  param->padded_N;
    int64_t *sptp   = b      +  param->padded_N;    /* 2 polynomials */
    int64_t *buffer = sptp   +  param->padded_N*2;  /* 3 polynomials */
    int     bit     = 0;    /* flip a bit for bimodal Gaussian */
    int     counter = 0;    /* number of samples to get a signature */

    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    challenge (sptp, h, msg, msg_len, param);

    sample:
        if(counter>100)
        {
            printf ("signing failed\n");
            return -1;
        }

        counter = counter+1;
        memset(buffer, 0, sizeof(int64_t)*param->padded_N*3);

        /* sample r from discrete Gaussian and b from binary*/
        if (param->id==Gaussian_512_107 || param->id==Gaussian_761_107)
        {
            DDGS(r, param->N, param->stdev,seed, LENGTH_OF_HASH);
            /* flipping bit for bimodal Gaussian */
            crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
            bit = seed[0]&1;
            if (bit==0)
                bit = -1;
        }
        /* or sample r from uniform and set b = 1*/
        else if (param->id== uniform_512_107 || param->id==uniform_761_107)
        {
            pol_unidrnd_with_seed(r,param->N,param->q/param->p, seed, LENGTH_OF_HASH);
            bit = 1;
        }


        /* u1 = p*r + u0 */
        for (i=0;i<param->N;i++)
            u1[i] = r[i]*param->p+sptp[i];

        /* v1 = u1 * h */
        pol_mul_coefficients( v1, h, u1, param, buffer);

        /* a = (v0-v1)/g  mod p*/
        for (i=0;i<param->N;i++)
            a[i] = cmod(sptp[i+param->N]-v1[i], param->p);

        pol_mul_mod_p(a, a, g_inv, param, buffer);

        /* v= v1+ag */
        pol_mul_coefficients(v, a, g, param, buffer);

        /* rejection sampling on t side, step 1 */
        if (max_norm(v, param->N)> param->B_t)
        {
            goto sample;
        }

        for (i=0;i<param->N;i++)
            v[i] = v1[i] + bit * v[i];
        /* rejection sampling on t side, step 2 */
        if (max_norm(v, param->N)> param->norm_bound_t)
        {
            goto sample;
        }

        /* b = af; sig = af +r   */
        pol_mul_coefficients(b, a, f, param, buffer);
        for (i=0;i<param->N;i++)
            sig[i] = r[i] + bit * b[i];

        /* now perform rejection sampling on Gaussian*/
        if (param->id==Gaussian_512_107 || param->id==Gaussian_761_107)
        {
            /* rejection sampling to make signature into a Gaussian */
            if (rejection_sampling_with_seed(b, sig, param, seed) == 0)
            {
                goto sample;
            }
        }
        else if (param->id== uniform_512_107 || param->id==uniform_761_107)
        {
            /* rejection sampling to make signature into a uniform */
            if (max_norm(sig, param->N)>param->norm_bound_s)
            {
                goto sample;
            }
        }

    return counter;
}


