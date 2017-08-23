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
#include "param.h"
#include "poly/poly.h"
#include "rng/fastrandombytes.h"


/*
 * generate a set of private/public key pairs.
 * requires a buffer for 3 padded polynomials
 */

void keygen(
            int64_t     *f,         /* output - secret key */
            int64_t     *g,         /* output - secret key */
            int64_t     *g_inv,     /* output - secret key */
            int64_t     *h,         /* output - public key */
            int64_t     *buf,       /* input  - buffer     */
    const   PQ_PARAM_SET*param)     /* input  - parameters */
{
    int64_t i;
    int64_t *fntt = buf;
    int64_t *gntt = buf  + param->padded_N;
    int64_t *hntt = gntt + param->padded_N;
    int64_t *tmp  = hntt;


    memset(buf, 0, sizeof(int64_t)*param->padded_N*4);
    /*
     * generate flat trianry polynomials f and g
     * also compute g^-1 mod 2
     */
    pol_gen_flat(f, param->N, param->d);
    do{
        pol_gen_flat(g, param->N, param->d);
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

int rejection_sampling(
    const   int64_t     *sec,
    const   int64_t     *sig,
    const   PQ_PARAM_SET*param)
{
    uint64_t    t;
    uint64_t    norm;
    uint64_t    scala;
    double      rate = param->Ms;
    long        bignum = 0xfffffff;

    norm    = get_scala (sec, sec, param->N);
    /* reject if |af|_2 > B_s */
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
    rng_uint64(&t);
    if ((1+(t&bignum))/((double)bignum+1)< rate)
        return 1;
    else
        return 0;   /* reject */
}


/*
 * sign a message using rejection sampling method
 * returns the number of repetitions
 * buf memory requirement: 10 polynomials.
 */
int sign(
            int64_t     *sig,       /* output - signature  */
    const   int64_t     *msg,       /* input  - message    */
    const   int64_t     *f,         /* input  - secret key */
    const   int64_t     *g,         /* input  - secret key */
    const   int64_t     *g_inv,     /* input  - secret key */
    const   int64_t     *h,         /* input  - public key */
            int64_t     *buf,       /* input  - buffer     */
    const   PQ_PARAM_SET*param)     /* input  - parameters */
{

    int64_t i;
    int64_t *r      = buf;
    int64_t *u1     = r      +  param->padded_N;
    int64_t *v1     = u1     +  param->padded_N;
    int64_t *v      = v1     +  param->padded_N;
    int64_t *a      = v      +  param->padded_N;
    int64_t *b      = a      +  param->padded_N;
    int64_t *buffer = b      +  param->padded_N;
    int bit     = 0;    /* flipping bit for bimodal Gaussian */
    int counter = 0;    /* number of samples to get a signature */

    sample:
        if(counter>100)
        {
            printf ("signng failed\n");
            return -1;
        }
        memset(buffer, 0, sizeof(int64_t)*param->padded_N*3);

        /* sample from discrete Gaussian */
        DGS(r, param->N, param->stdev);

        /* flipping bit for bimodal Gaussian */
        bit = rand()%2;
        if (bit==0) bit = -1;

        counter = counter+1;

        /* u1 = 2*r + u0 */
        for (i=0;i<param->N;i++)
            u1[i] = r[i]*2+msg[i];

        /* v1 = u1 * h */
        pol_mul_coefficients( v1, h, u1, param, buffer);

        /* a = (v0-v1)/g */
        for (i=0;i<param->N;i++)
            a[i] = cmod(msg[i+param->N]-v1[i], 2);

        pol_mul_mod_2(a, a, g_inv, param, buffer);

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

        /* rejection sampling to make signature into a Gaussian */
        if (rejection_sampling(b, sig, param) == 0)
        {
            goto sample;
        }

    return counter;
}

/*
 * verifies a signature, returns 0 if valid
 * buf memory requirement: 5 polynomials.
 */
int verify(
    const   int64_t     *sig,       /* input  - signature  */
    const   int64_t     *msg,       /* input  - message    */
    const   int64_t     *h,         /* input  - public key */
            int64_t     *buf,       /* input  - buffer     */
    const   PQ_PARAM_SET*param)     /* input  - parameters */
{
    int64_t i;
    int64_t *u      = buf;
    int64_t *v      = u      +param->padded_N;
    int64_t *buffer = v      +param->padded_N;

    /* check if |s| is smaller than sigma*11 */
    if (max_norm(sig, param->N)>param->stdev*11)
    {
        printf("max norm failed\n");
        return -1;
    }

    /* reconstruct u = 2s + u_p */
    for (i=0;i<param->N;i++)
        u[i] = sig[i]*2 + msg[i];

    /* v = u * h */
    pol_mul_coefficients(v, u, h, param, buffer);


    /* check if v \equiv v_p mod 2 */
    for (i=0;i<param->N;i++)
    {
        if ((v[i]-msg[i+param->N]) % 2 ==1)
        {
            printf("congruent condition failed\nv:\n");
            return -1;
        }
    }
    return 0;
}

