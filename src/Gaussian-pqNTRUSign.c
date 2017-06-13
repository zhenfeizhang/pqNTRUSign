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

void keygen(
    int64_t     *f,
    int64_t     *g,
    int64_t     *g_inv,
    int64_t     *h,
    int64_t     *buf,
    PQ_PARAM_SET *param)
{
    int64_t i;
    int64_t *fntt = buf;
    int64_t *gntt = buf  + param->N;
    int64_t *hntt = gntt + param->N;
    int64_t *tmp  = hntt;

    memset(f, 0, sizeof(int64_t)*param->N);
    memset(g, 0, sizeof(int64_t)*param->N);

    /*
     * generate flat trianry polynomials f and g
     * also compute g^-1 mod 2
     *
     */
    pol_gen_flat(f, param->N, param->d);
    do{
        pol_gen_flat(g, param->N, param->d);
    }while (pol_inv_mod2(g_inv, g, param->N) == -1);


    /* set f = pf */
    for (i=0;i<param->N;i++)
        tmp[i] = 2*f[i];

    /* convert f and g into NTT form */
    NTT(tmp, fntt);
    NTT(g, gntt);


    for (i=0;i<param->N;i++)
    {
        /* compute f^-1 mod q */
        fntt[i] = InvMod(fntt[i],param->q);
        /* compute h = gf^-1 mod q */
        hntt[i] = gntt[i]*fntt[i] % param->q;
    }

    Inv_NTT(h, hntt);

}


/*
 * rejection sampling on a bimodal sample
 * "a" with a = r \pm b for r sampled from Gaussian
 * reject into a Gaussian
 */

int rejection_sampling(
    const   int64_t     *a,
    const   int64_t     *b,
    const   PQ_PARAM_SET*param)
{
    uint64_t    t;
    uint64_t    norm;
    uint64_t    scala;
    double      rate = param->Ms;
    long        bignum = 0xfffffff;

    norm    = get_scala (a, a, param->N);
    scala   = abs(get_scala (a, b, param->N));

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
        return 0;
}


int sign(
            int64_t     *sig,
    const   int64_t     *msg,
    const   int64_t     *f,
    const   int64_t     *g,
    const   int64_t     *g_inv,
    const   int64_t     *h,
            int64_t     *buf,
    const   PQ_PARAM_SET*param)
{

    int64_t i;
    int64_t *r      = buf;
    int64_t *u1     = r      +param->N;
    int64_t *v1     = u1     +param->N;
    int64_t *v      = v1     +param->N;
    int64_t *a      = v      +param->N;
    int64_t *b      = a      +param->N;
    int64_t *buffer = b      +param->N;
    int bit     = 0;    /* flipping bit for bimodal Gaussian */
    int counter = 0;    /* number of samples to get a signature */
    sample:
        DGS(r, param->N, param->stdev);
        bit = rand()%2;
        if (bit==0) bit = -1;
        counter = counter+1;

        /* u1 = 2*r + u0 */
        for (i=0;i<param->N;i++)
            u1[i] = r[i]*2+msg[i];

        /* v1 = u1 * h */
        pol_mul_coefficients( v1, h, u1, param->N, 512, param->q, buffer);

        /* a = (v0-v1)/g */
        for (i=0;i<param->N;i++)
            a[i] = cmod(msg[i+param->N]-v1[i], 2);

        pol_mul_coefficients(a, a, g_inv, param->N, 512, 2, buffer);

        /* v= v1+ag */
        pol_mul_coefficients(v, a, g, param->N, 512, param->q, buffer);

        /* rejection sampling on t side, step 1 */
        if (max_norm(v, param->N)> param->B_t)
            goto sample;

        for (i=0;i<param->N;i++)
            v[i] = v1[i] + bit * v[i];
        /* rejection sampling on t side, step 2 */
        if (max_norm(v, param->N)> param->norm_bound_t)
            goto sample;

        /* b = af; sig = af +r   */
        pol_mul_coefficients(b, a, f, param->N, 512, param->q, buffer);
        for (i=0;i<param->N;i++)
            sig[i] = r[i] + bit * b[i];

        /* rejection sampling to make signature into a Gaussian */
        if (rejection_sampling(b, sig, param) == 0)
            goto sample;

    return counter;
}


int verify(
    const   int64_t     *sig,
    const   int64_t     *msg,
    const   int64_t     *h,
            int64_t     *buf,
    const   PQ_PARAM_SET*param)
{
    int64_t i;
    int64_t *u      = buf;
    int64_t *v      = u      +param->N;
    int64_t *buffer = v      +param->N;

    /* check if |s| is smaller than sigma*11 */
    if (max_norm(sig, param->N)>param->stdev*11)
        return -1;

    /* reconstruct u = 2s + u_p */
    for (i=0;i<param->N;i++)
        u[i] = sig[i]*2 + msg[i];

    /* v = u * h */
    pol_mul_coefficients(v, u, h, param->N, 512, param->q, buffer);

    /* check if v \equiv v_p mod 2 */
    for (i=0;i<param->N;i++)
    {
        if ((v[i]-msg[i+param->N]) % 2 ==1)
            return -1;
    }
    return 0;
}

/*
 * identical to a norm signing procedure
 * except the output signature is v not u
 */

int batch_sign(
            int64_t     *sig,
    const   int64_t     *msg,
    const   int64_t     *f,
    const   int64_t     *g,
    const   int64_t     *g_inv,
    const   int64_t     *h,
            int64_t     *buf,
    const   PQ_PARAM_SET*param)
{

    int64_t i;
    int64_t *r      = buf;
    int64_t *u1     = r      +param->N;
    int64_t *v1     = u1     +param->N;
    int64_t *v      = v1     +param->N;
    int64_t *a      = v      +param->N;
    int64_t *b      = a      +param->N;
    int64_t *buffer = b      +param->N;
    int bit     = 0;
    int counter = 0;

    sample:
        DGS(r, param->N, param->stdev);
        bit = rand()%2;
        if (bit==0) bit = -1;
        counter = counter+1;

        /* u1 = 2*r + u0 */
        for (i=0;i<param->N;i++)
            u1[i] = r[i]*2+msg[i];

        /* v1 = u1 * h */
        pol_mul_coefficients( v1, h, u1, param->N, 512, param->q, buffer);

        /* a = (v0-v1)/g */
        for (i=0;i<param->N;i++)
            a[i] = cmod(msg[i+param->N]-v1[i], 2);

        pol_mul_coefficients(a, a, g_inv, param->N, 512, 2, buffer);

        /* v= v1+ag */
        pol_mul_coefficients(v, a, g, param->N, 512, param->q, buffer);
        /* rejection sampling on t side, step 1 */
        if (max_norm(v, param->N)> param->B_t)
            goto sample;

        for (i=0;i<param->N;i++)
            v[i] = v1[i] + bit * v[i];
        /* rejection sampling on t side, step 2 */
        if (max_norm(v, param->N)> param->norm_bound_t)
            goto sample;

        /* b = af; sig = af +r   */
        pol_mul_coefficients(b, a, f, param->N, 512, param->q, buffer);
        for (i=0;i<param->N;i++)
            sig[i] = r[i] + bit * b[i];

        /* rejection sampling to make signature into a Gaussian */
        if (rejection_sampling(b, sig, param) == 0)
            goto sample;

    for (i=0;i<param->N;i++)
        sig[i] = v[i];
    return counter;
}

int batch_verify(
    const   int64_t     *sig,
    const   int64_t     *msg,
    const   int64_t     *h,
            int64_t     *buf,
    const   PQ_PARAM_SET*param)
{
    int64_t i;
    int64_t *u      = buf;
    int64_t *v      = u      +param->N;
    int64_t *hinv   = v      +param->N;
    int64_t *buffer = hinv   +param->N;

    NTT(h, buffer);
    for (i=0;i<param->N;i++)
        buffer[i] = InvMod(buffer[i], param->q);
    Inv_NTT(hinv, buffer);
    for (i=0;i<param->N;i++)
    {
        if ((sig[i]-msg[i+param->N]) % 2 ==1)
        {
            printf("t side error\n");
            return -1;
        }
    }
    pol_mul_coefficients(u, sig, hinv, param->N, 512, param->q, buffer);


//    if (max_norm(u, param->N)>param->stdev*11)
//        return -1;

    for (i=0;i<param->N;i++)
    {
        if ((u[i]-msg[i]) % 2 ==1)
        {
            printf("s side error\n");
            return -1;
        }
    }

    return 0;
}

