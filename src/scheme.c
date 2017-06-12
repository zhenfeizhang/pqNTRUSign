/*
 * scheme.c
 *
 *  Created on: Jun 6, 2017
 *      Author: zhenfei
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include "param.h"
#include "poly/poly.h"

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
    int64_t *gntt = buf + param->N;
    int64_t *hntt = gntt + param->N;


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
        f[i] = 2*f[i];

    /* convert f and g into NTT form */
    NTT(f, fntt);
    NTT(g, gntt);


    for (i=0;i<param->N;i++)
    {
        /* compute f^-1 mod q */
        fntt[i] = InvMod(fntt[i],param->q);
        /* compute h = gf^-1 mod q */
        hntt[i] = gntt[i]*fntt[i] % param->q;
    }


    for (i=0;i<param->N;i++)
        f[i] = f[i]/2;

    Inv_NTT(h, hntt);

}




void sign(
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


    DGS(r, param->N, param->stdev);

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


    for (i=0;i<param->N;i++)
        v[i] += v1[i];

    pol_mul_coefficients(b, a, f, param->N, 512, param->q, buffer);


    for (i=0;i<param->N;i++)
        sig[i] = b[i]+ r[i];


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

    if (max_norm(sig, param->N)>param->stdev*11)
        return -1;

    for (i=0;i<param->N;i++)
        u[i] = sig[i]*2 + msg[i];

    pol_mul_coefficients(v, u, h, param->N, 512, param->q, buffer);

    for (i=0;i<param->N;i++)
    {
        if ((v[i]-msg[i+param->N]) % 2 ==1)
            return -1;
    }
    return 0;

}
