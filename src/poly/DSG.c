/*
 * discrete_gaussian_sampler.c
 *
 *  Created on: Jun 5, 2017
 *      Author: zhenfei
 */

#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include "../rng/fastrandombytes.h"

/*  todo: replace this sampler with a better one.
 *  Preferably faster, constant time, more precisions*/

void DGS (      int64_t   *v,
          const uint16_t  dim,
          const uint8_t   stdev)
{
    uint16_t d2 = dim/2;
    uint16_t i;
    uint64_t t;

    static double const Pi=3.141592653589793238462643383279502884L;
    static long const bignum = 0xfffffff;
    double r1, r2, theta, rr;

    for (i=0;i<d2;i++)
    {
        rng_uint64(&t);
        r1 = (1+(t&bignum))/((double)bignum+1);
        r2 = (1+((t>>32)&bignum))/((double)bignum+1);
        theta = 2*Pi*r1;
        rr = sqrt(-2.0*log(r2))*stdev;
        v[2*i] = (int64_t) floor(rr*sin(theta) + 0.5);
        v[2*i+1] = (int64_t) floor(rr*cos(theta) + 0.5);
    }

    if (dim%2 == 1)
    {
        rng_uint64(&t);
        r1 = (1+(t&bignum))/((double)bignum+1);
        r2 = (1+((t>>32)&bignum))/((double)bignum+1);
        theta = 2*Pi*r1;
        rr = sqrt(-2.0*log(r2))*stdev;
        v[dim-1] = (int64_t) floor(rr*sin(theta) + 0.5);
    }
}
