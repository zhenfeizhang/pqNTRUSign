/*
 * misc.c
 *
 *  Created on: Jun 12, 2017
 *      Author: zhenfei
 */
#include <stdint.h>
#include <stdlib.h>
int64_t max_norm(const int64_t *f, const int16_t N)
{
    int16_t i;
    int64_t norm = 0;

    for (i=0;i<N;i++)
    {
        if (abs(f[i])>norm)
            norm = abs(f[i]);
    }
    return norm;
}

/* return the square of the l2 norm */
int64_t l2_norm(const int64_t *f, const int16_t N)
{
    int16_t i;
    int64_t norm = 0;

    for (i=0;i<N;i++)
    {
        norm += f[i]*f[i];
    }
    return norm;
}


/* return the scala product of two vectors */
int64_t get_scala(
        const int64_t *f,
        const int64_t *g,
        const int16_t N)
{
    int16_t i;
    int64_t product = 0;
    for (i=0;i<N;i++)
        product += f[i]*g[i];
    return product;
}
