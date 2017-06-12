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
