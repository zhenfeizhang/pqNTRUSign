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

/*
 * uncomment VERBOSE to get extra information for testing
 * #define VERBOSE
 */


uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

int test(PQ_PARAM_SET *param)
{

    int64_t   *f, *g, *g_inv, *h, *buf, *msg, *sig, *mem;


    uint64_t startc, endc, signtime = 0, verifytime = 0;
    clock_t start, end;
    double cpu_time_used1;
    double cpu_time_used2;
    int i =0;
    int counter = 0;

    /* memory to store keys/msgs/ctx */
    mem = malloc (sizeof(int64_t)*param->padded_N * 7);
    /* buffer */
    buf = malloc (sizeof(int64_t)*param->padded_N * 10);



    if (!mem || !buf)
    {
        printf("malloc error!\n");
        return -1;
    }


    memset(mem, 0, sizeof(int64_t)*param->padded_N * 7);
    memset(buf, 0, sizeof(int64_t)*param->padded_N * 10);


    f       = mem;
    g       = f     + param->padded_N;
    g_inv   = g     + param->padded_N;
    h       = g_inv + param->padded_N;
    msg     = h     + param->padded_N;
    sig     = msg   + param->padded_N*2;


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
    pol_gen_flat(msg, param->N, param->d);
    pol_gen_flat(msg+param->N, param->N, param->d);

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

    memset(buf, 0, sizeof(int64_t)*param->N * 10);
    sign(sig, msg, f,g,g_inv,h,buf,param);
#ifdef VERBOSE
    printf("the signature is:\n");
    for (i=0;i<param->N;i++)
        printf("%lld,",(long long)sig[i]);
    printf("\n");
#endif
    printf("=====================================\n");

    printf("now verifying the signature: 0 for valid, -1 for invalid:   ");
    /* verifying the signature */
    printf("%d \n", verify(sig, msg, h,buf,param));
    printf("=====================================\n");

    printf("benchmark with signing a set of messages\n");

    for (i=0;i<100;i++)
    {

        memset(msg, 0, sizeof(int64_t)*param->N*2);
        pol_gen_flat(msg, param->N, param->d);
        pol_gen_flat(msg+param->N, param->N, param->d);

        /* sign the msg */
        memset(buf, 0, sizeof(int64_t)*param->N * 10);
        start = clock();
        startc = rdtsc();
        counter += sign(sig, msg, f,g,g_inv,h,buf,param);
        endc = rdtsc();
        end = clock();
        cpu_time_used1 += (end-start);
        signtime += (endc-startc);

        /* verifying the signature */
        memset(buf, 0, sizeof(int64_t)*param->N * 5);
        startc = rdtsc();
        start = clock();

        if(verify(sig, msg, h,buf,param)!=0)
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

int main(void)
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

