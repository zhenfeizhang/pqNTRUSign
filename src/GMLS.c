/*
 ============================================================================
 Name        : GMLS.c
 Author      : zhenfei
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include "param.h"
#include "GMLS.h"
#include "poly/poly.h"





int main(void) {


    int64_t   *f, *g, *g_inv, *h, *buf, *msg, *sig;
    PQ_PARAM_SET *param = pq_get_param_set_by_id(Guassian_512_107);

    f = malloc ( sizeof(int64_t)*param->N);
    g = malloc ( sizeof(int64_t)*param->N);
    g_inv = malloc ( sizeof(int64_t)*param->N);
    h = malloc ( sizeof(int64_t)*param->N);
    buf = malloc ( sizeof(int64_t)*param->N*11);
    msg = malloc ( sizeof(int64_t)*param->N*2);
    sig = malloc ( sizeof(int64_t)*param->N);


    /* generate a set of keys */
    keygen(f,g,g_inv,h,buf,param);

    /* generate a message vector to sign */
    pol_gen_flat(msg, param->N, param->d);
    pol_gen_flat(msg+param->N, param->N, param->d);

    /* sign the msg */
    sign(sig, msg, f,g,g_inv,h,buf,param);

    /* verifying the signature */
    printf("%d \n", verify(sig, msg, h,buf,param));

	return EXIT_SUCCESS;
}


