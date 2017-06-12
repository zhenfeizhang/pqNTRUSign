
/*
 * param.c
 *
 *  Created on: Jun 5, 2017
 *      Author: zhenfei
 */
#include <string.h>

#include "param.h"

static PQ_PARAM_SET pqParamSets[] = {
    {
      Guassian_512_107,    /* parameter set id */
      "g512-107",          /* human readable name */
      {0xff, 0xff, 0xf9},  /* OID */
      10,                  /* bitlength of N */
      16,                  /* bitlength of q */
      512,                 /* ring degree */
      3,                   /* message space prime */
      65537,               /* ring modulus */
      58,                  /* max norm of g*a convolution */
      (1<<15)-58,          /* q/2 - B_t */
      1,                   /* todo: rejection rate on s side */
      1,                   /* todo: rejection rate on t side */
      77,                  /* Product form +1/-1 counts */
      514,                 /* # Polynomial coefficients for Karatsuba */
      107,                 /* std dev */
    },
};

static int numParamSets = sizeof(pqParamSets)/sizeof(PQ_PARAM_SET);

PQ_PARAM_SET *
pq_get_param_set_by_id(PQ_PARAM_SET_ID id)
{
  int i;

  for(i=0; i<numParamSets; i++)
  {
    if(pqParamSets[i].id == id)
    {
      return (pqParamSets + i);
    }
  }
  return NULL;
}
