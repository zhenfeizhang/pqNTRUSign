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

#include <string.h>

#include "param.h"

static PQ_PARAM_SET pqParamSets[] = {
    {
      Guassian_512_107,    /* parameter set id */
      "g512-107",          /* human readable name */
      {0xff, 0xff, 0xf9},  /* OID */
      9,                  /* bitlength of N */
      17,                  /* bitlength of q */
      512,                 /* ring degree */
      3,                   /* message space prime */
      65537,               /* ring modulus */
      215,                 /* max l2 norm of f*a convolution */
      40,                  /* max norm of g*a convolution */
      (1<<15)-39,          /* q/2 - B_t */
      7.38905609893065,    /* rejection rate on s side: e^2 */
      77,                  /* Product form +1/-1 counts */
      512,                 /* # Polynomial coefficients for Karatsuba */
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
