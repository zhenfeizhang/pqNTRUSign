/*
 * param.h
 *
 *  Created on: Jun 5, 2017
 *      Author: zhenfei
 */

#ifndef PARAM_H_
#define PARAM_H_
#include "stdint.h"

typedef enum _PQ_PARAM_SET_ID PQ_PARAM_SET_ID;
typedef const struct _PQ_PARAM_SET  PQ_PARAM_SET;

enum _PQ_PARAM_SET_ID {
    /* method - dimention - deviation */
    Guassian_512_107,
    /* method - dimention */
    Unifrom_563,
};


struct _PQ_PARAM_SET {
  PQ_PARAM_SET_ID  id;          /* parameter set id */
  const char       *name;       /* human readable name */
  const uint8_t    OID[3];      /* OID */
  uint8_t          N_bits;      /* ceil(log2(N)) */
  uint8_t          q_bits;      /* ceil(log2(q)) */
  const uint16_t   N;           /* ring degree */
  int8_t           p;           /* message space prime */
  int64_t          q;           /* ring modulus */
  int64_t          B_t;         /* max norm of g*a convolution */
  int64_t          norm_bound_t;/* q/2 - B_t */
  int64_t          Ms;          /* rejection rate on s side */
  int64_t          Mt;          /* rejection rate on t side */
  const uint16_t   d;           /* Flat form +1/-1 counts */
  uint16_t         padded_N;    /* # Polynomial coefficients for Karatsuba */
  uint16_t         stdev;
};

PQ_PARAM_SET *
pq_get_param_set_by_id(PQ_PARAM_SET_ID id);

#endif /* PARAM_H_ */
