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

#ifndef PARAM_H_
#define PARAM_H_
#include <stdint.h>


#define LENGTH_OF_HASH 64

typedef enum _PQ_PARAM_SET_ID PQ_PARAM_SET_ID;
typedef const struct _PQ_PARAM_SET  PQ_PARAM_SET;



enum _PQ_PARAM_SET_ID {
    /* method - dimention - deviation */
    Gaussian_512_107,
    Gaussian_761_107,
    uniform_512_107,
    uniform_761_107,
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
    int64_t          B_s;         /* max l2 norm of f*a convolution (Gaussian only) */
    int64_t          B_t;         /* max infty norm of g*a convolution */
    int64_t          norm_bound_s;/* (q/2 - B_t)/p */
    int64_t          norm_bound_t;/* q/2 - B_t */
    double           Ms;          /* rejection rate on s side */
    const uint16_t   d;           /* Flat form +1/-1 counts */
    uint16_t         padded_N;    /* # Polynomial coefficients for Karatsuba */
    uint16_t         stdev;

    /* NTT param */
    int64_t          *roots;
    int64_t          *inv_roots;
    int64_t          inv_N;
};

PQ_PARAM_SET *
pq_get_param_set_by_id(PQ_PARAM_SET_ID id);

#endif /* PARAM_H_ */
