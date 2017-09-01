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

#ifndef POLY_POLY_H_
#define POLY_POLY_H_


/*
 * generate a degree N-1 trinary polynomial with
 * d number of +1s and -1s each
 */
void
pol_gen_flat(
          int64_t  *ai,
    const uint16_t  N,
    const uint16_t  d);

/*
 * generate a degree N-1 polynomial whose coefficients
 * follow discrete Gaussian with deviation stdev
 */

void DGS (
          int64_t   *v,
    const uint16_t  N,
    const uint8_t   stdev);

/* deterministic DGS */
void DDGS (      int64_t  *v,
          const uint16_t  dim,
          const uint64_t  stdev,
          unsigned char   *seed,
                  size_t  seed_len);

/*
 * Uniform random element of Z^n mod q
 */
void
pol_unidrnd(
    int64_t          *v,
    const int16_t    N,
    const int64_t    q);

void
pol_unidrnd_with_seed(
    int64_t          *v,
    const int16_t    N,
    const int64_t    q,
    unsigned char    *seed,
    const int16_t    seed_len);

void NTT(
    const PQ_PARAM_SET  *param,
    const int64_t       *f,
          int64_t       *f_ntt);

void Inv_NTT(
    const PQ_PARAM_SET  *param,
          int64_t       *f,
    const int64_t       *f_ntt);


int64_t
max_norm(const int64_t *f, const int16_t N);


void
pol_mul_coefficients(
     int64_t         *c,       /* out - address for polynomial c */
     const int64_t   *a,       /*  in - pointer to polynomial a */
     const int64_t   *b,       /*  in - pointer to polynomial b */
     PQ_PARAM_SET    *param,
     int64_t         *tmp);

void
pol_mul_mod_p(
     int64_t         *c,       /* out - address for polynomial c */
     const int64_t   *a,       /*  in - pointer to polynomial a */
     const int64_t   *b,       /*  in - pointer to polynomial b */
     PQ_PARAM_SET    *param,
     int64_t         *tmp);

int
pol_inv_mod2(
    int64_t        *a_inv,
    const int64_t  *a,
    const uint16_t N);


int64_t InvMod(int64_t a, int64_t n);


void binary_poly_gen(
        int64_t  *ai,
        const uint16_t  N);
/* Center 'a' modulo p (an odd prime).
 * (a_i -> [-(p-1)/2, (p-1)/2]
 */
int64_t
cmod(const int64_t a, const int64_t p);


/* return the scala product of two vectors */
int64_t get_scala(
        const int64_t *f,
        const int64_t *g,
        const int16_t N);
int64_t max_norm(const int64_t *f, const int16_t N);

#endif /* POLY_POLY_H_ */
