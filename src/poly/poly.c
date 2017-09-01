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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../rng/fastrandombytes.h"
#include "../rng/shred.h"
#include "../rng/crypto_hash_sha512.h"
#include "../param.h"
int is_balance(const int64_t *f, const int16_t N)
{
    int i, counter = 0;
    for (i=0;i<N;i++)
    {
        counter += f[i];
    }
    return counter;
}


void
_pol_gen_flat(
          int64_t  *ai,
    const uint16_t  N,
    const uint16_t  d)
{
  uint64_t r;
  int16_t count,i, coeff[6];

  count = 0;
  while(count < d+1)
  {
    rng_uint64(&r);
    for (i =0;i<6;i++)
    {
        coeff[i] = r & 0x3FF;
        r = (r - coeff[i])>>10;
        if (coeff[i]<N)
        {
            if (ai[coeff[i]]==0)
            {
                ai[coeff[i]]=1;
                count++;
            }
        }
    }
  }
  count = 0;
  while(count < d)
  {
    rng_uint64(&r);
    for (i =0;i<6;i++)
    {
        coeff[i] = r & 0x3FF;
        r = (r - coeff[i])>>10;
        if (coeff[i]<N)
        {
            if (ai[coeff[i]]==0)
            {
                ai[coeff[i]]=-1;
                count++;
            }
        }

    }
  }
  return;
}


void
pol_gen_flat(
          int64_t  *ai,
    const uint16_t  N,
    const uint16_t  d)
{
    do{
        memset(ai, 0, sizeof(int64_t)*N);
        _pol_gen_flat(ai,N,d);
    }while (is_balance(ai,N)==0);
}


void binary_poly_gen(
        int64_t  *ai,
        const uint16_t  N)
{
    uint16_t r;
    uint64_t i,j,index;
    for (i=0;i<=N/16;i++)
    {
        rng_uint16(&r);
        for (j=0;j<16;j++)
        {
            index = i*16+j;
            if (index<N)
                ai[index] = (r & ( 1 << j)) >> j;
        }
    }
}

/* Uniform random element of pZ^n, v, such that
 * v_i + (p-1)/2 <= (q-1)/2
 * v_i - (p-1)/2 >= -(q-1)/2
 */
void
pol_unidrnd_pZ(
    int64_t          *v,
    const int16_t    N,
    const int64_t    q,
    const int8_t     p)
{
  int16_t i = 0;
  uint64_t r = 0;

  int64_t range = q/p;
  int64_t center = q/(2*p);

  int64_t rndcap = (UINT64_MAX - (UINT64_MAX % range));

  while(i < N) {
    rng_uint64(&r);
    if(r < rndcap) {
      v[i] = ((int64_t)(r % range) - center) * p;
      ++i;
    }
  }
  return;
}

/* Uniform random element of pZ^n, v, such that
 * v_i + (p-1)/2 <= (q-1)/2
 * v_i - (p-1)/2 >= -(q-1)/2
 */
void
pol_unidrnd(
    int64_t          *v,
    const int16_t    N,
    const int64_t    q)
{
  int16_t i = 0;
  uint64_t r = 0;

  int64_t range = q;
  int64_t center = q/2;

  int64_t rndcap = (UINT64_MAX - (UINT64_MAX % range));

  while(i < N) {
    rng_uint64(&r);
    if(r < rndcap) {
      v[i] = ((int64_t)(r % range) - center);
      ++i;
    }
  }
  return;
}

/* Uniform random element of pZ^n, v, such that
 * v_i + (p-1)/2 <= (q-1)/2
 * v_i - (p-1)/2 >= -(q-1)/2
 */
void
pol_unidrnd_with_seed(
    int64_t          *v,
    const int16_t    N,
    const int64_t    q,
    unsigned char    *seed,
    const int16_t    seed_len)
{
  int16_t   i = 0,j=0;
  uint64_t  r       = 0;
  uint64_t  *ptr    = (uint64_t*) seed;
  int64_t   range   = q;
  int64_t   center  = q/2;
  int64_t   rndcap  = (UINT64_MAX - (UINT64_MAX % range));

  crypto_hash_sha512(seed, seed, seed_len);

  while(i < N) {
    r = ptr[j++];
    if(j==8)
    {
        crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
        j = 0;
    }

    if(r < rndcap) {
      v[i] = ((int64_t)(r % range) - center);
      ++i;
    }
  }
  return;
}

int
pol_inv_mod2(
    int64_t        *a_inv,
    const int64_t  *a,
    const uint16_t N)
{
  uint16_t i;
  uint16_t k;
  uint16_t m;

  uint16_t degf;
  uint16_t degg;
  uint16_t degc;
  uint16_t degb;
  uint16_t degtmp;

  /* TODO: minimize memory usage */
  uint16_t scratch_len = 4*(N+1);
  uint8_t *scratch = malloc(scratch_len);

  uint8_t *f = scratch;
  uint8_t *g = f + (N+1);
  uint8_t *b = g + (N+1);
  uint8_t *c = b + (N+1);
  uint8_t *poltmp;

  if(!scratch)
  {
    return -1;
  }
  memset(scratch, 0, scratch_len);

  /* f = a (mod 2)*/
  degf = 0;
  for(i=0; i<N; i++) {
    f[i] = (uint8_t) (a[i] & 1);
    if(f[i]) degf = i;
  }

  /* g = x^N - 1 */
  g[0] = 1;
  g[N] = 1;
  degg = N;

  /* b(X) = 1 */
  b[0] = 1;
  degb = 0;

  /* c(X) = 0 */
  degc = 0;

  k = 0;

  while (1)
  {
    /* find smallest m such that f[m] is nonzero */
    for (m = 0; (m <= degf) && (f[m] == 0); ++m);
    if (m > degf)
    {
      free(scratch);
      return -1;
    }
    if(m > 0) {
      f = f + m;
      degf -= m;
      degc += m;
      for (i = degc; i >= m; i--)
      {
          c[i] = c[i-m];
      }
      for (i = 0; i < m; i++)
      {
          c[i] = 0;
      }
      k += m;
    }

    /* if f(X) = 1, done */

    if (degf == 0)
    {
      break;
    }

    if(degf < degg) {
      /* Swap f and g, b and c */
      poltmp = f; f = g; g = poltmp;
      poltmp = c; c = b; b = poltmp;
      degtmp = degf; degf = degg; degg = degtmp;
      degtmp = degc; degc = degb; degb = degtmp;
    }

    /* f(X) += g(X)
     * might change degree of f if degg >= degf
     */

    for (i = 0; i <= degg; i++)
    {
      f[i] ^= g[i];
    }

    if(degg == degf)
    {
      while(degf > 0 && f[degf] == 0)
      {
        --degf;
      }
    }

    /* b(X) += c(X) */
    for (i = 0; i <= degc; i++)
    {
      b[i] ^= c[i];
    }

    if (degc >= degb)
    {
      degb = degc;
      while(degb > 0 && b[degb] == 0)
      {
        --degb;
      }
    }
  }

  /* a^-1 in (Z/2Z)[X]/(X^N - 1) = b(X) shifted left k coefficients */

  if (k >= N)
  {
    k = k - N;
  }

  m = 0;
  for (i = k; i < N; i++)
  {
    a_inv[m++] = (int64_t)(b[i]);
  }

  for (i = 0; i < k; i++)
  {
    a_inv[m++] = (int64_t)(b[i]);
  }

  shred(scratch, scratch_len);
  free(scratch);

  return 0;
}


/* Space efficient Karatsuba multiplication.
 * See: Thomé, "Karatsuba multiplication with temporary space of size \le n"
 * http://www.loria.fr/~thome/files/kara.pdf
 *
 * Note: Input length should factor into b * 2^k, b <= 38
 */
static void
karatsuba(
    int64_t        *res1,   /* out - a * b in Z[x], must be length 2k */
    int64_t        *tmp1,   /*  in - k coefficients of scratch space */
    int64_t const  *a,     /*  in - polynomial */
    int64_t const  *b,     /*  in - polynomial */
    uint16_t const  k)     /*  in - number of coefficients in a and b */
{
  uint16_t i;
  uint16_t j;

  /* Grade school multiplication for small / odd inputs */
  if(k <= 32 || (k & 1) != 0)
  {
    for(j=0; j<k; j++)
    {
      res1[j] = a[0]*b[j];
    }
    for(i=1; i<k; i++)
    {
      res1[i+k-1] = 0;
      for(j=0; j<k; j++)
      {
        res1[i+j] += a[i]*b[j];
      }
    }
    res1[2*k-1] = 0;

    return;
  }

  uint16_t const p = k>>1;

  int64_t *res2 = res1+p;
  int64_t *res3 = res1+k;
  int64_t *res4 = res1+k+p;
  int64_t *tmp2 = tmp1+p;
  int64_t const *a2 = a+p;
  int64_t const *b2 = b+p;

  for(i=0; i<p; i++)
  {
    res1[i] = a[i] - a2[i];
    res2[i] = b2[i] - b[i];
  }

  karatsuba(tmp1, res3, res1, res2, p);

  karatsuba(res3, res1, a2, b2, p);

  for(i=0; i<p; i++)
  {
    tmp1[i] += res3[i];
  }

  for(i=0; i<p; i++)
  {
    res2[i]  = tmp1[i];
    tmp2[i] += res4[i];
    res3[i] += tmp2[i];
  }

  karatsuba(tmp1, res1, a, b, p);

  for(i=0; i<p; i++)
  {
    res1[i]  = tmp1[i];
    res2[i] += tmp1[i] + tmp2[i];
    res3[i] += tmp2[i];
  }

  return;
}

/* Center 'a' modulo p (an odd prime).
 * (a_i -> [-(p-1)/2, (p-1)/2]
 */
int64_t
cmod(const int64_t a, const int64_t p)
{
  int64_t b;
  b = a;
  if (b >= 0)
  {
    b %= p;
  }
  else
  {
    b = p + (b % p);
  }
  if (b > ((p-1)/2))
  {
    b -= p;
  }

  return b;
}


void
pol_mul_coefficients(
     int64_t         *c,       /* out - address for polynomial c */
     const int64_t   *a,       /*  in - pointer to polynomial a */
     const int64_t   *b,       /*  in - pointer to polynomial b */
     PQ_PARAM_SET    *param,
     int64_t         *tmp)
{
    uint16_t i;
    int64_t *res = tmp;
    int64_t *scratch = res + 2*param->padded_N;
    memset(res, 0, 2*param->N*sizeof(int64_t));
    karatsuba(res, scratch, a, b, param->padded_N);

    /* x^N + 1 ring */
    if (param->id == Gaussian_512_107 || param->id == uniform_512_107)
    {
        for(i=0; i<param->N; i++)
            c[i] = cmod(res[i] - res[i+param->N], param->q);
    }
    /* x^N - 1 ring */
    else if (param->id == Gaussian_761_107 || param->id == uniform_761_107)
    {
        for(i=0; i<param->N; i++)
            c[i] = cmod(res[i] + res[i+param->N], param->q);
    }
}

void
pol_mul_mod_p(
     int64_t         *c,       /* out - address for polynomial c */
     const int64_t   *a,       /*  in - pointer to polynomial a */
     const int64_t   *b,       /*  in - pointer to polynomial b */
     PQ_PARAM_SET    *param,
     int64_t         *tmp)
{
    uint16_t i;
    int64_t *res = tmp;
    int64_t *scratch = res + 2*param->padded_N;
    memset(res, 0, 2*param->N*sizeof(int64_t));
    karatsuba(res, scratch, a, b, param->padded_N);

    /* x^N + 1 ring */
    if (param->id == Gaussian_512_107 || param->id == uniform_512_107)
    {
        for(i=0; i<param->N; i++)
            c[i] = cmod(res[i] - res[i+param->N], param->p);
    }
    /* x^N - 1 ring */
    else if (param->id == Gaussian_761_107 || param->id == uniform_761_107)
    {
        for(i=0; i<param->N; i++)
            c[i] = cmod(res[i] + res[i+param->N], param->p);
    }
}

