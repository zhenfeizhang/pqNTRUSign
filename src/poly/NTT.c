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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "NTT.h"
#include "../param.h"
int64_t modq(
          int64_t     a,
          int64_t     q)
{
    int64_t     b = a%q;
    if (b<0)
        return q+b;
    else
        return b;
}

void NTT(
    const PQ_PARAM_SET  *param,
    const int64_t       *f,
          int64_t       *f_ntt)
{
    uint16_t i,j;
    int64_t base, tmp;
    memset(f_ntt, 0, sizeof(uint64_t)*param->N);

    if (param->N%2==0)
    {
        int64_t odd,even;
        for (i=0;i<param->N/2;i++)
        {
            odd  = f[0];
            even = f[0];
            base = 1;
            for (j=1;j<param->N;j++)
            {
                base = base*param->roots[i] % param->q;
                tmp = f[j]*base;
                even = even + tmp;
                if (j%2==0)
                    odd = odd + tmp;
                else
                    odd = odd + param->q - tmp;
            }
            f_ntt[i]= even % param->q;
            f_ntt[param->N-1-i] = odd % param->q;
        }
    }
    else
    {
        for (i=0;i<param->N;i++)
        {
            base = 1;
            f_ntt[i]  = f[0];
            for (j=1;j<param->N;j++)
            {
                base = base*param->roots[i] % param->q;
                f_ntt[i] += f[j]*base;

            }
            f_ntt[i] %= param->q;
        }
    }

}


void Inv_NTT(
    const PQ_PARAM_SET  *param,
          int64_t       *f,
    const int64_t       *f_ntt)
{
    uint16_t    i,j;
    int64_t     base;

    memset(f, 0, sizeof(int64_t)*param->N);
    for (j=0;j<param->N;j++)
    {
        base = 1;
        for (i=0;i<param->N;i++)
        {
            f[i] = modq(f[i]+f_ntt[j]*base,param->q);
            base = modq(base*param->inv_roots[j], param->q);
        }
    }
    for (i=0;i<param->N;i++)
    {
        f[i] = modq(f[i]*param->inv_N,param->q);
        if(f[i]>param->q/2)
            f[i] = f[i]-param->q;
    }
}

int64_t* extendedEuclid (int64_t a, int64_t b){

    int64_t array[3];
    int64_t *dxy = array;
    if (b ==0){
        dxy[0] =a; dxy[1] =1; dxy[2] =0;

        return dxy;
    }
    else{
        int64_t t, t2;
        dxy = extendedEuclid(b, (a %b));
        t =dxy[1];
        t2 =dxy[2];
        dxy[1] =dxy[2];
        dxy[2] = t - a/b *t2;

        return dxy;
    }
}

int64_t InvMod(int64_t a, int64_t n)
{
   int64_t *ptr;

   ptr = extendedEuclid (a,n);
   if (ptr[0]!=1 && ptr[0]!=-1)
   {
       printf("InvMod error\n");
   }

   if (ptr[0] == -1)
       ptr[1] = -ptr[1];
   if (ptr[1] < 0)
      return ptr[1] + n;
   else
      return ptr[1];
}

