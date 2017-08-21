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
    const int64_t     *f,
          int64_t     *f_ntt)
{
    uint16_t i,j;
    int64_t odd,even,base, tmp;
    for (i=0;i<256;i++)
    {
        odd  = f[0];
        even = f[0];
        base = 1;
        for (j=1;j<512;j++)
        {
            base = base*roots512[i] % q512;
            tmp = f[j]*base;
            even = even + tmp;
            if (j%2==0)
                odd = odd + tmp;
            else
                odd = odd + 65537 - tmp;
        }
        f_ntt[i]= even % 65537;
        f_ntt[511-i] = odd % 65537;
    }
}


void Inv_NTT(
          int64_t     *f,
    const int64_t     *f_ntt)
{
    uint16_t    i,j;
    int64_t     base;

    memset(f, 0, sizeof(int64_t)*512);
    for (j=0;j<512;j++)
    {
        base = 1;
        for (i=0;i<512;i++)
        {

            f[i] = modq(f[i]+f_ntt[j]*base,q512);
            base = modq(base*invntt512[j], q512);
        }
    }
    for (i=0;i<512;i++)
    {
        f[i] = modq(f[i]*one_over_512,q512);
        if(f[i]>32768)
            f[i] = f[i]-65537;
    }
}

int64_t* extendedEuclid (int64_t a, int64_t b){
    int64_t *dxy = (int64_t *)malloc(sizeof(int64_t) *3);

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
       printf("error\n");

   if (ptr[0] == -1)
       ptr[1] = -ptr[1];
   if (ptr[1] < 0)
      return ptr[1] + n;
   else
      return ptr[1];
}

