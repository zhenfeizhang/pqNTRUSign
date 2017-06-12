/*
 * NTT.c
 *
 *  Created on: Jun 5, 2017
 *      Author: zhenfei
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "NTT.h"



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
            base = base*roots[i] % 65537;
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
    uint16_t i,j;
    uint64_t tmp;
    for (i=0;i<512;i++)
    {
        tmp = 0;
        for (j=0;j<512; j++)
        {
            tmp += f_ntt[j]*intt[i][j];
        }
        f[i] = tmp% 65537;
        if (f[i]>32768)
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

