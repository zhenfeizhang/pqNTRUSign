/*
 * packing.c
 *
 *  Created on: Aug 29, 2017
 *      Author: zhenfei
 */


#include <stdint.h>
#include <string.h>
#include "param.h"


/*
 * polynomial with coefficients mod q to char string
 */
static void
rndpoly_to_string(
    const uint16_t  in_len,     /*  in - degree of trinary poly */
    const int64_t   *poly,        /*  in - ptr to poly */
    unsigned char   *str)       /* out - addr for output string */
{
    uint16_t    overflow[8];        /* each overflow is with probability ~ 2^-16; */
    uint16_t    i, j, *tmp;

    for(i=0;i<8;i++)
        overflow[i] = in_len;
    tmp = (uint16_t*) str;
    for(i=0;i<in_len;i++)
    {
        if (poly[i] == 32768)
            overflow[j++] = i;
        tmp[i] = (uint16_t) (poly[i] & 0xFFFF);
    }
    memcpy(tmp+in_len, overflow, sizeof(uint16_t)*8);
    return;
}

/*
 * char string to polynomial with coefficients mod q
 */
static void
string_to_rndpoly(
    const uint16_t      in_len,     /*  in - degree of trinary poly */
          int64_t       *poly,        /*  in - ptr to poly */
    const unsigned char *str)       /* out - addr for output string */
{

    uint16_t    i;
    int16_t     *tmp;
    tmp = (int16_t*) str;
    for(i=0;i<in_len;i++)
    {
        poly[i] = (int64_t) tmp[i];
    }
    for(;i<in_len+8;i++)
    {
        if (tmp[i]<in_len)
            poly[tmp[i]] = 32768;
    }
    return;
}

/*
 *
 */
static void binary_to_string(
    const uint16_t  in_len,     /*  in - degree of trinary poly */
    const int64_t  *in,        /*  in - ptr to poly */
    unsigned char   *out)       /* out - addr for output string */
{
    unsigned char   tmp;
    uint16_t        Nover8,i,j;

    Nover8 = in_len/8;
    if (in_len%8==0)
        Nover8 --;

    for (i=0;i<Nover8;i++)
    {
        tmp = 0;
        for (j=0;j<7;j++)
        {
            tmp += (in[i*8+j]&1);
            tmp <<=1;
        }
        tmp     += (in[i*8+7]&1);
        out[i]  =   tmp;
    }
    tmp = 0;
    for (i=0;i<8;i++)
    {

        if (8*Nover8+i<in_len)
            tmp+= in[8*Nover8+i];
        if(i!=7)
            tmp<<=1;

    }
    out[Nover8] = tmp;

}


/*
 *
 */
static void string_to_binary(
    const uint16_t  in_len,     /*  in - degree of trinary poly */
            int64_t  *poly,        /*  in - ptr to poly */
    const unsigned char   *str)       /* out - addr for output string */
{
    unsigned char   tmp;
    int       Nover8,i,j;

    Nover8 = in_len/8;
    if (in_len%8==0)
        Nover8 --;
    for (i=0;i<Nover8;i++)
    {

        tmp = str[i];
        for (j=7;j>=0;j--)
        {
            poly[i*8+j] = (int64_t)(tmp&1);
            tmp >>= 1;
        }
    }

    tmp = str[Nover8];
    for (i=7;i>=0; i--)
    {
        if(i+Nover8*8<in_len)
            poly[Nover8*8+i] = (int64_t)(tmp&1);
        tmp >>=1;
    }
}


/*
 * trinary polynomial to char string
 * pack 5 coefficients into 8 bits
 */
static void
tri_to_string(
    const uint16_t  in_len,     /*  in - degree of trinary poly */
    const int64_t   *poly,        /*  in - ptr to poly */
    unsigned char   *str)       /* out - addr for output string */
{
    unsigned char tmp1, tmp2;
    int i,j;
    int padNover5;

    padNover5 = in_len/5;
    if(in_len%5==0)
        padNover5--;
    for (i=0;i<padNover5;i++)
    {
        tmp1 = 0;
        for (j=0;j<5;j++)
        {
            tmp2 = (poly[i*5+j]&0b11);
            if (tmp2==0b11)
                tmp2 = 2;
            tmp1 += tmp2;
            if (j!=4)
                tmp1 *= 3;
        }
        str[i] = tmp1;
    }
    tmp1 = 0;
    for (i=0;i<5;i++)
    {
        if (padNover5*5+i > in_len && i!=4)
            tmp1 *= 3;
        else
        {
            tmp2 = (poly[padNover5*5+i]&0b11);
            if (tmp2==0b11)
                tmp2 = 2;
            tmp1 += tmp2;
            if (i!=4)
                tmp1 *= 3;
        }
    }
    str[padNover5] = tmp1;

    return;
}



/*
 * trinary polynomial to char string
 * unpack 5 coefficients from 8 bits
 */
static void
string_to_tri(
    const uint16_t  in_len,     /*  in - degree of trinary poly */
    const unsigned char  *str,   /*  in - ptr to string */
    int64_t        *poly)       /* out - addr for trinary poly */
{
    unsigned char tmp;
    int i,j;
    int padNover5;

    padNover5 = in_len/5;
    if(in_len%5==0)
        padNover5--;

    for(i=0;i<padNover5;i++)
    {
        tmp = str[i];
        for (j=4;j>=0;j--)
        {
            poly[i*5+j] = tmp%3;
            if (poly[i*5+j]== 2)
                poly[i*5+j] = -1;
            tmp /= 3;
        }
    }
    tmp = str [padNover5];

    for (i=4;i>=0;i--)
    {
        if (padNover5*5+i<in_len)
        {
            poly[padNover5*5+i] = tmp%3;
            if (poly[padNover5*5+i]== 2)
                poly[padNover5*5+i] = -1;
        }
        tmp /= 3;
    }


    return;
}


int pack_public_key(
    unsigned char   *blob,
    const PQ_PARAM_SET *param,
    const int64_t  *h)

{
    blob[0] = (char) param->id;
    rndpoly_to_string(param->N, h, blob+1);

    return 0;
}

int unpack_public_key(
    const unsigned char   *blob,
    PQ_PARAM_SET *param,
    int64_t  *h)
{
    param = pq_get_param_set_by_id(blob[0]);
    string_to_rndpoly (param->N, h, blob+1);
    return 0;
}


int pack_secret_key(
    unsigned char   *blob,
    const PQ_PARAM_SET *param,
    const int64_t  *f,
    const int64_t  *g,
     int64_t  *g_inv,
    const int64_t  *h)
{

    blob[0] = (char) param->id;


    tri_to_string(param->N, f, blob+1);

    tri_to_string(param->N, g, blob+param->N/5+2);

    binary_to_string (param->N, g_inv, blob+param->N/5*2 + 3);

    rndpoly_to_string(param->N, h, blob + param->N/5*2 + 4 + param->N/8);

    return 0;
}

int unpack_secret_key(
    const unsigned char   *blob,
    PQ_PARAM_SET       *param,
    int64_t        *f,
    int64_t        *g,
    int64_t        *g_inv,
    int64_t        *h)
{
    param = pq_get_param_set_by_id(blob[0]);
    string_to_tri (param->N, blob+1, f);
    string_to_tri (param->N, blob+param->N/5+2, g);
    string_to_binary (param->N, g_inv, blob+param->N/5*2 + 3);
    string_to_rndpoly (param->N, h, blob + param->N/5*2 + 4 + param->N/8);
    return 0;
}
