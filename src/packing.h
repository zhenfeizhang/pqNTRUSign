/*
 * packing.h
 *
 *  Created on: Sep 1, 2017
 *      Author: zhenfei
 */

#ifndef PACKING_H_
#define PACKING_H_


int unpack_secret_key(
    const unsigned char   *blob,
    PQ_PARAM_SET       *param,
    int64_t        *f,
    int64_t        *g,
    int64_t        *g_inv,
    int64_t        *h);

int pack_secret_key(
    unsigned char   *blob,
    const PQ_PARAM_SET *param,
    const int64_t  *f,
    const int64_t  *g,
     int64_t  *g_inv,
    const int64_t  *h);


int unpack_public_key(
    const unsigned char   *blob,
    PQ_PARAM_SET *param,
    int64_t  *h);

int pack_public_key(
    unsigned char   *blob,
    const PQ_PARAM_SET *param,
    const int64_t  *h);

#endif /* PACKING_H_ */
