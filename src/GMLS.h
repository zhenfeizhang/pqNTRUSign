/*
 * GMLS.h
 *
 *  Created on: Jun 6, 2017
 *      Author: zhenfei
 */

#ifndef GMLS_H_
#define GMLS_H_
#include "param.h"
void keygen(
    int64_t     *f,
    int64_t     *g,
    int64_t     *g_inv,
    int64_t     *hntt,
    int64_t     *buf,
    PQ_PARAM_SET *param);

int sign(
            int64_t     *sig,
    const   int64_t     *msg,
    const   int64_t     *f,
    const   int64_t     *g,
    const   int64_t     *g_inv,
    const   int64_t     *h,
            int64_t     *buf,
    const   PQ_PARAM_SET*param);

int verify(
            int64_t     *sig,
    const   int64_t     *msg,
    const   int64_t     *h,
            int64_t     *buf,
    const   PQ_PARAM_SET*param);


int batch_sign(
            int64_t     *sig,
    const   int64_t     *msg,
    const   int64_t     *f,
    const   int64_t     *g,
    const   int64_t     *g_inv,
    const   int64_t     *h,
            int64_t     *buf,
    const   PQ_PARAM_SET*param);

int batch_verify(
            int64_t     *sig,
    const   int64_t     *msg,
    const   int64_t     *h,
            int64_t     *buf,
    const   PQ_PARAM_SET*param);

#endif /* GMLS_H_ */
