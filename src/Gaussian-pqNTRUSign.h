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

#ifndef GAUSSIAN_PQNTRUSIGN_H_
#define GAUSSIAN_PQNTRUSIGN_H_
#include "param.h"


/*
 * generate a set of private/public key pairs.
 * requires a buffer for 3 padded polynomials
 */
void keygen(
            int64_t     *f,         /* output - secret key */
            int64_t     *g,         /* output - secret key */
            int64_t     *g_inv,     /* output - secret key */
            int64_t     *h,         /* output - public key */
            int64_t     *buf,       /* input  - buffer     */
    const   PQ_PARAM_SET*param);    /* input  - parameters */

/*
 * sign a message using rejection sampling method
 * returns the number of repetitions
 * buf memory requirement: 10 polynomials.
 */
int sign(
            int64_t     *sig,       /* output - signature  */
    const   int64_t     *msg,       /* input  - message    */
    const   int64_t     *f,         /* input  - secret key */
    const   int64_t     *g,         /* input  - secret key */
    const   int64_t     *g_inv,     /* input  - secret key */
    const   int64_t     *h,         /* input  - public key */
            int64_t     *buf,       /* input  - buffer     */
    const   PQ_PARAM_SET*param);    /* input  - parameters */

/*
 * verifies a signature, returns 0 if valid
 * buf memory requirement: 5 polynomials.
 */
int verify(
    const   int64_t     *sig,       /* input  - signature  */
    const   int64_t     *msg,       /* input  - message    */
    const   int64_t     *h,         /* input  - public key */
            int64_t     *buf,       /* input  - buffer     */
    const   PQ_PARAM_SET*param);    /* input  - parameters */


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

#endif /* GAUSSIAN_PQNTRUSIGN_H_ */
