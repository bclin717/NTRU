//
// Created by kevin on 2018/3/5.
//

#ifndef SS_NTRU_MASTER_PROXYREENCRYPT_H
#define SS_NTRU_MASTER_PROXYREENCRYPT_H

#endif //SS_NTRU_MASTER_PROXYREENCRYPT_H

#include "param.h"

void
bitDecomposition(
        int64_t* BDinput,
        const int inputLength,
        int64_t* BDoutput,
        const int64_t l);

void
powerOf2(
        int64_t* POinput,
        const int inputLength,
        int64_t* POoutput,
        const PARAM_SET* param);

void
generateReEncryptionKey(
        const int64_t *fA,       /* input secret key f of A */
        const int64_t *hnttB,       /* intput public key h of B */
        int64_t *rk,      /* output re-encryption key rk */
        const PARAM_SET *param);


void
ReEncrypt(
        int64_t *reCiphertext, /* output msg re-encrypted */
        const int64_t *rk,  /* input re-encryption key */
        const int64_t *c, /* input msg encrypted by Key A */
        int64_t *buf,
        const PARAM_SET* param);

void
ReDecrypt(
        int64_t *fB,     /* input secret key f of B */
        int64_t *deCntt,  /* output decrypted msg */
        int64_t *cntt,  /* input re-encrypted msg */
        int64_t* buf,
        const PARAM_SET* param);

