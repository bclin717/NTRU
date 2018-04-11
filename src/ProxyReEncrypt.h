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
        const int outputLength,
        const int64_t l);

void
powerOf2(
        int64_t* POinput,
        const int inputLength,
        int64_t* POoutput,
        const PARAM_SET* param);

void
generateReEncryptionKey(
        int64_t *fA,       /* input secret key f of A */
        int64_t *hB,       /* intput public key h of B */
        int64_t *rk,      /* output re-encryption key rk */
        int64_t *buf,
        const PARAM_SET *param);



void
ReEncrypt(
        const char* msg,
        int64_t hntt,
        int64_t cntt,
        const PARAM_SET* param);

void
ReDecrypt(
        char* msg,   /* output message string */
        int64_t* f,     /* input secret key */
        int64_t* hntt,  /* input public key */
        int64_t* cntt,  /* input ciphertext */
        int64_t* buf,
        const PARAM_SET* param);

