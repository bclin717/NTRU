//
// Created by kevin on 2018/3/5.
//

#ifndef SS_NTRU_MASTER_PROXYREENCRYPT_H
#define SS_NTRU_MASTER_PROXYREENCRYPT_H

#endif //SS_NTRU_MASTER_PROXYREENCRYPT_H

#include "param.h"

void
bitDecomposition(
        int64_t *BDinput,
        const int length,
        int64_t *BDoutput,
        const int outputLength,
        int64_t l);

void
powerOf2(
        int64_t *POinput,
        int64_t *POoutput);

void
computeReEncryptionKey(
        int64_t keyA,
        int64_t keyB,
        int64_t reKey);

void
ReEncrypt(
        const char *msg,
        int64_t hntt,
        int64_t cntt,
        const PARAM_SET *param);

void
ReDecrypt(
        char *msg,   /* output message string */
        int64_t *f,     /* input secret key */
        int64_t *hntt,  /* input public key */
        int64_t *cntt,  /* input ciphertext */
        int64_t *buf,
        const PARAM_SET *param);

