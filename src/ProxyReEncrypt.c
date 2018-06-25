//
// Created by kevin on 2018/3/5.
//

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "param.h"
#include "poly/poly.h"
#include "rng/fastrandombytes.h"
#include "rng/crypto_hash_sha512.h"
#include "ProxyReEncrypt.h"

void base10to2(int64_t n, int64_t l, int64_t* output) {
    int i = 0;
    for(i = 0; i < l; i++) {
        output[i] = n % 2;
        if(n == 0)
            output[i] = 0;
        else
            n /= 2;
    }
}

void
bitDecomposition(
        int64_t* BDinput,
        const int inputLength,
        int64_t* BDoutput,
        int64_t l) {

    int i, i2;
    int64_t base2bits[inputLength][l];

    for(i = 0; i < inputLength; i++)
        base10to2(BDinput[i], l, base2bits[i]);

    for(i = 0; i < l; i++) {
        for(i2 = 0; i2 < inputLength; i2++) {
            BDoutput[i * inputLength + (inputLength - i2 - 1)] = base2bits[i2][i];
        }
    }
}

void
powerOf2(
        int64_t* POinput,
        const int inputLength,
        int64_t* POoutput,
        PARAM_SET* param) {

    int i, i2;
    for(i = 0; i < param->l; i++) {
        for(i2 = 0; i2 < inputLength; i2++) {
            POoutput[i * inputLength + (inputLength - i2 - 1)] = (int64_t) modq(pow(2, i) * POinput[i2], param->q);
        }
    }

}

void newNTT(int64_t *f, int64_t *f_ntt, int64_t length, const PARAM_SET *param) {
    int i, i2;
    int64_t temp[param->N], tempNTT[param->N];
    if (length > param->N) {
        for (i = 0; i < length / param->N; i++) {
            for (i2 = 0; i2 < param->N; i2++)
                temp[i2] = f[i2 + i * param->N];
            NTT(temp, tempNTT, param);
            for (i2 = 0; i2 < param->N; i2++)
                f_ntt[i2 + i * param->N] = tempNTT[i2];
        }
    }
}

void newINTT(int64_t *f, int64_t *f_ntt, int64_t length, PARAM_SET *param) {
    int i, i2;
    int64_t temp[param->N], tempNTT[param->N];
    if (length > param->N) {
        for (i = 0; i < length / param->N; i++) {
            for (i2 = 0; i2 < param->N; i2++)
                tempNTT[i2] = f_ntt[i2 + i * param->N];
            INTT(temp, tempNTT, param);
            for (i2 = 0; i2 < param->N; i2++)
                f[i2 + i * param->N] = temp[i2];
        }
    }
}

void
generateReEncryptionKey(
        const int64_t *fA,       /* input secret key f of A */
        const int64_t *fB,
        const int64_t *hnttB,       /* input public key h of B */
        int64_t *rk,      /* output re-encryption key rk */
        const PARAM_SET *param) {

    int64_t *buf = malloc(sizeof(int64_t) * param->N * param->l * 7);

    int64_t i, i2, *e, *entt, *r, *rntt, *POfA, *POfAntt, *fAntt, *fBntt, *fABdivNTT, *fABdiv, *rkntt;
    e = buf;
    entt = e + param->N * param->l;
    r = entt + param->N * param->l;
    rntt = r + param->N * param->l;
    POfA = rntt + param->N * param->l;
    POfAntt = POfA + param->N * param->l;
    rkntt = POfAntt + param->N * param->l;

    fAntt = malloc(sizeof(int64_t) * param->N * 4);
    fBntt = fAntt + param->N;
    fABdivNTT = fBntt + param->N;
    fABdiv = fABdivNTT + param->N;


    DDGS(e, param->N * param->l, param->stddev, "A", 1);
    DDGS(r, param->N * param->l, param->stddev, "A", 1);

    // p*e2
    for (i = 0; i < param->N * param->l; i++)
        r[i] = r[i] * param->p;

    newNTT(r, rntt, param->N * param->l, param);
    newNTT(e, entt, param->N * param->l, param);

    NTT(fA, fAntt, param);
    NTT(fB, fBntt, param);

    for (i = 0; i < param->N; i++) {
        /* compute f^-1 mod q */
        fBntt[i] = InvMod(fBntt[i], param->q);
        /* compute h = p*gf^-1 mod q */
        fABdivNTT[i] = param->p * fAntt[i] * fBntt[i] % param->q;
    }

    INTT(fABdiv, fABdivNTT, param);

    // PO(fA/fB)
    powerOf2(fABdiv, param->N, POfA, param);
    newNTT(POfA, POfAntt, param->N * param->l, param);

    // rkntt = e(NTT)*PO(fA/fB) + r(NTT) mod q
    for (i = 0; i < param->l * param->N; i++) {
        rkntt[i] = entt[i] * POfAntt[i] + rntt[i];
    }
    newINTT(rk, rkntt, param->l * param->N, param);

//    for (i = 0; i < param->N * param->l; i++) {
//        if (i % 11 == 10) printf("\n");
//        printf("%5lld,", rk[i]);
//    }

    //Release ring memoryPOfA
    memset(buf, 0, sizeof(int64_t) * param->N * param->l * 7);
    memset(fAntt, 0, sizeof(int64_t) * param->N * 4);
}

void
ReEncrypt(
        int64_t *reCiphertext, /* output msg re-encrypted */
        const int64_t *rk,  /* input re-encryption key */
        const int64_t *cntt, /* input msg encrypted by Key A */
        int64_t *buf,
        const PARAM_SET *param) {
    int i, i2;

    memset(reCiphertext, 0, sizeof(int64_t) * param->N);

    int64_t *rkNTT, *BDc;
    int64_t *cntt2;

    rkNTT = malloc(sizeof(int64_t) * param->N * param->l * 3);
    BDc = rkNTT + (param->N * param->l);
    cntt2 = BDc + (param->N * param->l);


    newNTT(rk, rkNTT, param->N * param->l, param);

    int64_t *c;
    c = buf + param->N;
    INTT(c, cntt, param);

    bitDecomposition(c, param->N, BDc, param->l);

    newNTT(BDc, cntt2, param->N * param->l, param);

    for (i = 0; i < param->l; i++) {
        for (i2 = 0; i2 < param->N; i2++) {
            reCiphertext[i2] += modq(rkNTT[i2 + i * param->N] * cntt2[i2 + i * param->N], param->q);
        }
    }

    //Release ring memory
    memset(buf, 0, sizeof(int64_t) * param->N);
    memset(rkNTT, 0, sizeof(int64_t) * param->N * param->l * 3);
}

void
ReDecrypt(
        int64_t *fB,     /* input secret key f of B */
        int64_t *deCntt,  /* output decrypted msg */
        int64_t *cntt,  /* input re-encrypted msg */
        int64_t *buf,
        const PARAM_SET *param) {

    int i;

    int64_t *fBntt;
    fBntt = buf;

    NTT(fB, fBntt, param);

    for (i = 0; i < param->N; i++) {
        deCntt[i] = modq(modq(fBntt[i] * cntt[i], param->q), param->p);
    }

    memset(buf, 0, sizeof(int64_t));
}