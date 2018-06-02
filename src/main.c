//
// Created by kevin on 2018/2/23.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "ProxyReEncrypt.h"
#include "NTRUEncrypt.h"
#include "param.h"
#include "poly/poly.h"
#include "api.h"
#include "poly/ntt.h"

uint16_t i;
PARAM_SET *param;
int64_t *mem, *fA, *gA, *hnttA, *buf, *m, *m2, *cnttA; /* *c, *h; */

int64_t *fB, *gB, *hnttB, *cnttB;

int64_t *rk;


char *msg_rev;

void initParam() {
    param = get_param_set_by_id(NTRU_KEM_1024);
    mem = malloc(sizeof(int64_t) * param->N * 17 + LENGTH_OF_HASH * 2);
    msg_rev = malloc(sizeof(char) * param->max_msg_len);

    rk = malloc(sizeof(int64_t) * param->N * param->l);

    if (!mem || !msg_rev) {
        printf("malloc failed\n");
        exit(1);
    }

    m = mem;
    m2 = m + param->N;
    cnttA = m2 + param->N;
    fA = cnttA + param->N;
    gA = fA + param->N;
    hnttA = gA + param->N;

    fB = hnttA + param->N;
    gB = fB + param->N;
    hnttB = gB + param->N;
    cnttB = hnttB + param->N;

    buf = cnttB + param->N;
}

void keyGen(int64_t *f, int64_t *g, int64_t *hntt) {
    keygen(f, g, hntt, buf, param);

//    printf("f:\n");
//    for (i = 0; i < param->N; i++) {
//        printf("%5lld,", (long long) f[i]);
//        if (i % 32 == 31)
//            printf("\n");
//    }
//
//    printf("g:\n");
//    for (i = 0; i < param->N; i++) {
//        p;;rintf("%5lld,", (long long) g[i]);
//        if (i % 32 == 31)
//            printf("\n");
//    }
//
//    printf("h (in NTT form):\n");
//    for (i = 0; i < param->N; i++) {
//        printf("%10lld,", (long long) hntt[i]);
//        if (i % 16 == 15)
//            printf("\n");
//    }
}

void checkKey() {
    printf("check keys, 0 - okay, -1 - error: %d\n", check_keys(fA, gA, hnttA, buf, param));
    printf("check keys, 0 - okay, -1 - error: %d\n", check_keys(fB, gB, hnttB, buf, param));
}

int main() {

    initParam();

    keyGen(fA, gA, hnttA);
    keyGen(fB, gB, hnttB);

    int i, i2;
    int length = param->N;
    int64_t *BD = malloc(sizeof(int64_t) * length * param->l);
    int64_t *PO = malloc(sizeof(int64_t) * length * param->l);

    for (i = 0; i < length * param->l; i++) {
        BD[i] = 0;
        PO[i] = 0;
    }

    int64_t a[length];
    int64_t b[length];
    memset(a, 0, sizeof(int64_t) * length);
    memset(b, 0, sizeof(int64_t) * length);
    a[0] = 4, a[1] = 9;
    b[0] = 6, b[1] = 1;

    generateReEncryptionKey(fA, hnttB, rk, param);

//    bitDecomposition(a, 2, BD, param->l);
//    powerOf2(b, 2, PO, param);
//
//
//    int64_t tempA[length], tempB[length], tempC[length];
//    int64_t tempAntt[length], tempBntt[length], tempCntt[length];
//    int64_t result[length];
//    for (i = 0; i < length; i++) {
//        tempA[i] = 0;
//        tempB[i] = 0;
//        tempC[i] = 0;
//        tempAntt[i] = 0;
//        tempBntt[i] = 0;
//        tempCntt[i] = 0;
//        result[i] = 0;
//    }
//
//
//    for (i = 0; i < param->l * length; i += length) {
//        for (i2 = 0; i2 < length; i2++) {
//            tempA[i2] = BD[i2 + i];
//            tempB[i2] = PO[i2 + i];
//        }
//        NTT(tempA, tempAntt, param);
//        NTT(tempB, tempBntt, param);
//        for (i2 = 0; i2 < length; i2++) {
//            tempCntt[i2] = modq(tempAntt[i2] * tempBntt[i2], param->q);
//        }
//        INTT(tempC, tempCntt, param);
//        for (i2 = 0; i2 < length; i2++) {
//            result[i2] = modq(result[i2] + tempC[i2], param->q);
//        }
//    }
//
//    for (i = 0; i < length * param->l; i++) {
//        if (i % 45 == 0) printf("\n");
//        printf("%lld, ", BD[i]);
//    }
//
//    printf("\n\n");
//
//    for (i = 0; i < length * param->l; i++) {
//        if (i % 45 == 0) printf("\n");
//        printf("%lld, ", PO[i]);
//    }
//
//    printf("\n\n");
//
//    for (i = 0; i < length; i++) {
//        if (i % 14 == 0) printf("\n");
//        printf("%lld, ", result[i]);
//    }







    return 0;
}