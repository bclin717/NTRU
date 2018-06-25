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

    generateReEncryptionKey(fA, fB, hnttB, rk, param);

    binary_poly_gen(m, param->N);


    encrypt_kem(m, hnttA, cnttA, buf, param);

    ReEncrypt(cnttB, rk, cnttA, buf, param);

//    ReDecrypt(fB, cnttB, cnttA, buf, param);
    decrypt_kem(m2, fB, cnttB, buf, param);

    int counter = 0;
    for (i = 0; i < param->N; i++)
        counter += abs(m2[i] - m[i]);
    printf("there are %d out of 1024 coefficients that are incorrect!\n", counter);

    return 0;
}