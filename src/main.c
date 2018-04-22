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

uint16_t i;
PARAM_SET *param;
int64_t *mem, *fA, *gA, *hnttA, *buf, *m, *m2, *cnttA; /* *c, *h; */

int64_t *fB, *gB, *hnttB, *cnttB;

char *msg_rev;

void initParam() {
    param = get_param_set_by_id(NTRU_KEM_1024);
    mem = malloc(sizeof(int64_t) * param->N * 17 + LENGTH_OF_HASH * 2);
    msg_rev = malloc(sizeof(char) * param->max_msg_len);

    if (!mem || !msg_rev) {
        printf("malloc failed\n");
        exit(1);
    }

    m = mem;
    m2 = m + param->N;
    cnttA = m2 + param->N;
    fA = cnttA + param->N;
    gA = fA + param->N;;
    hnttA = gA + param->N;

    fB = hnttA + param->N;
    gB = fB + param->N;
    hnttB = gB + param->N;
    cnttB = hnttB + param->N;

    buf = cnttB + param->N;     /* 7 ring elements and 2 hashes*/
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

    int64_t *rk = malloc(sizeof(int64_t) * param->N);

    generateReEncryptionKey(fA, hnttB, rk, buf, param);



    return 0;
}