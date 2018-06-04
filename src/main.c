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

    return 0;
}