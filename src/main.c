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
int64_t *mem, *f, *g, *hntt, *buf, *m, *m2, *cntt; /* *c, *h; */
char *msg_rev;

void initParam() {
    param = get_param_set_by_id(NTRU_KEM_1024);
    mem = malloc(sizeof(int64_t) * param->N * 13 + LENGTH_OF_HASH * 2);
    msg_rev = malloc(sizeof(char) * param->max_msg_len);

    if (!mem || !msg_rev) {
        printf("malloc failed\n");
        exit(1);
    }

    m = mem;
    m2 = m + param->N;
    cntt = m2 + param->N;
    f = cntt + param->N;
    g = f + param->N;;
    hntt = g + param->N;
    buf = hntt + param->N;     /* 7 ring elements and 2 hashes*/
}

void keyGen() {
    keygen(f, g, hntt, buf, param);

    printf("f:\n");
    for (i = 0; i < param->N; i++) {
        printf("%5lld,", (long long) f[i]);
        if (i % 32 == 31)
            printf("\n");
    }

    printf("g:\n");
    for (i = 0; i < param->N; i++) {
        printf("%5lld,", (long long) g[i]);
        if (i % 32 == 31)
            printf("\n");
    }

    printf("h (in NTT form):\n");
    for (i = 0; i < param->N; i++) {
        printf("%10lld,", (long long) hntt[i]);
        if (i % 16 == 15)
            printf("\n");
    }
}

void checkKey() {
    printf("check keys, 0 - okay, -1 - error: %d\n", check_keys(f, g, hntt, buf, param));
}

int main() {
    initParam();

    //生成並印出 DGS 分佈的變數陣列
//    printf("testing discrete Gaussian sampler with dev %lld\n", (long long) param->stddev);
//    DGS(f, (const uint16_t) param->N, (const uint16_t) param->stddev);
//    for (i = 0; i < param->N; i++) {
//        printf("%5lld ", (long long) f[i]);
//        if (i % 32 == 31)
//            printf("\n");
//    }
//    memset(f, 0, sizeof(int64_t) * param->N);

//    keyGen();
//    checkKey();

    int64_t a[2] = {4, 9};
    int64_t length = sizeof(a) / sizeof(a[0]);
    int64_t output[length*param->l];

    bitDecomposition(a, 2, output, param->l*length, param->l);

    return 0;
}