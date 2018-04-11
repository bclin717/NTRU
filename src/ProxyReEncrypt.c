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
        const int outputLength,
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

    // print
    for(i = 0; i < inputLength; i++) {
        printf("No %d elements : %d in base 2: ",i ,BDinput[i]);
        for(i2 = 0; i2 < l ; i2++) {
            printf("%d", base2bits[i][i2]);
        }
        printf("\n");
    }

    printf("BitDecompose Output : ");
    for(i = 0; i < outputLength ; i++) {
        printf("%d", BDoutput[i]);
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
            POoutput[i * inputLength + (inputLength - i2 - 1)] = (int64_t)( pow(2, i) * POinput[i2] ) % param->q;
        }
    }

    printf("\nPowerOf2 Output :");
    for(i = 0; i < param->l*inputLength; i++) {
        if(i % inputLength == 0) printf(" ");
        printf("%d,", POoutput[i]);

    }
}

void
generateReEncryptionKey(
        int64_t *fA,       /* input secret key f of A */
        int64_t *hnttB,       /* intput public key h of B */
        int64_t *rk,      /* output re-encryption key rk */
        int64_t *buf,
        const PARAM_SET *param) {

    int64_t length = sizeof(fA) / sizeof(fA[0]);
    int64_t *POfA;
    int64_t *rkntt;

    int64_t i, *e, *entt, *r, *rntt;
    e = buf;
    entt = e + param->N;
    r = entt + param->N;
    rntt = r + param->N;

    DGS(e, param->N, param->stddev);
    DGS(r, param->N, param->stddev);

    // p*e2
    for (i = 0; i < param->N; i++) {
        r[i] = r[i] * param->p;
    }

    NTT(e, entt, param);
    NTT(r, rntt, param);

    // PO(fA)
    powerOf2(fA, length, POfA, param);

    // rkntt = hB(NTT) * e(NTT) + r(NTT) mod q
    for (i = 0; i < param->N; i++)
        rkntt[i] = modq(entt[i] * hnttB[i] + rntt[i], param->q);

    INTT(rk, rkntt, param);

    memset(buf, 0, sizeof(int64_t) * param->N * 4);
}
