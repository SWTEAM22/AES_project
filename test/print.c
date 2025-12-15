#include <stdio.h>
#include <string.h>
#include "../include/api.h"
#include "../include/error.h"
#include "../include/foundation.h"
#include "print.h"
#include "../aes/header/aes.h"

// 값들을 16진수 형태로 출력하는 함수
void print_data(const uint8_t* dat, size_t len) {
    if (!dat || len == 0) return;
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", dat[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

// 값들을 4x4 행렬 형태로 출력하는 함수
void print_state(const uint8_t state[4][4]) {
    if (!state) return;
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            printf("%02x ", state[r][c]);
        }
        printf("\n");
    }
}
