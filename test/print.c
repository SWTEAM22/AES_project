#include <stdio.h>
#include <string.h>
#include "../include/api.h"
#include "../include/error.h"
#include "../include/foundation.h"
#include "print.h"
#include "../aes/header/aes.h"

/**
 * @file print.c
 * @brief 테스트용 출력 함수 구현 파일
 *
 * @details
 *   이 파일은 테스트 코드에서 사용하는 데이터 출력 함수의 구현을 포함한다.
 *
 * @see print.h
 */

/**
 * @brief 데이터를 16진수 형태로 출력하는 함수
 *
 * @details
 *   데이터를 16진수 형태로 출력하며, 16바이트마다 줄바꿈을 수행한다.
 *
 * @param[in] dat 출력할 데이터 버퍼
 * @param[in] len 데이터 길이 (바이트 단위)
 *
 * @remark
 *   - dat가 NULL이거나 len이 0이면 아무것도 출력하지 않는다.
 *   - 각 바이트는 2자리 16진수로 출력된다 (예: "2b 7e 15 16").
 *
 * @see print_state()
 */
void print_data(const uint8_t* dat, size_t len) {
    if (!dat || len == 0) return;
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", dat[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

/**
 * @brief AES state 행렬을 4x4 형태로 출력하는 함수
 *
 * @details
 *   AES state 행렬을 4x4 행렬 형태로 출력한다.
 *   각 행은 한 줄에 출력되며, 각 바이트는 16진수로 표시된다.
 *
 * @param[in] state 출력할 AES state 행렬 (4x4 바이트 배열)
 *
 * @remark
 *   - state가 NULL이면 아무것도 출력하지 않는다.
 *   - 출력 형식: 각 행마다 4개의 16진수 바이트가 공백으로 구분되어 출력된다.
 *
 * @see print_data()
 */
void print_state(const uint8_t state[4][4]) {
    if (!state) return;
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            printf("%02x ", state[r][c]);
        }
        printf("\n");
    }
}
