#ifndef PRINT_H
#define PRINT_H

#include "../include/foundation.h"
#include "../include/error.h"

/**
 * @file print.h
 * @brief 테스트용 출력 함수 헤더 파일
 *
 * @details
 *   이 헤더 파일은 테스트 코드에서 사용하는 데이터 출력 함수를 선언한다.
 *
 * @see print.c
 */

/**
 * @brief 데이터를 16진수 형태로 출력하는 함수
 *
 * @param[in] dat 출력할 데이터 버퍼
 * @param[in] len 데이터 길이 (바이트 단위)
 *
 * @remark
 *   - 16바이트마다 줄바꿈을 수행한다.
 *   - dat가 NULL이거나 len이 0이면 아무것도 출력하지 않는다.
 *
 * @see print_state()
 */
void print_data(const uint8_t* dat, size_t len);

/**
 * @brief AES state 행렬을 4x4 형태로 출력하는 함수
 *
 * @param[in] state 출력할 AES state 행렬 (4x4 바이트 배열)
 *
 * @remark
 *   - state가 NULL이면 아무것도 출력하지 않는다.
 *   - 각 행을 한 줄에 출력한다.
 *
 * @see print_data()
 */
void print_state(const uint8_t state[4][4]);

#endif // !PRINT_H