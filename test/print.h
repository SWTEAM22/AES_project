#ifndef PRINT_H
#define PRINT_H

#include "../include/foundation.h"
#include "../include/error.h"

/*------------------------------- 출력 함수 -----------------------------------------------*/

// 값들을 16진수 형태로 출력하는 함수
void print_data(const uint8_t* dat, size_t len);

// 값들을 4x4 행렬 형태로 출력하는 함수
void print_state(const uint8_t state[4][4]);

#endif // !PRINT_H