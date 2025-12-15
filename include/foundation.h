#ifndef FOUNDATION_H
#define FOUNDATION_H

#include <stdint.h>
#include <stddef.h>

/**
 * @file foundation.h
 * @brief 기본 상수 및 타입 정의 헤더 파일
 *
 * @details
 *   이 헤더 파일은 암호화 라이브러리에서 사용하는 기본 상수, 타입 정의,
 *   매크로를 포함한다.
 */

/** @brief 입력 매개변수 표시 매크로 */
#define IN

/** @brief 출력 매개변수 표시 매크로 */
#define OUT

/** @brief 참(True) 값 */
#define TRUE 1

/** @brief 거짓(False) 값 */
#define FALSE 0

/** @brief AES 블록 크기 (바이트) */
#define AES_BLOCK_SIZE 16

/** @brief AES-128 키 크기 (바이트) */
#define AES_KEY_SIZE_128 16

/** @brief AES-192 키 크기 (바이트) */
#define AES_KEY_SIZE_192 24

/** @brief AES-256 키 크기 (바이트) */
#define AES_KEY_SIZE_256 32

/** @brief SHA-256 블록 크기 (바이트) */
#define SHA256_BLOCK_SIZE 64

/** @brief SHA-512 블록 크기 (바이트) */
#define SHA512_BLOCK_SIZE 128

/** @brief SHA-224 다이제스트 크기 (바이트) */
#define SHA224_DIGEST_SIZE 28

/** @brief SHA-256 다이제스트 크기 (바이트) */
#define SHA256_DIGEST_SIZE 32

/** @brief SHA-384 다이제스트 크기 (바이트) */
#define SHA384_DIGEST_SIZE 48

/** @brief SHA-512 다이제스트 크기 (바이트) */
#define SHA512_DIGEST_SIZE 64

/** @brief SHA-512/224 다이제스트 크기 (바이트) */
#define SHA512_224_DIGEST_SIZE 28

/** @brief SHA-512/256 다이제스트 크기 (바이트) */
#define SHA512_256_DIGEST_SIZE 32

/**
 * @brief 테스트 케이스 선택 매크로
 *
 * @details
 *   - 0: 파일 암복호화 프로그램 (FILE_CRYPTO)
 *   - 1: AES 테스트 (AES_TEST_MAIN)
 *   - 2: SHA 테스트 (SHA_TEST_MAIN)
 */
#define TESTCASE 0

#if TESTCASE == 1
#define AES_TEST_MAIN

#elif TESTCASE == 2
#define SHA_TEST_MAIN

#else
#define FILE_CRYPTO

#endif // !TESTCASE

/** @brief 바이트 타입 정의 */
typedef uint8_t byte;

/** @brief 워드 타입 정의 */
typedef uint16_t word;

#endif // !FOUNDATION_H