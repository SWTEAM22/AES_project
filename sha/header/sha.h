#ifndef SHA_H
#define SHA_H

#include "../include/foundation.h"
#include "../include/error.h"
#include "../include/api.h"

/**
 * @file sha.h
 * @brief SHA-2 해시 알고리즘 헤더 파일
 *
 * @details
 *   이 헤더 파일은 SHA-2 계열 해시 알고리즘의 함수 선언을 포함한다.
 *   SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256을 지원한다.
 *
 * @see sha.c
 */

/**
 * @brief SHA-512 계열 공통 처리 함수
 *
 * @details
 *   SHA-512, SHA-384, SHA-512/224, SHA-512/256의 공통 처리 로직을 수행한다.
 *   초기 해시 값과 출력 길이만 다르게 설정하여 각 알고리즘을 구현한다.
 *
 * @param[out] digest       계산된 해시 다이제스트를 저장할 버퍼
 * @param[in]  data         해시를 계산할 입력 데이터
 * @param[in]  data_len     입력 데이터의 길이 (바이트 단위)
 * @param[in]  initial_hash 초기 해시 값 (8개의 64비트 워드)
 * @param[in]  output_len   출력 다이제스트 길이 (바이트 단위)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see sha384_hash()
 * @see sha512_hash()
 * @see sha512_224_hash()
 * @see sha512_256_hash()
 */
ERR_MSG sha512_process(
    OUT uint8_t* digest,
    IN  const uint8_t* data,
    IN  size_t data_len,
    IN  const uint64_t* initial_hash,
    IN  size_t output_len);

/**
 * @brief SHA-224 해시 함수
 *
 * @param[out] digest   계산된 SHA-224 다이제스트 (28바이트)
 * @param[in]  data     해시를 계산할 입력 데이터
 * @param[in]  data_len 입력 데이터의 길이 (바이트 단위)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see sha256_hash()
 */
ERR_MSG sha224_hash(
    OUT uint8_t* digest,
    IN  const uint8_t* data,
    IN  size_t data_len);

/**
 * @brief SHA-256 해시 함수
 *
 * @param[out] digest   계산된 SHA-256 다이제스트 (32바이트)
 * @param[in]  data     해시를 계산할 입력 데이터
 * @param[in]  data_len 입력 데이터의 길이 (바이트 단위)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see sha224_hash()
 */
ERR_MSG sha256_hash(
    OUT uint8_t* digest,
    IN  const uint8_t* data,
    IN  size_t data_len);

/**
 * @brief SHA-384 해시 함수
 *
 * @param[out] digest   계산된 SHA-384 다이제스트 (48바이트)
 * @param[in]  data     해시를 계산할 입력 데이터
 * @param[in]  data_len 입력 데이터의 길이 (바이트 단위)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see sha512_hash()
 */
ERR_MSG sha384_hash(
    OUT uint8_t* digest,
    IN  const uint8_t* data,
    IN  size_t data_len);

/**
 * @brief SHA-512 해시 함수
 *
 * @param[out] digest   계산된 SHA-512 다이제스트 (64바이트)
 * @param[in]  data     해시를 계산할 입력 데이터
 * @param[in]  data_len 입력 데이터의 길이 (바이트 단위)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see sha384_hash()
 * @see sha512_224_hash()
 * @see sha512_256_hash()
 */
ERR_MSG sha512_hash(
    OUT uint8_t* digest,
    IN  const uint8_t* data,
    IN  size_t data_len);

/**
 * @brief SHA-512/224 해시 함수
 *
 * @param[out] digest   계산된 SHA-512/224 다이제스트 (28바이트)
 * @param[in]  data     해시를 계산할 입력 데이터
 * @param[in]  data_len 입력 데이터의 길이 (바이트 단위)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see sha512_hash()
 * @see sha512_256_hash()
 */
ERR_MSG sha512_224_hash(
    OUT uint8_t* digest,
    IN  const uint8_t* data,
    IN  size_t data_len);

/**
 * @brief SHA-512/256 해시 함수
 *
 * @param[out] digest   계산된 SHA-512/256 다이제스트 (32바이트)
 * @param[in]  data     해시를 계산할 입력 데이터
 * @param[in]  data_len 입력 데이터의 길이 (바이트 단위)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see sha512_hash()
 * @see sha512_224_hash()
 */
ERR_MSG sha512_256_hash(
    OUT uint8_t* digest,
    IN  const uint8_t* data,
    IN  size_t data_len);

#endif // !SHA_H
