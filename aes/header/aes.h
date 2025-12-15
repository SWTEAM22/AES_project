#ifndef AES_H
#define AES_H

#include "../include/foundation.h"
#include "../include/error.h"

/**
 * @file aes.h
 * @brief AES 블록 암호 알고리즘 헤더 파일
 *
 * @details
 *   이 헤더 파일은 AES(Advanced Encryption Standard) 블록 암호 알고리즘의
 *   데이터 구조체와 함수 선언을 포함한다.
 *   AES-128, AES-192, AES-256을 모두 지원한다.
 *
 * @see aes.c
 */

/** @brief AES 최대 라운드 수 (AES-256) */
#define MAX_ROUNDS 14

/**
 * @brief AES 키 구조체
 *
 * @details
 *   확장된 라운드 키와 라운드 수를 저장하는 구조체이다.
 *   key_expansion() 함수로 초기화되어야 한다.
 *
 * @remark
 *   - rd_key: 라운드 키 배열 (각 라운드마다 4개의 32비트 워드 필요)
 *   - rounds: 라운드 수 (AES-128: 10, AES-192: 12, AES-256: 14)
 */
typedef struct aes_key {
	uint32_t rd_key[4 * (MAX_ROUNDS + 1)];  /**< 라운드 키 배열 */
	size_t rounds;                          /**< 라운드 수 */
}AES_KEY;

/**
 * @brief GF(2^8) 유한체에서 x 곱셈 연산 (xtimes)
 *
 * @param[in,out] dat 곱셈 연산을 수행할 바이트 포인터
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see gf_mult()
 * @see mix_columns()
 */
ERR_MSG xtimes(uint8_t* dat);

/**
 * @brief GF(2^8) 유한체에서 두 바이트의 곱셈 연산
 *
 * @param[out] dst  곱셈 결과를 저장할 바이트 포인터
 * @param[in]  src1 곱셈할 첫 번째 바이트
 * @param[in]  src2 곱셈할 두 번째 바이트
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see xtimes()
 * @see mix_columns()
 */
ERR_MSG gf_mult(OUT uint8_t* dst, IN const uint8_t* src1, IN const uint8_t* src2);

/**
 * @brief 32비트 워드에 S-box를 적용하는 함수
 *
 * @param[in,out] word S-box를 적용할 32비트 워드 포인터
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see rot_word()
 * @see key_expansion_inline()
 */
ERR_MSG sub_word(uint32_t* word);

/**
 * @brief 4바이트 워드를 왼쪽으로 1바이트 회전하는 함수
 *
 * @param[in,out] word 회전할 4바이트 배열 포인터
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see sub_word()
 * @see key_expansion_inline()
 */
ERR_MSG rot_word(uint8_t* word);

/**
 * @brief AES 키 확장(키 스케줄) 함수 (인라인 구현)
 *
 * @param[out] key        확장된 라운드 키를 저장할 AES_KEY 구조체 포인터
 * @param[in]  master_key 마스터 키 (16/24/32바이트)
 * @param[in]  key_len    마스터 키의 길이 (바이트 단위, 16/24/32 중 하나)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see sub_word()
 * @see rot_word()
 * @see key_expansion()
 */
ERR_MSG key_expansion_inline(OUT AES_KEY* key, IN const uint8_t* master_key, IN size_t key_len);




/**
 * @brief AES SubBytes 변환 함수
 *
 * @param[in,out] state AES state 행렬 (4x4 바이트 배열)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see aes_encrypt()
 */
ERR_MSG sub_bytes(uint8_t state[4][4]);

/**
 * @brief AES ShiftRows 변환 함수
 *
 * @param[in,out] state AES state 행렬 (4x4 바이트 배열)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see aes_encrypt()
 */
ERR_MSG shift_rows(uint8_t state[4][4]);

/**
 * @brief AES MixColumns 변환 함수
 *
 * @param[in,out] state AES state 행렬 (4x4 바이트 배열)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see aes_encrypt()
 */
ERR_MSG mix_columns(uint8_t state[4][4]);

/**
 * @brief AES AddRoundKey 변환 함수
 *
 * @param[in,out] state AES state 행렬 (4x4 바이트 배열)
 * @param[in]     key   확장된 AES 키 구조체
 * @param[in]     round 라운드 번호 (0부터 시작)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see aes_encrypt()
 * @see aes_decrypt()
 */
ERR_MSG add_round_key(uint8_t state[4][4], const AES_KEY* key, size_t round);

/**
 * @brief AES 블록 암호화 함수
 *
 * @param[out] ct  생성된 암호문 블록 (16바이트)
 * @param[in]  key 확장된 AES 키 구조체
 * @param[in]  pt  암호화할 평문 블록 (16바이트)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see key_expansion()
 * @see aes_decrypt()
 */
ERR_MSG aes_encrypt(
	OUT uint8_t* ct,
	IN const AES_KEY* key,
	IN const uint8_t* pt);

/**
 * @brief AES InvSubBytes 변환 함수
 *
 * @param[in,out] state AES state 행렬 (4x4 바이트 배열)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see aes_decrypt()
 */
ERR_MSG inv_sub_bytes(uint8_t state[4][4]);

/**
 * @brief AES InvShiftRows 변환 함수
 *
 * @param[in,out] state AES state 행렬 (4x4 바이트 배열)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see aes_decrypt()
 */
ERR_MSG inv_shift_rows(uint8_t state[4][4]);

/**
 * @brief AES InvMixColumns 변환 함수
 *
 * @param[in,out] state AES state 행렬 (4x4 바이트 배열)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see aes_decrypt()
 */
ERR_MSG inv_mix_columns(uint8_t state[4][4]);

/**
 * @brief AES 블록 복호화 함수
 *
 * @param[out] pt  생성된 평문 블록 (16바이트)
 * @param[in]  key 확장된 AES 키 구조체
 * @param[in]  ct  복호화할 암호문 블록 (16바이트)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see key_expansion()
 * @see aes_encrypt()
 */
ERR_MSG aes_decrypt(
	OUT uint8_t* pt,
	IN const AES_KEY* key,
	IN const uint8_t* ct);

#endif  // !AES_H