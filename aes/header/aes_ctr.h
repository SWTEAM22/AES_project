#ifndef AES_CTR
#define AES_CTR

#include "../include/foundation.h"
#include "../include/error.h"
#include "aes.h"

/**
 * @file aes_ctr.h
 * @brief AES-CTR 모드 암호화/복호화 헤더 파일
 *
 * @details
 *   이 헤더 파일은 AES-CTR(Counter) 모드의 암호화 및 복호화 함수 선언을 포함한다.
 *   CTR 모드는 블록암호 AES를 이용한 스트림 암호 방식으로, 암호화와 복호화가 대칭 구조이다.
 *
 * @see aes_ctr.c
 * @see aes.h
 */

/**
 * @brief 128비트 카운터를 1 증가시키는 함수
 *
 * @details
 *   - CTR 모드에서는 블록마다 counter를 1씩 증가시켜 다음 키스트림을 생성한다.
 *   - Big-endian 방식으로 오른쪽(LSB)부터 올림(carry)을 전파한다.
 *
 * @param[in,out] counter 증가시킬 128비트 카운터 (16바이트 배열, 결과가 저장됨)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see aes_ctr_crypto_inline()
 */
ERR_MSG increment_counter(uint8_t* counter);

/**
 * @brief AES-CTR 모드로 암호화/복호화 수행하는 함수 (인라인 구현)
 *
 * @details
 *   - CTR(Counter) 모드는 블록암호 AES를 이용한 스트림 암호 방식이다.
 *   - 매 블록마다 카운터를 AES로 암호화한 키스트림을 생성하고, 평문과 XOR하여 암호문을 생성한다.
 *   - 복호화 과정도 동일하게 XOR 한 번만 수행하면 되므로 암호화와 복호화가 대칭이다.
 *
 * @param[out] ct       출력 버퍼 (암호문 또는 복호문)
 * @param[in]  key      확장된 AES 키 구조체
 * @param[in]  pt       입력 평문/암호문 버퍼
 * @param[in]  data_len 입력 데이터 전체 길이 (바이트 단위)
 * @param[in]  iv       초기 카운터(IV, 16바이트)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see increment_counter()
 * @see aes_encrypt()
 * @see aes_ctr_crypto()
 */
ERR_MSG aes_ctr_crypto_inline(
	OUT uint8_t* ct,
	IN const AES_KEY* key,
	IN const uint8_t* pt,
	IN size_t data_len,
	IN const uint8_t* iv);

#endif // !AES_CTR