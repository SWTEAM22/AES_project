#include "../include/foundation.h"
#include "../include/api.h"
#include "../include/error.h"
#include "../aes/header/aes.h"
#include "../aes/header/aes_ctr.h"


/**
 * @brief AES 키 확장(키 스케줄) 함수
 *
 * @param[out] key        확장된 AES 키 정보를 저장할 구조체 포인터
 * @param[in]  master_key 128/192/256비트 마스터 키 (바이트 배열)
 * @param[in]  key_len    마스터 키의 길이 (16/24/32 바이트)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see aes_encrypt_block()
 * @see aes_decrypt_block()
 * @see aes_ctr_crypto()
 */
ERR_MSG key_expansion(
	OUT AES_KEY* key,
	IN const uint8_t* master_key,
	IN size_t key_len) {
	// 입력 검증
	if (key == NULL || master_key == NULL) return ERR_AES_KEY_SCHEDULE_NULL_PTR;
	if (key_len != AES_KEY_SIZE_128 && key_len != AES_KEY_SIZE_192 && key_len != AES_KEY_SIZE_256) {
		return ERR_AES_KEY_SCHEDULE_INVALID_KEY;
	}
	
	ERR_MSG err = key_expansion_inline(key, master_key, key_len);
	if (err != SUCCESS) return err;
	return SUCCESS;
}

/**
 * @brief AES 블록 암호화 함수
 *
 * @param[out] ct 암호문(16바이트)
 * @param[in]  key 확장된 AES 키 구조체
 * @param[in]  pt 평문(16바이트)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see key_expansion()
 * @see aes_decrypt_block()
 */
ERR_MSG aes_encrypt_block(
	OUT uint8_t* ct,
	IN const AES_KEY* key,
	IN const uint8_t* pt) {
	// 입력 검증
	if (ct == NULL || key == NULL || pt == NULL) return ERR_AES_ENCRYPT_NULL_PTR;
	
	ERR_MSG err = aes_encrypt(ct, key, pt);
	if (err != SUCCESS) return err;
	return SUCCESS;
}

/**
 * @brief AES 블록 복호화 함수
 *
 * @param[out] pt 평문(16바이트)
 * @param[in]  key 확장된 AES 키 구조체
 * @param[in]  ct 암호문(16바이트)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see key_expansion()
 * @see aes_encrypt_block()
 */
ERR_MSG aes_decrypt_block(
	OUT uint8_t* pt,
	IN const AES_KEY* key,
	IN const uint8_t* ct) {
	// 입력 검증
	if (pt == NULL || key == NULL || ct == NULL) return ERR_AES_DECRYPT_NULL_PTR;
	
	ERR_MSG err = aes_decrypt(pt, key, ct);
	if (err != SUCCESS) return err;
	return SUCCESS;
}

/**
 * @brief AES-CTR(카운터) 모드 암/복호화 함수
 *
 * @param[out] ct       암호문 또는 복호문(동일 버퍼 사용 가능)
 * @param[in]  key      확장된 AES 키 구조체
 * @param[in]  pt       평문 또는 암호문 입력 데이터
 * @param[in]  data_len 처리할 데이터 길이(바이트)
 * @param[in]  iv       16바이트 초기 카운터(IV)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see key_expansion()
 */
ERR_MSG aes_ctr_crypto(
	OUT uint8_t* ct,
	IN const AES_KEY* key,
	IN const uint8_t* pt,
	IN size_t data_len,
	IN const uint8_t* iv) {
	// 입력 검증
	if (ct == NULL || key == NULL || pt == NULL || iv == NULL) {
		return ERR_AES_CTR_INVALID_ARG;
	}
	
	ERR_MSG err = aes_ctr_crypto_inline(ct, key, pt, data_len, iv);
	if (err != SUCCESS) return err;
	return SUCCESS;
}