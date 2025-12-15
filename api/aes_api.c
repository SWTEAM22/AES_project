#include "../include/foundation.h"
#include "../include/api.h"
#include "../include/error.h"
#include "../aes/header/aes.h"
#include "../aes/header/aes_ctr.h"

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

// 단일 블록 연산
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

// CTR (aes_ctr.c / aes_ctr.h 있는 경우 우선 노출)
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