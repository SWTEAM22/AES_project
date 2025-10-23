#include "../include/foundation.h"
#include "../include/api.h"
#include "../include/error.h"
#include "../aes/header/aes.h"
#include "../aes/header/aes_ctr.h"

ERR_MSG key_expansion(
	OUT AES_KEY* key,
	IN const uint8_t* master_key,
	IN size_t key_len) {
	key_expansion(key, master_key, key_len);
	return SUCCESS;
}

// 단일 블록 연산
ERR_MSG aes_encrypt_block(
	OUT uint8_t* ct,
	IN const AES_KEY* key,
	IN const uint8_t* pt) {
	aes_encrypt(ct, key, pt);
	return SUCCESS;
}

ERR_MSG aes_decrypt_block(
	OUT uint8_t* pt,
	IN const AES_KEY* key,
	IN const uint8_t* ct) {
	aes_decrypt(pt, key, ct);
	return SUCCESS;
}

// CTR (aes_ctr.c / aes_ctr.h 있는 경우 우선 노출)
ERR_MSG aes_ctr_crypto(
	OUT uint8_t* ct,
	IN const AES_KEY* key,
	IN const uint8_t* pt,
	IN size_t data_len,
	IN const uint8_t* iv) {
	aes_ctr_crypto(ct, key, pt, data_len, iv);
	return SUCCESS;
}