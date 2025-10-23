#include "../include/foundation.h"
#include "../include/error.h"
#include "../include/api.h"
#include "./header/aes.h"

/*----------------------------------- GF128 상에서 곱셈 연산 -------------------------------------------*/

ERR_MSG xtimes(uint8_t* dat) {
	return SUCCESS;
}
ERR_MSG gf_mult(OUT uint8_t* dst, IN const uint8_t* src1, IN const uint8_t* src2) {
	return SUCCESS;
}

/*--------------------------------- 키확장 및 키확장 내부함수 ----------------------------------------*/

ERR_MSG sub_word(uint32_t* word) {
	return SUCCESS;
}

ERR_MSG rot_word(uint8_t* word) {
	return SUCCESS;
}

ERR_MSG key_expansion(OUT AES_KEY* key, IN const uint8_t* master_key, IN size_t key_len) {
	return SUCCESS;
}

/*------------------------------ AES 암호화 및 암호화 내부함수 ------------------------------------------*/

ERR_MSG sub_bytes(uint8_t state[4][4]) {
	return SUCCESS;
}

ERR_MSG shift_rows(uint8_t state[4][4]) {
	return SUCCESS;
}

ERR_MSG mix_columns(uint8_t state[4][4]) {
	return SUCCESS;
}

ERR_MSG add_round_key(uint8_t state[4][4], const AES_KEY* key) {
	return SUCCESS;
}

ERR_MSG aes_encrypt(
	OUT uint8_t* ct,
	IN const AES_KEY* key,
	IN const uint8_t* pt) {
	return SUCCESS;
}

/*------------------------------ AES 복호화 및 복호화 내부함수 ------------------------------------------*/

ERR_MSG inv_sub_bytes(uint8_t state[4][4]) {
	return SUCCESS;
}
ERR_MSG inv_shift_rows(uint8_t state[4][4]) {
	return SUCCESS;
}
ERR_MSG inv_mix_columns(uint8_t state[4][4]) {
	return SUCCESS;
}
// add_round_key 함수는 암호화와 동일

ERR_MSG aes_decrypt(
	OUT uint8_t* pt,
	IN const AES_KEY* key,
	IN const uint8_t* ct) {
	return SUCCESS;
}