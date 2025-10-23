#include "../include/foundation.h"
#include "../include/error.h"
#include "./header/aes_ctr.h"

ERR_MSG increment_counter(uint8_t* counter) {		// 카운터 증가 함수
	return SUCCESS;
}

static ERR_MSG aes_ctr_crypto(
	OUT uint8_t* ct,
	IN const AES_KEY* key,
	IN const uint8_t* pt,
	IN size_t data_len,
	IN const uint8_t* iv) {
	return SUCCESS;
}