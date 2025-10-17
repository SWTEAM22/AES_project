#ifndef AES_CTR
#define AES_CTR

#include "../include/foundation.h"
#include "../include/error.h"
#include "aes.h"
/*------------------------------- AES-CTR 및 내부 함수 -----------------------------------------------*/

ERR_MSG increment_counter(uint8_t* counter);		// 카운터 증가 함수

static ERR_MSG aes_ctr_crypto(
	OUT uint8_t* ct,
	IN const AES_KEY* key,
	IN const uint8_t* pt,
	IN size_t data_len,
	IN const uint8_t* iv);


#endif // !AES_CTR