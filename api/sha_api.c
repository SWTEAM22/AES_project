#include "../include/foundation.h"
#include "../include/api.h"
#include "../include/error.h"
#include "../sha/header/sha.h"
#include <stdio.h>

ERR_MSG sha2_hash(
	OUT uint8_t* digest,
	IN  const uint8_t* data,
	IN  size_t data_len,
	IN  SHA2_TYPE type) {
	// 입력 검증
	if (digest == NULL) return ERR_SHA_HASH_NULL_PTR;
	if (data == NULL && data_len != 0) return ERR_SHA_HASH_INVALID_DATA;
	
	ERR_MSG err;
	
	if (type == SHA224) {
		err = sha224_hash(digest, data, data_len);
		if (err != SUCCESS) return err;
	}
	else if (type == SHA256) {
		err = sha256_hash(digest, data, data_len);
		if (err != SUCCESS) return err;
	}
	else if (type == SHA384) {
		err = sha384_hash(digest, data, data_len);
		if (err != SUCCESS) return err;
	}
	else if (type == SHA512) {
		err = sha512_hash(digest, data, data_len);
		if (err != SUCCESS) return err;
	}
	else if (type == SHA512_224) {
		err = sha512_224_hash(digest, data, data_len);
		if (err != SUCCESS) return err;
	}
	else if (type == SHA512_256) {
		err = sha512_256_hash(digest, data, data_len);
		if (err != SUCCESS) return err;
	}
	else {
		printf("wrong input : sha number\n");
		return ERR_API_INVALID_ARG;
	}
	return SUCCESS;
}