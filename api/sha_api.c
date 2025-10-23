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
	if (type == SHA224) sha224_hash(digest, data, data_len);
	else if (type == SHA256) sha256_hash(digest, data, data_len);
	else if (type == SHA384) sha384_hash(digest, data, data_len);
	else if (type == SHA512) sha512_hash(digest, data, data_len);
	else if (type == SHA512_224) sha512_224_hash(digest, data, data_len);
	else if (type == SHA512_256) sha512_256_hash(digest, data, data_len);
	else {
		printf("wrong input : sha number\n");
		return ERR_API_INVALID_ARG;
	}
	return SUCCESS;
}