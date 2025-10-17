#ifndef SHA_H
#define SHA_H

#include "../include/foundation.h"
#include "../include/error.h"
#include "../include/api.h"

// 각 해시 함수별 API
ERR_MSG sha224_hash(
    OUT uint8_t* digest /*28*/,
    IN  const uint8_t* data,
    IN  size_t data_len);

ERR_MSG sha256_hash(
    OUT uint8_t* digest /*32*/,
    IN  const uint8_t* data,
    IN  size_t data_len);

ERR_MSG sha384_hash(
    OUT uint8_t* digest /*48*/,
    IN  const uint8_t* data,
    IN  size_t data_len);

ERR_MSG sha512_hash(
    OUT uint8_t* digest /*64*/,
    IN  const uint8_t* data,
    IN  size_t data_len);

ERR_MSG sha512_224_hash(
    OUT uint8_t* digest /*28*/,
    IN  const uint8_t* data,
    IN  size_t data_len);

ERR_MSG sha512_256_hash(
    OUT uint8_t* digest /*32*/,
    IN  const uint8_t* data,
    IN  size_t data_len);

#endif // !SHA_H
