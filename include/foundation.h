#ifndef FOUNDATION_H
#define FOUNDATION_H

#include <stdint.h>
#include <stddef.h>

#define IN
#define OUT

#define TRUE 1
#define FALSE 0

// 암호화 관련 상수
#define AES_BLOCK_SIZE 16          // AES 블록 크기 (바이트)

#define AES_KEY_SIZE_128 16        // AES-128 키 크기
#define AES_KEY_SIZE_192 24        // AES-192 키 크기
#define AES_KEY_SIZE_256 32        // AES-256 키 크기

// SHA 관련 상수
#define SHA256_BLOCK_SIZE 64       // SHA-256 블록 크기
#define SHA512_BLOCK_SIZE 128      // SHA-512 블록 크기

#define SHA224_DIGEST_SIZE 28      // SHA-224 다이제스트 크기
#define SHA256_DIGEST_SIZE 32      // SHA-256 다이제스트 크기
#define SHA384_DIGEST_SIZE 48      // SHA-384 다이제스트 크기
#define SHA512_DIGEST_SIZE 64      // SHA-512 다이제스트 크기
#define SHA512_224_DIGEST_SIZE 28  // SHA-512/224 다이제스트 크기
#define SHA512_256_DIGEST_SIZE 32  // SHA-512/256 다이제스트 크기

typedef uint8_t byte;
typedef uint16_t word;

#endif // !FOUNDATION_H