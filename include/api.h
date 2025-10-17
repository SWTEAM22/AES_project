#ifndef API_H
#define API_H

#include "error.h"
#include "foundation.h"
#include "../aes/header/aes.h"


// SHA-2 해시 알고리즘 선택
typedef enum {
	SHA224,
	SHA256,
	SHA384,
	SHA512,
	SHA512_224,
	SHA512_256
} SHA2_TYPE;

// 키 스케줄
ERR_MSG key_expansion(
	OUT AES_KEY* key, 
	IN const uint8_t* master_key, 
	IN size_t key_len);     

// 단일 블록 연산
ERR_MSG aes_encrypt_block(
	OUT uint8_t* ct,
	IN const AES_KEY* key,
	IN const uint8_t* pt);

ERR_MSG aes_decrypt_block(
	OUT uint8_t* pt,
	IN const AES_KEY* key,
	IN const uint8_t* ct);

// CTR (aes_ctr.c / aes_ctr.h 있는 경우 우선 노출)
ERR_MSG aes_ctr_crypto(
	OUT uint8_t* ct,
	IN const AES_KEY* key,
	IN const uint8_t* pt,
	IN size_t data_len,
	IN const uint8_t* iv);

///////////////////////////////////////////////////////////////////////////////////

/* sha-2 해시 */
ERR_MSG sha2_hash(
	OUT uint8_t* digest,
	IN  const uint8_t* data,
	IN  size_t data_len,
	IN  SHA2_TYPE type);

///////////////////////////////////////////////////////////////////////////////////

ERR_MSG encrypt_file_with_tag(
	IN  const char* input_filepath,      // 입력 파일 경로
	IN  const uint8_t* key,              // AES 키
	IN  size_t key_len,                  // 키 길이 (바이트 단위)
	IN  const uint8_t* iv,               // 초기화 벡터 (CTR 모드에 따라 필요)
	IN  size_t iv_len,                   // IV 길이
	IN  const char* output_filepath,     // 암호화된 파일 저장 경로
	OUT uint8_t* tag,                    // 생성된 해시 태그 (예: SHA-256: 32바이트)
	IN  size_t tag_len                   // 태그 길이
);

ERR_MSG decrypt_file_with_tag(
	IN  const char* input_filepath,      // 암호화된 파일 경로
	IN  const uint8_t* key,              // AES 키
	IN  size_t key_len,                  // 키 길이 (바이트 단위)
	IN  const uint8_t* iv,               // 초기화 벡터 (CTR 모드에 따라 필요)
	IN  size_t iv_len,                   // IV 길이
	IN const char* output_filepath,     // 복호화된 파일 저장 경로
	IN  const uint8_t* expected_tag,     // 예상되는 해시 태그
	IN  size_t tag_len                   // 태그 길이
);

#endif // !API_H