#include "../include/foundation.h"
#include "../include/api.h"
#include "../include/error.h"
#include "../aes/header/aes_ctr.h"
#include "../sha/header/sha.h"

ERR_MSG encrypt_file_with_tag(
	IN  const char* input_filepath,      // 입력 파일 경로
	IN  const uint8_t* key,              // AES 키
	IN  size_t key_len,                  // 키 길이 (바이트 단위)
	IN  const uint8_t* iv,               // 초기화 벡터 (CTR 모드에 따라 필요)
	IN  size_t iv_len,                   // IV 길이
	IN  const char* output_filepath,     // 암호화된 파일 저장 경로
	OUT uint8_t* tag,                    // 생성된 해시 태그 (예: SHA-256: 32바이트)
	IN  size_t tag_len                   // 태그 길이
) {
	return SUCCESS;
}

ERR_MSG decrypt_file_with_tag(
	IN  const char* input_filepath,      // 암호화된 파일 경로
	IN  const uint8_t* key,              // AES 키
	IN  size_t key_len,                  // 키 길이 (바이트 단위)
	IN  const uint8_t* iv,               // 초기화 벡터 (CTR 모드에 따라 필요)
	IN  size_t iv_len,                   // IV 길이
	IN const char* output_filepath,     // 복호화된 파일 저장 경로
	IN  const uint8_t* expected_tag,     // 예상되는 해시 태그
	IN  size_t tag_len                   // 태그 길이
) {
	return SUCCESS;
}