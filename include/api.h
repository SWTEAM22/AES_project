#ifndef API_H
#define API_H

#include "error.h"
#include "foundation.h"
#include "../aes/header/aes.h"

/**
 * @file api.h
 * @brief 암호화 및 해시 API 헤더 파일
 *
 * @details
 *   이 헤더 파일은 AES 암호화, SHA-2 해시, 파일 암복호화 기능을 제공하는
 *   통합 API 인터페이스를 정의한다.
 *
 * @see aes.h
 * @see sha.h
 */

/**
 * @brief SHA-2 해시 알고리즘 타입 열거형
 *
 * @details
 *   SHA-2 계열 해시 알고리즘 중 사용할 타입을 선택한다.
 */
typedef enum {
	SHA224,      /**< SHA-224 (28바이트 다이제스트) */
	SHA256,      /**< SHA-256 (32바이트 다이제스트) */
	SHA384,      /**< SHA-384 (48바이트 다이제스트) */
	SHA512,      /**< SHA-512 (64바이트 다이제스트) */
	SHA512_224,  /**< SHA-512/224 (28바이트 다이제스트) */
	SHA512_256   /**< SHA-512/256 (32바이트 다이제스트) */
} SHA2_TYPE;

/**
 * @brief AES 키 확장(키 스케줄) 함수
 *
 * @param[out] key        확장된 AES 키 정보를 저장할 구조체 포인터
 * @param[in]  master_key 128/192/256비트 마스터 키 (바이트 배열)
 * @param[in]  key_len    마스터 키의 길이 (16/24/32 바이트)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see aes_encrypt_block()
 * @see aes_decrypt_block()
 * @see aes_ctr_crypto()
 */
ERR_MSG key_expansion(
	OUT AES_KEY* key, 
	IN const uint8_t* master_key, 
	IN size_t key_len);     

/**
 * @brief AES 블록 암호화 함수
 *
 * @param[out] ct 암호문(16바이트)
 * @param[in]  key 확장된 AES 키 구조체
 * @param[in]  pt 평문(16바이트)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see key_expansion()
 * @see aes_decrypt_block()
 */
ERR_MSG aes_encrypt_block(
	OUT uint8_t* ct,
	IN const AES_KEY* key,
	IN const uint8_t* pt);

/**
 * @brief AES 블록 복호화 함수
 *
 * @param[out] pt 평문(16바이트)
 * @param[in]  key 확장된 AES 키 구조체
 * @param[in]  ct 암호문(16바이트)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see key_expansion()
 * @see aes_encrypt_block()
 */
ERR_MSG aes_decrypt_block(
	OUT uint8_t* pt,
	IN const AES_KEY* key,
	IN const uint8_t* ct);

/**
 * @brief AES-CTR(카운터) 모드 암/복호화 함수
 *
 * @param[out] ct       암호문 또는 복호문(동일 버퍼 사용 가능)
 * @param[in]  key      확장된 AES 키 구조체
 * @param[in]  pt       평문 또는 암호문 입력 데이터
 * @param[in]  data_len 처리할 데이터 길이(바이트)
 * @param[in]  iv       16바이트 초기 카운터(IV)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see key_expansion()
 */
ERR_MSG aes_ctr_crypto(
	OUT uint8_t* ct,
	IN const AES_KEY* key,
	IN const uint8_t* pt,
	IN size_t data_len,
	IN const uint8_t* iv);

/**
 * @brief SHA-2 해시 함수 (통합 API)
 *
 * @param[out] digest   계산된 해시 다이제스트를 저장할 버퍼
 * @param[in]  data     해시를 계산할 입력 데이터
 * @param[in]  data_len 입력 데이터의 길이 (바이트 단위)
 * @param[in]  type     사용할 SHA-2 알고리즘 타입
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see SHA2_TYPE
 */
ERR_MSG sha2_hash(
	OUT uint8_t* digest,
	IN  const uint8_t* data,
	IN  size_t data_len,
	IN  SHA2_TYPE type);

/**
 * @brief 파일을 AES-CTR 모드로 암호화하고 SHA-256 태그를 생성하는 함수 (기본 버전)
 *
 * @param[in]  input_filepath  암호화할 평문 파일 경로
 * @param[in]  key             AES 암호화 키 (16/24/32바이트)
 * @param[in]  key_len         키의 길이 (바이트 단위, 16/24/32 중 하나)
 * @param[in]  iv              초기화 벡터 (16바이트)
 * @param[in]  iv_len          IV의 길이 (16바이트)
 * @param[in]  output_filepath 암호화된 파일을 저장할 경로
 * @param[out] tag             생성된 SHA-256 태그를 저장할 버퍼 (최대 32바이트)
 * @param[in]  tag_len         태그 길이 (바이트 단위, 1~32)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see encrypt_file_with_tag_ex()
 * @see decrypt_file_with_tag()
 */
ERR_MSG encrypt_file_with_tag(
	IN  const char* input_filepath,
	IN  const uint8_t* key,
	IN  size_t key_len,
	IN  const uint8_t* iv,
	IN  size_t iv_len,
	IN  const char* output_filepath,
	OUT uint8_t* tag,
	IN  size_t tag_len
);

/**
 * @brief 파일을 AES-CTR 모드로 암호화하고 지정된 SHA-2 태그를 생성하는 함수 (확장 버전)
 *
 * @param[in]  input_filepath  암호화할 평문 파일 경로
 * @param[in]  key             AES 암호화 키 (16/24/32바이트)
 * @param[in]  key_len         키의 길이 (바이트 단위, 16/24/32 중 하나)
 * @param[in]  iv              초기화 벡터 (16바이트)
 * @param[in]  iv_len          IV의 길이 (16바이트)
 * @param[in]  output_filepath 암호화된 파일을 저장할 경로
 * @param[out] tag             생성된 태그를 저장할 버퍼
 * @param[in]  tag_len         태그 길이 (바이트 단위)
 * @param[in]  tag_type        사용할 SHA-2 알고리즘 타입
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see encrypt_file_with_tag()
 * @see decrypt_file_with_tag_ex()
 */
ERR_MSG encrypt_file_with_tag_ex(
	IN  const char* input_filepath,
	IN  const uint8_t* key,
	IN  size_t key_len,
	IN  const uint8_t* iv,
	IN  size_t iv_len,
	IN  const char* output_filepath,
	OUT uint8_t* tag,
	IN  size_t tag_len,
	IN  SHA2_TYPE tag_type
);

/**
 * @brief AES-CTR 모드로 암호화된 파일을 복호화하고 SHA-256 태그를 검증하는 함수 (기본 버전)
 *
 * @param[in] input_filepath  복호화할 암호문 파일 경로
 * @param[in] key             AES 복호화 키 (16/24/32바이트)
 * @param[in] key_len         키의 길이 (바이트 단위, 16/24/32 중 하나)
 * @param[in] iv              초기화 벡터 (16바이트)
 * @param[in] iv_len          IV의 길이 (16바이트)
 * @param[in] output_filepath 복호화된 평문 파일을 저장할 경로
 * @param[in] expected_tag    기대하는 SHA-256 태그 (최대 32바이트)
 * @param[in] tag_len         태그 길이 (바이트 단위, 1~32)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see decrypt_file_with_tag_ex()
 * @see encrypt_file_with_tag()
 */
ERR_MSG decrypt_file_with_tag(
	IN  const char* input_filepath,
	IN  const uint8_t* key,
	IN  size_t key_len,
	IN  const uint8_t* iv,
	IN  size_t iv_len,
	IN const char* output_filepath,
	IN  const uint8_t* expected_tag,
	IN  size_t tag_len
);

/**
 * @brief AES-CTR 모드로 암호화된 파일을 복호화하고 지정된 SHA-2 태그를 검증하는 함수 (확장 버전)
 *
 * @param[in] input_filepath  복호화할 암호문 파일 경로
 * @param[in] key             AES 복호화 키 (16/24/32바이트)
 * @param[in] key_len         키의 길이 (바이트 단위, 16/24/32 중 하나)
 * @param[in] iv              초기화 벡터 (16바이트)
 * @param[in] iv_len          IV의 길이 (16바이트)
 * @param[in] output_filepath 복호화된 평문 파일을 저장할 경로
 * @param[in] expected_tag    기대하는 태그
 * @param[in] tag_len         태그 길이 (바이트 단위)
 * @param[in] tag_type        사용할 SHA-2 알고리즘 타입 (암호화 시 사용한 타입과 동일해야 함)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see decrypt_file_with_tag()
 * @see encrypt_file_with_tag_ex()
 */
ERR_MSG decrypt_file_with_tag_ex(
	IN  const char* input_filepath,
	IN  const uint8_t* key,
	IN  size_t key_len,
	IN  const uint8_t* iv,
	IN  size_t iv_len,
	IN  const char* output_filepath,
	IN  const uint8_t* expected_tag,
	IN  size_t tag_len,
	IN  SHA2_TYPE tag_type
);

#endif // !API_H