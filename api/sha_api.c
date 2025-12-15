#include "../include/foundation.h"
#include "../include/api.h"
#include "../include/error.h"
#include "../sha/header/sha.h"
#include <stdio.h>

/**
 * @brief SHA-2 해시 함수 (통합 API)
 *
 * @details
 *   - SHA-2 알고리즘 계열(SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256) 중
 *     지정된 타입에 따라 입력 데이터의 해시 값을 계산한다.
 *   - 이 함수는 SHA-2 계열의 모든 알고리즘을 통합된 인터페이스로 제공하는 래퍼 함수이다.
 *   - 내부적으로 각 SHA-2 타입에 해당하는 구체적인 해시 함수를 호출한다.
 *   - 파일 무결성 검증, 메시지 인증 코드(MAC) 생성 등에 사용된다.
 *
 * @param[out] digest   계산된 해시 다이제스트를 저장할 버퍼
 *                      - SHA224: 28바이트, SHA256: 32바이트
 *                      - SHA384: 48바이트, SHA512: 64바이트
 *                      - SHA512_224: 28바이트, SHA512_256: 32바이트
 * @param[in]  data     해시를 계산할 입력 데이터
 * @param[in]  data_len 입력 데이터의 길이 (바이트 단위)
 * @param[in]  type     사용할 SHA-2 알고리즘 타입
 *                      - SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_SHA_HASH_NULL_PTR: digest가 NULL
 *   - ERR_SHA_HASH_INVALID_DATA: data가 NULL이면서 data_len이 0이 아님
 *   - ERR_API_INVALID_ARG: 유효하지 않은 SHA-2 타입
 *   - 각 SHA-2 해시 함수에서 발생한 에러 코드
 *
 * @remark
 *   - 빈 데이터(data_len == 0)도 처리 가능하며, 이 경우 data는 NULL이어도 됨
 *   - digest 버퍼는 선택한 SHA-2 타입의 다이제스트 크기 이상이어야 함
 *   - SHA-512 계열(SHA-512, SHA-512/224, SHA-512/256)은 64바이트 다이제스트를 생성하지만,
 *     SHA-512/224와 SHA-512/256은 각각 28바이트, 32바이트만 사용됨
 *
 * @see sha224_hash()
 * @see sha256_hash()
 * @see sha384_hash()
 * @see sha512_hash()
 * @see sha512_224_hash()
 * @see sha512_256_hash()
 * @see compute_truncated_tag()
 * @see encrypt_file_with_tag_ex()
 * @see decrypt_file_with_tag_ex()
 */
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