#include "../include/foundation.h"
#include "../include/api.h"
#include "../include/error.h"
#include "../aes/header/aes_ctr.h"
#include "../sha/header/sha.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
	// 입력 검증
	if (input_filepath == NULL || key == NULL || iv == NULL || output_filepath == NULL || tag == NULL) {
		return ERR_API_NULL_PTR;
	}
	if (key_len != AES_KEY_SIZE_128 && key_len != AES_KEY_SIZE_192 && key_len != AES_KEY_SIZE_256) {
		return ERR_AES_KEY_SCHEDULE_INVALID_KEY;
	}
	if (iv_len != AES_BLOCK_SIZE) {
		return ERR_AES_CTR_INVALID_LENGTH;
	}
	if (tag_len < SHA256_DIGEST_SIZE) {
		return ERR_API_INVALID_ARG;
	}

	// 파일 열기
	FILE* input_file = fopen(input_filepath, "rb");
	if (input_file == NULL) {
		return ERR_API_FILE_IO;
	}

	FILE* output_file = fopen(output_filepath, "wb");
	if (output_file == NULL) {
		fclose(input_file);
		return ERR_API_FILE_IO;
	}

	// 파일 크기 확인
	fseek(input_file, 0, SEEK_END);
	long file_size = ftell(input_file);
	fseek(input_file, 0, SEEK_SET);

	if (file_size < 0) {
		fclose(input_file);
		fclose(output_file);
		return ERR_API_FILE_IO;
	}

	size_t data_size = (size_t)file_size;
	uint8_t* plaintext = (uint8_t*)malloc(data_size);
	uint8_t* ciphertext = (uint8_t*)malloc(data_size);

	if (plaintext == NULL || ciphertext == NULL) {
		if (plaintext) free(plaintext);
		if (ciphertext) free(ciphertext);
		fclose(input_file);
		fclose(output_file);
		return ERR_API_MEMORY_ALLOC;
	}

	// 파일 읽기
	size_t read_size = fread(plaintext, 1, data_size, input_file);
	fclose(input_file);

	if (read_size != data_size) {
		free(plaintext);
		free(ciphertext);
		fclose(output_file);
		return ERR_API_FILE_IO;
	}

	// AES 키 확장
	AES_KEY aes_key;
	ERR_MSG err = key_expansion(&aes_key, key, key_len);
	if (err != SUCCESS) {
		free(plaintext);
		free(ciphertext);
		fclose(output_file);
		return err;
	}

	// 암호화
	err = aes_ctr_crypto(ciphertext, &aes_key, plaintext, data_size, iv);
	if (err != SUCCESS) {
		free(plaintext);
		free(ciphertext);
		fclose(output_file);
		return err;
	}

	// 해시 태그 생성 (평문에 대해)
	err = sha256_hash(tag, plaintext, data_size);
	if (err != SUCCESS) {
		free(plaintext);
		free(ciphertext);
		fclose(output_file);
		return err;
	}

	// 암호문 파일에 쓰기
	size_t written = fwrite(ciphertext, 1, data_size, output_file);
	fclose(output_file);

	// 메모리 초기화 후 해제
	memset(plaintext, 0, data_size);
	memset(ciphertext, 0, data_size);
	free(plaintext);
	free(ciphertext);

	if (written != data_size) {
		return ERR_API_FILE_IO;
	}

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
	// 입력 검증
	if (input_filepath == NULL || key == NULL || iv == NULL || output_filepath == NULL || expected_tag == NULL) {
		return ERR_API_NULL_PTR;
	}
	if (key_len != AES_KEY_SIZE_128 && key_len != AES_KEY_SIZE_192 && key_len != AES_KEY_SIZE_256) {
		return ERR_AES_KEY_SCHEDULE_INVALID_KEY;
	}
	if (iv_len != AES_BLOCK_SIZE) {
		return ERR_AES_CTR_INVALID_LENGTH;
	}
	if (tag_len < SHA256_DIGEST_SIZE) {
		return ERR_API_INVALID_ARG;
	}

	// 파일 열기
	FILE* input_file = fopen(input_filepath, "rb");
	if (input_file == NULL) {
		return ERR_API_FILE_IO;
	}

	FILE* output_file = fopen(output_filepath, "wb");
	if (output_file == NULL) {
		fclose(input_file);
		return ERR_API_FILE_IO;
	}

	// 파일 크기 확인
	fseek(input_file, 0, SEEK_END);
	long file_size = ftell(input_file);
	fseek(input_file, 0, SEEK_SET);

	if (file_size < 0) {
		fclose(input_file);
		fclose(output_file);
		return ERR_API_FILE_IO;
	}

	size_t data_size = (size_t)file_size;
	uint8_t* ciphertext = (uint8_t*)malloc(data_size);
	uint8_t* plaintext = (uint8_t*)malloc(data_size);
	uint8_t computed_tag[SHA256_DIGEST_SIZE];

	if (ciphertext == NULL || plaintext == NULL) {
		if (ciphertext) free(ciphertext);
		if (plaintext) free(plaintext);
		fclose(input_file);
		fclose(output_file);
		return ERR_API_MEMORY_ALLOC;
	}

	// 파일 읽기
	size_t read_size = fread(ciphertext, 1, data_size, input_file);
	fclose(input_file);

	if (read_size != data_size) {
		free(ciphertext);
		free(plaintext);
		fclose(output_file);
		return ERR_API_FILE_IO;
	}

	// AES 키 확장
	AES_KEY aes_key;
	ERR_MSG err = key_expansion(&aes_key, key, key_len);
	if (err != SUCCESS) {
		free(ciphertext);
		free(plaintext);
		fclose(output_file);
		return err;
	}

	// 복호화
	err = aes_ctr_crypto(plaintext, &aes_key, ciphertext, data_size, iv);
	if (err != SUCCESS) {
		free(ciphertext);
		free(plaintext);
		fclose(output_file);
		return err;
	}

	// 해시 태그 검증
	err = sha256_hash(computed_tag, plaintext, data_size);
	if (err != SUCCESS) {
		free(ciphertext);
		free(plaintext);
		fclose(output_file);
		return err;
	}

	// 태그 비교
	if (memcmp(computed_tag, expected_tag, SHA256_DIGEST_SIZE) != 0) {
		memset(ciphertext, 0, data_size);
		memset(plaintext, 0, data_size);
		free(ciphertext);
		free(plaintext);
		fclose(output_file);
		return ERR_API_INVALID_ARG; // 태그 불일치
	}

	// 복호문 파일에 쓰기
	size_t written = fwrite(plaintext, 1, data_size, output_file);
	fclose(output_file);

	// 메모리 초기화 후 해제
	memset(ciphertext, 0, data_size);
	memset(plaintext, 0, data_size);
	free(ciphertext);
	free(plaintext);

	if (written != data_size) {
		return ERR_API_FILE_IO;
	}

	return SUCCESS;
}