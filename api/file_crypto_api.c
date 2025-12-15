#include "../include/foundation.h"
#include "../include/api.h"
#include "../include/error.h"
#include "../aes/header/aes_ctr.h"
#include "../sha/header/sha.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/**
 * @brief AES 키 길이 유효성 검증 함수
 *
 * @details
 *   - 입력된 키 길이가 AES 표준에서 지원하는 유효한 길이인지 확인한다.
 *   - AES는 128비트(16바이트), 192비트(24바이트), 256비트(32바이트) 키 길이를 지원한다.
 *   - 파일 암복호화 API에서 키 입력 검증 시 사용된다.
 *
 * @param[in] key_len 검증할 키 길이 (바이트 단위)
 *
 * @return int 유효한 키 길이면 1(참), 그렇지 않으면 0(거짓) 반환
 *
 * @remark
 *   - AES_KEY_SIZE_128 (16바이트), AES_KEY_SIZE_192 (24바이트), AES_KEY_SIZE_256 (32바이트)만 유효
 *   - 정적(static) 함수로 내부에서만 사용됨
 *
 * @see encrypt_file_with_tag()
 * @see decrypt_file_with_tag()
 */
static int is_valid_aes_key_len(size_t key_len) {
    return key_len == AES_KEY_SIZE_128 ||
           key_len == AES_KEY_SIZE_192 ||
           key_len == AES_KEY_SIZE_256;
}

/**
 * @brief SHA-2 알고리즘 타입에 따른 다이제스트 크기 반환 함수
 *
 * @details
 *   - SHA-2 알고리즘 타입을 입력받아 해당 알고리즘의 다이제스트 크기(바이트)를 반환한다.
 *   - 태그 생성 및 검증 시 필요한 다이제스트 크기를 결정하는 데 사용된다.
 *
 * @param[in] type SHA-2 알고리즘 타입 (SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256)
 *
 * @return size_t 다이제스트 크기 (바이트 단위), 유효하지 않은 타입이면 0 반환
 *
 * @remark
 *   - 정적(static) 함수로 내부에서만 사용됨
 *   - SHA224: 28바이트, SHA256: 32바이트, SHA384: 48바이트, SHA512: 64바이트
 *   - SHA512_224: 28바이트, SHA512_256: 32바이트
 *
 * @see compute_truncated_tag()
 * @see encrypt_file_with_tag_ex()
 * @see decrypt_file_with_tag_ex()
 */
static size_t get_sha2_digest_size(SHA2_TYPE type) {
    switch (type) {
    case SHA224:     return SHA224_DIGEST_SIZE;
    case SHA256:     return SHA256_DIGEST_SIZE;
    case SHA384:     return SHA384_DIGEST_SIZE;
    case SHA512:     return SHA512_DIGEST_SIZE;
    case SHA512_224: return SHA512_224_DIGEST_SIZE;
    case SHA512_256: return SHA512_256_DIGEST_SIZE;
    default:         return 0;
    }
}

/**
 * @brief 파일 전체를 메모리로 읽어오는 함수
 *
 * @details
 *   - 지정된 경로의 파일을 바이너리 모드로 열어 전체 내용을 메모리에 읽어온다.
 *   - 파일 크기를 먼저 확인한 후 동적 메모리를 할당하여 파일 내용을 저장한다.
 *   - 암호화/복호화 작업 전 평문 또는 암호문 파일을 읽는 데 사용된다.
 *
 * @param[in]  path   읽을 파일의 경로 (절대 경로 또는 상대 경로)
 * @param[out] buffer 파일 내용을 저장할 버퍼 포인터의 주소 (할당된 메모리 주소가 저장됨)
 * @param[out] size   읽어온 파일의 크기 (바이트 단위)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_NULL_PTR: NULL 포인터 입력
 *   - ERR_API_FILE_IO: 파일 열기/읽기 실패
 *   - ERR_API_MEMORY_ALLOC: 메모리 할당 실패
 *
 * @remark
 *   - 정적(static) 함수로 내부에서만 사용됨
 *   - 호출자는 반환된 buffer를 free()로 해제해야 함
 *   - 빈 파일(0바이트)의 경우 buffer는 NULL이 되고 size는 0이 됨
 *   - 실패 시 할당된 메모리는 자동으로 해제됨
 *
 * @see write_entire_file()
 * @see encrypt_file_with_tag_ex()
 * @see decrypt_file_with_tag_ex()
 */
static ERR_MSG read_entire_file(const char* path, uint8_t** buffer, size_t* size) {
    if (path == NULL || buffer == NULL || size == NULL) {
        return ERR_API_NULL_PTR;
    }

    FILE* fp = fopen(path, "rb");
    if (fp == NULL) {
        return ERR_API_FILE_IO;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return ERR_API_FILE_IO;
    }

    long file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        return ERR_API_FILE_IO;
    }
    rewind(fp);

    uint8_t* data = NULL;
    if (file_size > 0) {
        data = (uint8_t*)malloc((size_t)file_size);
        if (data == NULL) {
            fclose(fp);
            return ERR_API_MEMORY_ALLOC;
        }
        size_t read_bytes = fread(data, 1, (size_t)file_size, fp);
        if (read_bytes != (size_t)file_size) {
            memset(data, 0, (size_t)file_size);
            free(data);
            fclose(fp);
            return ERR_API_FILE_IO;
        }
    }

    fclose(fp);
    *buffer = data;
    *size = (size_t)file_size;
    return SUCCESS;
}

/**
 * @brief 데이터를 파일에 전체 쓰는 함수
 *
 * @details
 *   - 지정된 경로에 바이너리 모드로 파일을 생성하고 데이터를 전체 쓴다.
 *   - 기존 파일이 있으면 덮어쓰고, 없으면 새로 생성한다.
 *   - 암호화/복호화 작업 후 결과를 파일로 저장하는 데 사용된다.
 *
 * @param[in] path 저장할 파일의 경로 (절대 경로 또는 상대 경로)
 * @param[in] data 파일에 쓸 데이터 버퍼
 * @param[in] size 쓸 데이터의 크기 (바이트 단위)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_NULL_PTR: path가 NULL
 *   - ERR_API_FILE_IO: 파일 열기/쓰기 실패
 *
 * @remark
 *   - 정적(static) 함수로 내부에서만 사용됨
 *   - size가 0이면 빈 파일이 생성됨 (data는 NULL이어도 됨)
 *   - size > 0이면 data는 NULL이 아니어야 함
 *
 * @see read_entire_file()
 * @see encrypt_file_with_tag_ex()
 * @see decrypt_file_with_tag_ex()
 */
static ERR_MSG write_entire_file(const char* path, const uint8_t* data, size_t size) {
    if (path == NULL) {
        return ERR_API_NULL_PTR;
    }

    FILE* fp = fopen(path, "wb");
    if (fp == NULL) {
        return ERR_API_FILE_IO;
    }

    if (size > 0) {
        if (data == NULL || fwrite(data, 1, size, fp) != size) {
            fclose(fp);
            return ERR_API_FILE_IO;
        }
    }

    fclose(fp);
    return SUCCESS;
}

/**
 * @brief SHA-2 해시를 계산하여 지정된 길이로 자른 태그 생성 함수
 *
 * @details
 *   - 입력 데이터에 대해 SHA-2 해시를 계산하고, 결과를 지정된 길이(tag_len)로 자른다.
 *   - 태그는 파일 무결성 검증에 사용되며, 암호화 시 평문에 대해 계산된다.
 *   - 내부적으로 sha2_hash()를 호출하여 전체 다이제스트를 계산한 후 앞부분만 복사한다.
 *
 * @param[out] tag      생성된 태그를 저장할 버퍼
 * @param[in]  tag_len  생성할 태그의 길이 (바이트 단위, 다이제스트 크기 이하여야 함)
 * @param[in]  data     해시를 계산할 데이터
 * @param[in]  data_len 데이터의 길이 (바이트 단위)
 * @param[in]  tag_type 사용할 SHA-2 알고리즘 타입
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_INVALID_ARG: 잘못된 인자 (tag가 NULL, tag_len이 0이거나 다이제스트 크기 초과)
 *   - sha2_hash()에서 발생한 에러 코드
 *
 * @remark
 *   - 정적(static) 함수로 내부에서만 사용됨
 *   - tag_len은 선택한 SHA-2 타입의 다이제스트 크기 이하여야 함
 *   - 보안을 위해 내부 다이제스트 버퍼는 사용 후 0으로 초기화됨
 *
 * @see sha2_hash()
 * @see get_sha2_digest_size()
 * @see encrypt_file_with_tag_ex()
 */
static ERR_MSG compute_truncated_tag(
    OUT uint8_t* tag,
    IN  size_t tag_len,
    IN  const uint8_t* data,
    IN  size_t data_len,
    IN  SHA2_TYPE tag_type)
{
    if (tag == NULL || tag_len == 0) {
        return ERR_API_INVALID_ARG;
    }

    size_t digest_size = get_sha2_digest_size(tag_type);
    if (digest_size == 0 || tag_len > digest_size) {
        return ERR_API_INVALID_ARG;
    }

    uint8_t digest[SHA512_DIGEST_SIZE];
    const uint8_t* src = (data_len > 0) ? data : NULL;
    ERR_MSG err = sha2_hash(digest, src, data_len, tag_type);
    if (err != SUCCESS) {
        memset(digest, 0, sizeof(digest));
        return err;
    }

    memcpy(tag, digest, tag_len);
    memset(digest, 0, sizeof(digest));
    return SUCCESS;
}

/**
 * @brief 파일을 AES-CTR 모드로 암호화하고 SHA-256 태그를 생성하는 함수 (기본 버전)
 *
 * @details
 *   - 입력 파일을 AES-CTR 모드로 암호화하여 출력 파일로 저장한다.
 *   - 평문에 대해 SHA-256 해시를 계산하여 태그를 생성한다.
 *   - 이 함수는 SHA-256을 고정으로 사용하는 편의 함수이며, 내부적으로 encrypt_file_with_tag_ex()를 호출한다.
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
 * @remark
 *   - SHA-256을 고정으로 사용하므로, 다른 SHA 알고리즘이 필요하면 encrypt_file_with_tag_ex() 사용
 *   - 태그는 평문에 대해 계산되며, 파일 무결성 검증에 사용됨
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
    IN  size_t tag_len)
{
    return encrypt_file_with_tag_ex(
        input_filepath,
        key,
        key_len,
        iv,
        iv_len,
        output_filepath,
        tag,
        tag_len,
        SHA256);
}

/**
 * @brief 파일을 AES-CTR 모드로 암호화하고 지정된 SHA-2 태그를 생성하는 함수 (확장 버전)
 *
 * @details
 *   - 입력 파일을 AES-CTR 모드로 암호화하여 출력 파일로 저장한다.
 *   - 평문에 대해 지정된 SHA-2 알고리즘으로 해시를 계산하여 태그를 생성한다.
 *   - 암호화 과정: 평문 파일 읽기 → AES 키 확장 → AES-CTR 암호화 → 암호문 파일 저장
 *   - 태그 생성: 평문에 대해 SHA-2 해시 계산 → 지정된 길이로 자름
 *
 * @param[in]  input_filepath  암호화할 평문 파일 경로
 * @param[in]  key             AES 암호화 키 (16/24/32바이트)
 * @param[in]  key_len         키의 길이 (바이트 단위, 16/24/32 중 하나)
 * @param[in]  iv              초기화 벡터 (16바이트)
 * @param[in]  iv_len          IV의 길이 (16바이트)
 * @param[in]  output_filepath 암호화된 파일을 저장할 경로
 * @param[out] tag             생성된 태그를 저장할 버퍼
 * @param[in]  tag_len         태그 길이 (바이트 단위, 선택한 SHA-2 타입의 다이제스트 크기 이하)
 * @param[in]  tag_type        사용할 SHA-2 알고리즘 타입 (SHA224, SHA256, SHA384, SHA512 등)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_NULL_PTR: NULL 포인터 입력
 *   - ERR_API_INVALID_ARG: 잘못된 인자 (키 길이, IV 길이, 태그 길이 등)
 *   - ERR_API_FILE_IO: 파일 읽기/쓰기 실패
 *   - ERR_API_MEMORY_ALLOC: 메모리 할당 실패
 *   - key_expansion(), aes_ctr_crypto(), sha2_hash()에서 발생한 에러 코드
 *
 * @remark
 *   - 태그는 평문에 대해 계산되며, 복호화 시 무결성 검증에 사용됨
 *   - 보안을 위해 사용된 메모리(평문, 암호문)는 작업 후 0으로 초기화됨
 *   - 빈 파일(0바이트)도 처리 가능
 *
 * @see encrypt_file_with_tag()
 * @see decrypt_file_with_tag_ex()
 * @see key_expansion()
 * @see aes_ctr_crypto()
 * @see compute_truncated_tag()
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
    IN  SHA2_TYPE tag_type)
{
    if (input_filepath == NULL || output_filepath == NULL ||
        key == NULL || iv == NULL || tag == NULL) {
        return ERR_API_NULL_PTR;
    }

    if (!is_valid_aes_key_len(key_len) || iv_len != AES_BLOCK_SIZE) {
        return ERR_API_INVALID_ARG;
    }

    if (tag_len == 0 || tag_len > get_sha2_digest_size(tag_type)) {
        return ERR_API_INVALID_ARG;
    }

    uint8_t* plaintext = NULL;
    size_t plaintext_len = 0;
    ERR_MSG err = read_entire_file(input_filepath, &plaintext, &plaintext_len);
    if (err != SUCCESS) {
        return err;
    }

    AES_KEY aes_key;
    err = key_expansion(&aes_key, key, key_len);
    if (err != SUCCESS) {
        if (plaintext) {
            memset(plaintext, 0, plaintext_len);
            free(plaintext);
        }
        return err;
    }

    uint8_t* ciphertext = NULL;
    if (plaintext_len > 0) {
        ciphertext = (uint8_t*)malloc(plaintext_len);
        if (ciphertext == NULL) {
            memset(plaintext, 0, plaintext_len);
            free(plaintext);
            return ERR_API_MEMORY_ALLOC;
        }

        err = aes_ctr_crypto(ciphertext, &aes_key, plaintext, plaintext_len, iv);
        if (err != SUCCESS) {
            memset(ciphertext, 0, plaintext_len);
            free(ciphertext);
            memset(plaintext, 0, plaintext_len);
            free(plaintext);
            return err;
        }
    }

    err = write_entire_file(output_filepath, ciphertext, plaintext_len);
    if (err != SUCCESS) {
        if (ciphertext) {
            memset(ciphertext, 0, plaintext_len);
            free(ciphertext);
        }
        if (plaintext) {
            memset(plaintext, 0, plaintext_len);
            free(plaintext);
        }
        return err;
    }

    err = compute_truncated_tag(tag, tag_len, plaintext, plaintext_len, tag_type);
    if (ciphertext) {
        memset(ciphertext, 0, plaintext_len);
        free(ciphertext);
    }
    if (plaintext) {
        memset(plaintext, 0, plaintext_len);
        free(plaintext);
    }
    return err;
}

/**
 * @brief AES-CTR 모드로 암호화된 파일을 복호화하고 SHA-256 태그를 검증하는 함수 (기본 버전)
 *
 * @details
 *   - 암호화된 파일을 AES-CTR 모드로 복호화하여 평문 파일로 저장한다.
 *   - 복호화된 평문에 대해 SHA-256 해시를 계산하여 기대 태그와 비교하여 무결성을 검증한다.
 *   - 이 함수는 SHA-256을 고정으로 사용하는 편의 함수이며, 내부적으로 decrypt_file_with_tag_ex()를 호출한다.
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
 *   - ERR_API_INVALID_DATA: 태그 검증 실패 (파일이 변조되었거나 잘못된 키/IV 사용)
 *
 * @remark
 *   - SHA-256을 고정으로 사용하므로, 다른 SHA 알고리즘이 필요하면 decrypt_file_with_tag_ex() 사용
 *   - 태그 검증 실패 시 복호화된 파일은 저장되지 않음
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
    IN  const char* output_filepath,
    IN  const uint8_t* expected_tag,
    IN  size_t tag_len)
{
    return decrypt_file_with_tag_ex(
        input_filepath,
        key,
        key_len,
        iv,
        iv_len,
        output_filepath,
        expected_tag,
        tag_len,
        SHA256);
}

/**
 * @brief AES-CTR 모드로 암호화된 파일을 복호화하고 지정된 SHA-2 태그를 검증하는 함수 (확장 버전)
 *
 * @details
 *   - 암호화된 파일을 AES-CTR 모드로 복호화하여 평문 파일로 저장한다.
 *   - 복호화된 평문에 대해 지정된 SHA-2 알고리즘으로 해시를 계산하여 기대 태그와 비교한다.
 *   - 복호화 과정: 암호문 파일 읽기 → AES 키 확장 → AES-CTR 복호화
 *   - 태그 검증: 복호화된 평문에 대해 SHA-2 해시 계산 → 기대 태그와 비교
 *   - 태그가 일치하지 않으면 파일이 변조되었거나 잘못된 키/IV가 사용된 것으로 간주하여 복호화 실패
 *
 * @param[in] input_filepath  복호화할 암호문 파일 경로
 * @param[in] key             AES 복호화 키 (16/24/32바이트)
 * @param[in] key_len         키의 길이 (바이트 단위, 16/24/32 중 하나)
 * @param[in] iv              초기화 벡터 (16바이트)
 * @param[in] iv_len          IV의 길이 (16바이트)
 * @param[in] output_filepath 복호화된 평문 파일을 저장할 경로
 * @param[in] expected_tag    기대하는 태그 (선택한 SHA-2 타입의 다이제스트 크기 이하)
 * @param[in] tag_len         태그 길이 (바이트 단위)
 * @param[in] tag_type        사용할 SHA-2 알고리즘 타입 (암호화 시 사용한 타입과 동일해야 함)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_NULL_PTR: NULL 포인터 입력
 *   - ERR_API_INVALID_ARG: 잘못된 인자 (키 길이, IV 길이, 태그 길이 등)
 *   - ERR_API_FILE_IO: 파일 읽기/쓰기 실패
 *   - ERR_API_MEMORY_ALLOC: 메모리 할당 실패
 *   - ERR_API_INVALID_DATA: 태그 검증 실패 (파일 변조 또는 잘못된 키/IV)
 *   - key_expansion(), aes_ctr_crypto(), sha2_hash()에서 발생한 에러 코드
 *
 * @remark
 *   - 태그 검증 실패 시 복호화된 파일은 저장되지 않음
 *   - 보안을 위해 사용된 메모리(평문, 암호문, 태그)는 작업 후 0으로 초기화됨
 *   - 암호화 시 사용한 SHA-2 타입과 동일한 타입을 사용해야 함
 *   - 빈 파일(0바이트)도 처리 가능
 *
 * @see decrypt_file_with_tag()
 * @see encrypt_file_with_tag_ex()
 * @see key_expansion()
 * @see aes_ctr_crypto()
 * @see sha2_hash()
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
    IN  SHA2_TYPE tag_type)
{
    if (input_filepath == NULL || output_filepath == NULL ||
        key == NULL || iv == NULL || expected_tag == NULL) {
        return ERR_API_NULL_PTR;
    }

    if (!is_valid_aes_key_len(key_len) || iv_len != AES_BLOCK_SIZE) {
        return ERR_API_INVALID_ARG;
    }

    size_t digest_size = get_sha2_digest_size(tag_type);
    if (digest_size == 0 || tag_len == 0 || tag_len > digest_size) {
        return ERR_API_INVALID_ARG;
    }

    uint8_t* ciphertext = NULL;
    size_t ciphertext_len = 0;
    ERR_MSG err = read_entire_file(input_filepath, &ciphertext, &ciphertext_len);
    if (err != SUCCESS) {
        return err;
    }

    AES_KEY aes_key;
    err = key_expansion(&aes_key, key, key_len);
    if (err != SUCCESS) {
        if (ciphertext) {
            memset(ciphertext, 0, ciphertext_len);
            free(ciphertext);
        }
        return err;
    }

    uint8_t* plaintext = NULL;
    if (ciphertext_len > 0) {
        plaintext = (uint8_t*)malloc(ciphertext_len);
        if (plaintext == NULL) {
            memset(ciphertext, 0, ciphertext_len);
            free(ciphertext);
            return ERR_API_MEMORY_ALLOC;
        }

        err = aes_ctr_crypto(plaintext, &aes_key, ciphertext, ciphertext_len, iv);
        if (err != SUCCESS) {
            memset(plaintext, 0, ciphertext_len);
            free(plaintext);
            memset(ciphertext, 0, ciphertext_len);
            free(ciphertext);
            return err;
        }
    }

    uint8_t computed_tag[SHA512_DIGEST_SIZE];
    const uint8_t* hash_input = (ciphertext_len > 0) ? plaintext : NULL;
    err = sha2_hash(computed_tag, hash_input, ciphertext_len, tag_type);
    if (err != SUCCESS) {
        if (plaintext) {
            memset(plaintext, 0, ciphertext_len);
            free(plaintext);
        }
        if (ciphertext) {
            memset(ciphertext, 0, ciphertext_len);
            free(ciphertext);
        }
        memset(computed_tag, 0, sizeof(computed_tag));
        return err;
    }

    if (memcmp(computed_tag, expected_tag, tag_len) != 0) {
        if (plaintext) {
            memset(plaintext, 0, ciphertext_len);
            free(plaintext);
        }
        if (ciphertext) {
            memset(ciphertext, 0, ciphertext_len);
            free(ciphertext);
        }
        memset(computed_tag, 0, sizeof(computed_tag));
        return ERR_API_INVALID_DATA;
    }
    memset(computed_tag, 0, sizeof(computed_tag));

    err = write_entire_file(output_filepath, plaintext, ciphertext_len);

    if (plaintext) {
        memset(plaintext, 0, ciphertext_len);
        free(plaintext);
    }
    if (ciphertext) {
        memset(ciphertext, 0, ciphertext_len);
        free(ciphertext);
    }
    return err;
}
