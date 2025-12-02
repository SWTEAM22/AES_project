#include "../include/foundation.h"
#include "../include/api.h"
#include "../include/error.h"
#include "../aes/header/aes_ctr.h"
#include "../sha/header/sha.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int is_valid_aes_key_len(size_t key_len) {
    return key_len == AES_KEY_SIZE_128 ||
           key_len == AES_KEY_SIZE_192 ||
           key_len == AES_KEY_SIZE_256;
}

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

// 전체 파일 읽기
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

// 전체 파일 쓰기
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

// SHA 해시 태그 생성
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

// 기본 버전: SHA256 사용
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

// 확장 버전: 원하는 SHA 타입 사용
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
