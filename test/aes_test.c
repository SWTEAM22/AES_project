#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#endif
#include "../include/api.h"
#include "../include/foundation.h"
#include "../include/error.h"
#include "../test/print.h"
#include "../aes/header/aes_ctr.h"
#include "../aes/header/aes.h"

/**
 * @file aes_test.c
 * @brief AES 알고리즘 테스트 프로그램
 *
 * @details
 *   이 파일은 AES 암호화 알고리즘의 정확성을 검증하는 테스트 프로그램이다.
 *   NIST 표준 테스트 벡터를 사용하여 AES-128, AES-192, AES-256의
 *   암호화 및 복호화 기능을 테스트한다.
 *
 * @author Secure Software Team
 * @date 2024
 */

#define MAX_LINE_LEN 2048
#define MAX_FILES 20

/**
 * @brief 16진수 문자를 숫자로 변환하는 함수
 *
 * @param[in] c 변환할 16진수 문자 ('0'-'9', 'a'-'f', 'A'-'F')
 *
 * @return int 변환된 숫자 (0-15), 유효하지 않은 문자면 -1
 */
static int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * @brief 공백으로 구분된 16진수 문자열을 바이트 배열로 변환하는 함수
 *
 * @details
 *   공백으로 구분된 16진수 문자열을 파싱하여 바이트 배열로 변환한다.
 *   예: "2B 7E 15 16" -> [0x2B, 0x7E, 0x15, 0x16]
 *
 * @param[in]  str      파싱할 16진수 문자열
 * @param[out] output   변환된 바이트를 저장할 배열
 * @param[in]  max_len  output 배열의 최대 길이
 *
 * @return int 변환된 바이트 수
 */
static int parse_hex_string_spaced(const char* str, uint8_t* output, size_t max_len) {
    int count = 0;
    const char* p = str;
    
    while (*p && count < (int)max_len) {
        // 공백 건너뛰기
        while (*p && isspace(*p)) p++;
        if (!*p) break;
        
        // 16진수 2자리 읽기
        int high = hex_char_to_int(*p++);
        if (high < 0) break;
        
        int low = hex_char_to_int(*p++);
        if (low < 0) break;
        
        output[count++] = (uint8_t)((high << 4) | low);
        
        // 다음 공백 건너뛰기
        while (*p && isspace(*p)) p++;
    }
    
    return count;
}

/**
 * @brief 공백 없는 16진수 문자열을 바이트 배열로 변환하는 함수
 *
 * @details
 *   공백 없이 연속된 16진수 문자열을 파싱하여 바이트 배열로 변환한다.
 *   예: "2b7e1516" -> [0x2B, 0x7E, 0x15, 0x16]
 *
 * @param[in]  str      파싱할 16진수 문자열
 * @param[out] output   변환된 바이트를 저장할 배열
 * @param[in]  max_len  output 배열의 최대 길이
 *
 * @return int 변환된 바이트 수
 */
static int parse_hex_string_compact(const char* str, uint8_t* output, size_t max_len) {
    int count = 0;
    const char* p = str;
    
    while (*p && count < (int)max_len) {
        // 공백 건너뛰기
        while (*p && isspace(*p)) p++;
        if (!*p) break;
        
        // 16진수 2자리 읽기
        int high = hex_char_to_int(*p++);
        if (high < 0) break;
        
        if (!*p) break;
        int low = hex_char_to_int(*p++);
        if (low < 0) break;
        
        output[count++] = (uint8_t)((high << 4) | low);
    }
    
    return count;
}

/**
 * @brief 데이터를 레이블과 함께 출력하는 함수
 *
 * @param[in] label 출력할 레이블
 * @param[in] data  출력할 데이터
 * @param[in] len   데이터 길이 (바이트 단위)
 */
static void print_bytes(const char* label, const uint8_t* data, size_t len) {
    if (!label || !data) return;
    printf("%s (%zu bytes):\n", label, len);
    print_data(data, len);
    printf("\n");
}

/**
 * @brief 파일에서 특정 접두사로 시작하는 라인을 찾는 함수
 *
 * @param[in] file   검색할 파일 포인터
 * @param[in] prefix 찾을 접두사 문자열
 *
 * @return const char* 찾은 라인 문자열, 없으면 NULL
 *
 * @remark
 *   - 반환된 포인터는 다음 호출 전까지만 유효하다 (정적 버퍼 사용).
 *   - 파일을 처음부터 검색한다 (rewind 수행).
 */
static const char* find_line_with_prefix(FILE* file, const char* prefix) {
    static char line_storage[MAX_LINE_LEN];
    rewind(file);
    
    while (fgets(line_storage, sizeof(line_storage), file)) {
        if (strncmp(line_storage, prefix, strlen(prefix)) == 0) {
            return line_storage;
        }
    }
    return NULL;
}

/**
 * @brief AES-128/192/256 테스트 벡터 파일을 파싱하고 테스트하는 함수
 *
 * @details
 *   NIST 표준 테스트 벡터 파일을 읽어서 AES 암호화 및 복호화를 테스트한다.
 *   파일명에서 키 길이를 자동으로 감지한다 (128/192/256).
 *
 * @param[in] filename 테스트 벡터 파일 경로
 *
 * @return int 성공한 테스트 케이스 수, 실패 시 0
 */
static int test_aes_ecb_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("ERROR: 파일을 열 수 없습니다: %s\n", filename);
        return 0;
    }
    
    printf("\n=== %s 테스트 ===\n", filename);
    
    // MASTERKEY 찾기
    rewind(file);
    char line[MAX_LINE_LEN];
    int found_key = 0;
    int key_len = 16;
    if (strstr(filename, "192")) key_len = 24;
    else if (strstr(filename, "256")) key_len = 32;
    
    uint8_t key[32];
    int key_bytes = 0;
    
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "MASTERKEY", 9) == 0) {
            found_key = 1;
            const char* key_start = strstr(line, "MASTERKEY");
            if (key_start) key_start += strlen("MASTERKEY");
            else key_start = line;
            
            int bytes = parse_hex_string_spaced(key_start, key, key_len);
            key_bytes += bytes;
            
            // 키가 두 줄에 걸쳐 있는 경우 (192, 256)
            if (key_bytes < key_len) {
                if (fgets(line, sizeof(line), file)) {
                    // 공백으로 시작하는 줄인지 확인 (연속된 키 데이터)
                    const char* p = line;
                    while (*p && isspace(*p)) p++;
                    if (*p && hex_char_to_int(*p) >= 0) {
                        int bytes2 = parse_hex_string_spaced(p, key + key_bytes, key_len - key_bytes);
                        key_bytes += bytes2;
                    }
                }
            }
            break;
        }
    }
    
    if (!found_key || key_bytes != key_len) {
        printf("ERROR: MASTERKEY를 찾을 수 없거나 키 파싱 실패 (예상: %d, 실제: %d)\n", key_len, key_bytes);
        fclose(file);
        return 0;
    }
    
    // MESSAGE 찾기
    const char* msg_line = find_line_with_prefix(file, "MESSAGE");
    if (!msg_line) {
        printf("ERROR: MESSAGE를 찾을 수 없습니다.\n");
        fclose(file);
        return 0;
    }
    
    uint8_t pt[16];
    const char* msg_start = strstr(msg_line, "MESSAGE");
    if (msg_start) msg_start += strlen("MESSAGE");
    else msg_start = msg_line;
    
    int pt_bytes = parse_hex_string_spaced(msg_start, pt, 16);
    if (pt_bytes != 16) {
        printf("ERROR: 평문 파싱 실패 (예상: 16, 실제: %d)\n", pt_bytes);
        fclose(file);
        return 0;
    }
    
    // CIPHERTEXT 찾기
    const char* ct_line = find_line_with_prefix(file, "CIPHERTEXT");
    if (!ct_line) {
        printf("ERROR: CIPHERTEXT를 찾을 수 없습니다.\n");
        fclose(file);
        return 0;
    }
    
    uint8_t expected_ct[16];
    const char* ct_start = strstr(ct_line, "CIPHERTEXT");
    if (ct_start) ct_start += strlen("CIPHERTEXT");
    else ct_start = ct_line;
    
    int ct_bytes = parse_hex_string_spaced(ct_start, expected_ct, 16);
    if (ct_bytes != 16) {
        printf("ERROR: 암호문 파싱 실패 (예상: 16, 실제: %d)\n", ct_bytes);
        fclose(file);
        return 0;
    }
    
    fclose(file);
    
    // AES 테스트 수행
    AES_KEY aes_key;
    uint8_t ct[16];
    uint8_t decrypted[16];
    
    print_bytes("Master Key", key, key_len);
    print_bytes("Plaintext", pt, 16);
    print_bytes("Expected Ciphertext", expected_ct, 16);
    
    // 키 확장
    ERR_MSG err = key_expansion(&aes_key, key, key_len);
    if (err != SUCCESS) {
        printf("ERROR: key_expansion failed: %04x\n", err);
        return 0;
    }
    
    // 암호화
    err = aes_encrypt(ct, &aes_key, pt);
    if (err != SUCCESS) {
        printf("ERROR: aes_encrypt failed: %04x\n", err);
        return 0;
    }
    print_bytes("Ciphertext (Computed)", ct, 16);
    
    // 암호문 검증
    int encrypt_match = (memcmp(ct, expected_ct, 16) == 0);
    
    if (!encrypt_match) {
        printf("✗ 암호화 테스트 실패!\n");
        printf("Expected: ");
        print_data(expected_ct, 16);
        printf("Got:      ");
        print_data(ct, 16);
    } else {
        printf("✓ 암호화 테스트 통과!\n");
    }
    
    // 복호화
    err = aes_decrypt(decrypted, &aes_key, ct);
    if (err != SUCCESS) {
        printf("ERROR: aes_decrypt failed: %04x\n", err);
        return 0;
    }
    
    // 복호문 검증
    int decrypt_match = (memcmp(decrypted, pt, 16) == 0);
    
    if (!decrypt_match) {
        printf("✗ 복호화 테스트 실패!\n");
        printf("Expected: ");
        print_data(pt, 16);
        printf("Got:      ");
        print_data(decrypted, 16);
    } else {
        printf("✓ 복호화 테스트 통과!\n");
    }
    print_bytes("Decrypted Plaintext", decrypted, 16);
    
    return encrypt_match && decrypt_match;
}

// AES-CTR 테스트 벡터 파일 파싱 및 테스트
static int test_aes_ctr_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("ERROR: 파일을 열 수 없습니다: %s\n", filename);
        return 0;
    }
    
    printf("\n=== %s 테스트 ===\n", filename);
    
    // [Key] 찾기
    rewind(file);
    char line[MAX_LINE_LEN];
    const char* key_line = NULL;
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "[Key]", 5) == 0) {
            key_line = line;
            break;
        }
    }
    
    if (!key_line) {
        printf("ERROR: [Key]를 찾을 수 없습니다.\n");
        fclose(file);
        return 0;
    }
    
    // 키 길이 결정
    int key_len = 16;
    if (strstr(filename, "192")) key_len = 24;
    else if (strstr(filename, "256")) key_len = 32;
    
    uint8_t key[32];
    // [Key] 뒤의 공백을 건너뛰고 16진수 문자열 시작 위치 찾기
    const char* key_start = strstr(key_line, "[Key]");
    if (key_start) {
        key_start += 5;  // "[Key]" 길이만큼 이동
        // 공백 건너뛰기
        while (*key_start && isspace(*key_start)) key_start++;
    } else {
        printf("ERROR: [Key] 태그를 찾을 수 없습니다.\n");
        fclose(file);
        return 0;
    }
    
    // 개행 문자 제거
    char key_str[256];
    int key_str_len = 0;
    const char* p_key = key_start;
    while (*p_key && *p_key != '\n' && *p_key != '\r' && key_str_len < 255) {
        if (!isspace(*p_key) || hex_char_to_int(*p_key) >= 0) {
            key_str[key_str_len++] = *p_key;
        }
        p_key++;
    }
    key_str[key_str_len] = '\0';
    
    int key_bytes = parse_hex_string_compact(key_str, key, key_len);
    if (key_bytes != key_len) {
        printf("ERROR: 키 파싱 실패 (예상: %d, 실제: %d)\n", key_len, key_bytes);
        printf("DEBUG: 파싱한 키 문자열: '%s'\n", key_str);
        fclose(file);
        return 0;
    }
    
    // [Init. Counter] 찾기
    rewind(file);
    const char* iv_line = NULL;
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "[Init. Counter]", 15) == 0) {
            iv_line = line;
            break;
        }
    }
    
    if (!iv_line) {
        printf("ERROR: [Init. Counter]를 찾을 수 없습니다.\n");
        fclose(file);
        return 0;
    }
    
    uint8_t iv[16];
    const char* iv_start = strstr(iv_line, "[Init. Counter]");
    if (iv_start) {
        iv_start += 15;  // "[Init. Counter]" 길이만큼 이동
        while (*iv_start && isspace(*iv_start)) iv_start++;
    } else {
        printf("ERROR: [Init. Counter] 태그를 찾을 수 없습니다.\n");
        fclose(file);
        return 0;
    }
    
    // 개행 문자 제거
    char iv_str[256];
    int iv_str_len = 0;
    const char* p_iv = iv_start;
    while (*p_iv && *p_iv != '\n' && *p_iv != '\r' && iv_str_len < 255) {
        if (!isspace(*p_iv) || hex_char_to_int(*p_iv) >= 0) {
            iv_str[iv_str_len++] = *p_iv;
        }
        p_iv++;
    }
    iv_str[iv_str_len] = '\0';
    
    int iv_bytes = parse_hex_string_compact(iv_str, iv, 16);
    if (iv_bytes != 16) {
        printf("ERROR: IV 파싱 실패 (예상: 16, 실제: %d)\n", iv_bytes);
        printf("DEBUG: 파싱한 IV 문자열: '%s'\n", iv_str);
        fclose(file);
        return 0;
    }
    
    // [Plaintext] 찾기 (Encrypt 섹션)
    rewind(file);
    const char* pt_line = NULL;
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "[Plaintext]", 11) == 0) {
            pt_line = line;
            break;
        }
    }
    
    if (!pt_line) {
        printf("ERROR: [Plaintext]를 찾을 수 없습니다.\n");
        fclose(file);
        return 0;
    }
    
    // 평문 시작 위치 찾기
    const char* pt_start = strstr(pt_line, "[Plaintext]");
    if (pt_start) {
        pt_start += 11;  // "[Plaintext]" 길이만큼 이동
        while (*pt_start && isspace(*pt_start)) pt_start++;
    } else {
        printf("ERROR: [Plaintext] 태그를 찾을 수 없습니다.\n");
        fclose(file);
        return 0;
    }
    
    // 평문 길이 계산 (16진수 문자 개수 세기)
    int pt_len = 0;
    const char* p_pt = pt_start;
    while (*p_pt && *p_pt != '\n' && *p_pt != '\r') {
        if (hex_char_to_int(*p_pt) >= 0) pt_len++;
        p_pt++;
    }
    pt_len /= 2;  // 2자리당 1바이트
    
    if (pt_len == 0 || pt_len > 256) {
        printf("ERROR: 평문 길이가 유효하지 않습니다: %d\n", pt_len);
        fclose(file);
        return 0;
    }
    
    uint8_t* pt = (uint8_t*)malloc(pt_len);
    if (!pt) {
        printf("ERROR: 메모리 할당 실패\n");
        fclose(file);
        return 0;
    }
    
    // 개행 문자 제거한 평문 문자열
    char pt_str[512];
    int pt_str_len = 0;
    p_pt = pt_start;
    while (*p_pt && *p_pt != '\n' && *p_pt != '\r' && pt_str_len < 511) {
        if (!isspace(*p_pt) || hex_char_to_int(*p_pt) >= 0) {
            pt_str[pt_str_len++] = *p_pt;
        }
        p_pt++;
    }
    pt_str[pt_str_len] = '\0';
    
    int pt_bytes = parse_hex_string_compact(pt_str, pt, pt_len);
    if (pt_bytes != pt_len) {
        printf("ERROR: 평문 파싱 실패 (예상: %d, 실제: %d)\n", pt_len, pt_bytes);
        printf("DEBUG: 파싱한 평문 문자열 길이: %d\n", pt_str_len);
        free(pt);
        fclose(file);
        return 0;
    }
    
    // [Ciphertext] 찾기 (Encrypt 섹션)
    rewind(file);
    const char* ct_line = NULL;
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "[Ciphertext]", 12) == 0) {
            ct_line = line;
            break;
        }
    }
    
    if (!ct_line) {
        printf("ERROR: [Ciphertext]를 찾을 수 없습니다.\n");
        free(pt);
        fclose(file);
        return 0;
    }
    
    const char* ct_start = strstr(ct_line, "[Ciphertext]");
    if (ct_start) {
        ct_start += 12;  // "[Ciphertext]" 길이만큼 이동
        while (*ct_start && isspace(*ct_start)) ct_start++;
    } else {
        printf("ERROR: [Ciphertext] 태그를 찾을 수 없습니다.\n");
        free(pt);
        fclose(file);
        return 0;
    }
    
    uint8_t* expected_ct = (uint8_t*)malloc(pt_len);
    if (!expected_ct) {
        printf("ERROR: 메모리 할당 실패\n");
        free(pt);
        fclose(file);
        return 0;
    }
    
    // 개행 문자 제거한 암호문 문자열
    char ct_str[512];
    int ct_str_len = 0;
    const char* p_ct = ct_start;
    while (*p_ct && *p_ct != '\n' && *p_ct != '\r' && ct_str_len < 511) {
        if (!isspace(*p_ct) || hex_char_to_int(*p_ct) >= 0) {
            ct_str[ct_str_len++] = *p_ct;
        }
        p_ct++;
    }
    ct_str[ct_str_len] = '\0';
    
    int ct_bytes = parse_hex_string_compact(ct_str, expected_ct, pt_len);
    if (ct_bytes != pt_len) {
        printf("ERROR: 암호문 파싱 실패 (예상: %d, 실제: %d)\n", pt_len, ct_bytes);
        printf("DEBUG: 파싱한 암호문 문자열 길이: %d\n", ct_str_len);
        free(pt);
        free(expected_ct);
        fclose(file);
        return 0;
    }
    
    fclose(file);
    
    // AES-CTR 테스트 수행
    AES_KEY aes_key;
    uint8_t* ct = (uint8_t*)malloc(pt_len);
    uint8_t* decrypted = (uint8_t*)malloc(pt_len);
    
    if (!ct || !decrypted) {
        printf("ERROR: 메모리 할당 실패\n");
        free(pt);
        free(expected_ct);
        if (ct) free(ct);
        if (decrypted) free(decrypted);
        return 0;
    }
    
    // 키 확장
    ERR_MSG err = key_expansion(&aes_key, key, key_len);
    if (err != SUCCESS) {
        printf("ERROR: key_expansion failed: %04x\n", err);
        free(pt);
        free(expected_ct);
        free(ct);
        free(decrypted);
        return 0;
    }
    
    print_bytes("Key", key, key_len);
    print_bytes("IV", iv, AES_BLOCK_SIZE);
    print_bytes("Plaintext", pt, pt_len);
    print_bytes("Expected Ciphertext", expected_ct, pt_len);
    
    // CTR 암호화
    err = aes_ctr_crypto(ct, &aes_key, pt, pt_len, iv);
    if (err != SUCCESS) {
        printf("ERROR: aes_ctr_crypto (encrypt) failed: %04x\n", err);
        free(pt);
        free(expected_ct);
        free(ct);
        free(decrypted);
        return 0;
    }
    print_bytes("Ciphertext (Computed)", ct, pt_len);
    
    // 암호문 검증
    int encrypt_match = (memcmp(ct, expected_ct, pt_len) == 0);
    
    if (!encrypt_match) {
        printf("✗ 암호화 테스트 실패!\n");
        printf("Expected: ");
        print_data(expected_ct, pt_len);
        printf("Got:      ");
        print_data(ct, pt_len);
    } else {
        printf("✓ 암호화 테스트 통과!\n");
    }
    
    // CTR 복호화
    err = aes_ctr_crypto(decrypted, &aes_key, ct, pt_len, iv);
    if (err != SUCCESS) {
        printf("ERROR: aes_ctr_crypto (decrypt) failed: %04x\n", err);
        free(pt);
        free(expected_ct);
        free(ct);
        free(decrypted);
        return 0;
    }
    
    // 복호문 검증
    int decrypt_match = (memcmp(decrypted, pt, pt_len) == 0);
    
    if (!decrypt_match) {
        printf("✗ 복호화 테스트 실패!\n");
        printf("Expected: ");
        print_data(pt, pt_len);
        printf("Got:      ");
        print_data(decrypted, pt_len);
    } else {
        printf("✓ 복호화 테스트 통과!\n");
    }
    print_bytes("Decrypted Plaintext", decrypted, pt_len);
    
    free(pt);
    free(expected_ct);
    free(ct);
    free(decrypted);
    
    return encrypt_match && decrypt_match;
}

// test 폴더에서 모든 tv_*.txt 파일 찾기
static int find_test_vector_files(char files[][256], int max_files) {
    int count = 0;
    
    // 하드코딩된 테스트 벡터 파일 목록 (6개)
    const char* known_files[] = {
        "test/tv_aes128.txt",
        "test/tv_aes192.txt",
        "test/tv_aes256.txt",
        "test/tv_aes-ctr128.txt",
        "test/tv_aes-ctr192.txt",
        "test/tv_aes-ctr256.txt"
    };
    
    // 먼저 하드코딩된 파일 목록 확인 (파일 존재 여부 확인)
    for (int i = 0; i < 6 && count < max_files; i++) {
        FILE* f = fopen(known_files[i], "r");
        if (f) {
            fclose(f);
            snprintf(files[count], 256, "%s", known_files[i]);
            count++;
        } else {
            // Windows 경로로 재시도
#ifdef _WIN32
            char win_path[256];
            snprintf(win_path, 256, "%s", known_files[i]);
            // '/'를 '\\'로 변경
            for (char* p = win_path; *p; p++) {
                if (*p == '/') *p = '\\';
            }
            f = fopen(win_path, "r");
            if (f) {
                fclose(f);
                snprintf(files[count], 256, "%s", win_path);
                count++;
            }
#endif
        }
    }
    
    // 하드코딩된 파일을 찾지 못한 경우 동적 검색 시도
    if (count == 0) {
#ifdef _WIN32
        WIN32_FIND_DATA findData;
        HANDLE hFind = FindFirstFile("test\\tv_*.txt", &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    if (count < max_files) {
                        snprintf(files[count], 256, "test\\%s", (const char*)findData.cFileName);
                        count++;
                    }
                }
            } while (FindNextFile(hFind, &findData) != 0);
            FindClose(hFind);
        }
        
        // 파일을 찾지 못한 경우 상대 경로로 재시도
        if (count == 0) {
            hFind = FindFirstFile("tv_*.txt", &findData);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        if (count < max_files) {
                            snprintf(files[count], 256, "%s", (const char*)findData.cFileName);
                            count++;
                        }
                    }
                } while (FindNextFile(hFind, &findData) != 0);
                FindClose(hFind);
            }
        }
#else
        DIR* dir = opendir("test");
        if (dir) {
            struct dirent* entry;
            while ((entry = readdir(dir)) != NULL && count < max_files) {
                if (strncmp(entry->d_name, "tv_", 3) == 0 && 
                    strstr(entry->d_name, ".txt") != NULL) {
                    snprintf(files[count], 256, "test/%s", entry->d_name);
                    count++;
                }
            }
            closedir(dir);
        }
        
        // 파일을 찾지 못한 경우 현재 디렉토리에서 재시도
        if (count == 0) {
            dir = opendir(".");
            if (dir) {
                struct dirent* entry;
                while ((entry = readdir(dir)) != NULL && count < max_files) {
                    if (strncmp(entry->d_name, "tv_", 3) == 0 && 
                        strstr(entry->d_name, ".txt") != NULL) {
                        snprintf(files[count], 256, "%s", entry->d_name);
                        count++;
                    }
                }
                closedir(dir);
            }
        }
#endif
    }
    
    return count;
}

#ifdef AES_TEST_MAIN
/**
 * @brief AES 테스트 프로그램의 메인 함수
 *
 * @details
 *   AES 테스트 벡터 파일들을 자동으로 찾아서 테스트를 수행한다.
 *   테스트 디렉토리에서 tv_aes*.txt 파일들을 검색하여
 *   AES-128, AES-192, AES-256 암호화 및 복호화를 테스트한다.
 *
 * @return int 프로그램 종료 코드 (0: 성공, 1: 실패)
 */
int main() {
    printf("========================================\n");
    printf("AES 테스트 벡터 파일 자동 테스트 시작\n");
    printf("========================================\n");
    
    char files[MAX_FILES][256];
    int file_count = find_test_vector_files(files, MAX_FILES);
    
    if (file_count == 0) {
        printf("ERROR: 테스트 벡터 파일을 찾을 수 없습니다.\n");
        printf("test 폴더에 tv_*.txt 파일이 있는지 확인하세요.\n");
        return 1;
    }
    
    printf("\n발견된 테스트 벡터 파일: %d개\n", file_count);
    for (int i = 0; i < file_count; i++) {
        printf("  - %s\n", files[i]);
    }
    printf("\n");
    
    int total_tests = 0;
    int passed_tests = 0;
    
    for (int i = 0; i < file_count; i++) {
        if (strstr(files[i], "ctr")) {
            // CTR 모드 테스트
            if (test_aes_ctr_file(files[i])) {
                passed_tests++;
            }
        } else {
            // ECB 모드 테스트 (AES-128/192/256)
            if (test_aes_ecb_file(files[i])) {
                passed_tests++;
            }
        }
        total_tests++;
    }
    
    printf("\n========================================\n");
    printf("테스트 결과: %d/%d 통과\n", passed_tests, total_tests);
    printf("========================================\n");
    
    return (passed_tests == total_tests) ? 0 : 1;
}
#endif // AES_TEST_MAIN
