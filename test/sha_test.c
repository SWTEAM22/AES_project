#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include "../include/api.h"
#include "../include/foundation.h"
#include "../include/error.h"
#include "../test/print.h"
#include "../sha/header/sha.h"

/**
 * @file sha_test.c
 * @brief SHA-2 해시 알고리즘 테스트 프로그램
 *
 * @details
 *   이 파일은 SHA-2 계열 해시 알고리즘의 정확성을 검증하는 테스트 프로그램이다.
 *   NIST 표준 테스트 벡터를 사용하여 SHA-224, SHA-256, SHA-384, SHA-512의
 *   해시 기능을 테스트한다.
 *
 * @author Secure Software Team
 * @date 2024
 */

#define MAX_MESSAGE_LEN 1000000
#define READ_CHUNK_SIZE 2048

typedef struct {
    const char* name;
    size_t digest_size;
    SHA2_TYPE type;
    int total;
    int passed;
    int logged_failures;
} ShaTypeInfo;

static ShaTypeInfo g_sha_info[] = {
    { "SHA-224", SHA224_DIGEST_SIZE, SHA224, 0, 0, 0 },
    { "SHA-256", SHA256_DIGEST_SIZE, SHA256, 0, 0, 0 },
    { "SHA-384", SHA384_DIGEST_SIZE, SHA384, 0, 0, 0 },
    { "SHA-512", SHA512_DIGEST_SIZE, SHA512, 0, 0, 0 },
};

/**
 * @brief SHA 테스트 통계를 초기화하는 함수
 *
 * @details
 *   모든 SHA 알고리즘 타입의 테스트 통계(총 테스트 수, 통과 수, 실패 수)를 0으로 초기화한다.
 */
static void reset_sha_stats(void) {
    for (size_t i = 0; i < sizeof(g_sha_info) / sizeof(g_sha_info[0]); i++) {
        g_sha_info[i].total = 0;
        g_sha_info[i].passed = 0;
        g_sha_info[i].logged_failures = 0;
    }
}

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
 * @brief 16진수 문자열에서 바이트를 수집하는 함수
 *
 * @details
 *   16진수 문자열을 파싱하여 바이트 배열로 변환한다.
 *   공백은 무시되며, 홀수 자릿수는 허용하지 않는다.
 *
 * @param[in]  src      파싱할 16진수 문자열
 * @param[out] dest     변환된 바이트를 저장할 배열
 * @param[in]  max_len  dest 배열의 최대 길이
 * @param[out] out_len  변환된 바이트 수
 *
 * @return bool 성공 시 true, 실패 시 false
 */
static bool collect_hex_bytes(const char* src, uint8_t* dest, size_t max_len, size_t* out_len) {
    size_t produced = 0;
    int high = -1;

    while (*src && *src != '\n' && *src != '\r') {
        unsigned char ch = (unsigned char)(*src++);
        if (isspace(ch)) continue;

        int value = hex_char_to_int((char)ch);
        if (value < 0) return false;

        if (high < 0) {
            high = value;
        } else {
            if (produced >= max_len) return false;
            dest[produced++] = (uint8_t)((high << 4) | value);
            high = -1;
        }
    }

    if (high >= 0) return false;  // 홀수 자릿수는 허용하지 않음
    *out_len = produced;
    return true;
}

/**
 * @brief 문자열의 앞뒤 공백을 제거하는 함수
 *
 * @param[in,out] str 공백을 제거할 문자열 (수정됨)
 *
 * @return char* 수정된 문자열 포인터 (입력과 동일)
 */
static char* trim(char* str) {
    if (str == NULL) return NULL;
    while (*str && isspace((unsigned char)*str)) str++;
    if (*str == '\0') return str;

    char* end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        *end-- = '\0';
    }
    return str;
}

/**
 * @brief 라인이 공백이거나 주석인지 확인하는 함수
 *
 * @param[in] line 확인할 라인 문자열
 *
 * @return bool 공백이거나 주석이면 true, 그렇지 않으면 false
 */
static bool is_blank_or_comment(const char* line) {
    return line == NULL || *line == '\0' || *line == '#';
}

/**
 * @brief 파일에서 전체 라인을 읽는 함수
 *
 * @details
 *   파일에서 한 줄을 읽되, 길이 제한 없이 전체를 읽는다.
 *   동적 메모리 할당을 사용한다.
 *
 * @param[in] file 읽을 파일 포인터
 *
 * @return char* 읽은 라인 문자열 (메모리 해제 필요), 실패 시 NULL
 *
 * @remark
 *   - 호출자는 반환된 포인터를 free()로 해제해야 한다.
 */
static char* read_full_line(FILE* file) {
    char buffer[READ_CHUNK_SIZE];
    char* result = NULL;
    size_t len = 0;

    while (fgets(buffer, sizeof(buffer), file)) {
        size_t chunk = strlen(buffer);
        bool has_newline = (chunk > 0 && buffer[chunk - 1] == '\n');
        if (has_newline) {
            buffer[--chunk] = '\0';
        }
        if (chunk > 0 && buffer[chunk - 1] == '\r') {
            buffer[--chunk] = '\0';
        }

        char* temp = realloc(result, len + chunk + 1);
        if (!temp) {
            free(result);
            return NULL;
        }
        result = temp;
        memcpy(result + len, buffer, chunk);
        len += chunk;
        result[len] = '\0';

        if (has_newline) {
            break;
        }
    }

    return result;
}

static int parse_section_header(const char* line) {
    if (!line || line[0] != '[') return -1;
    if (strstr(line, "[L = 28]")) return 0;
    if (strstr(line, "[L = 32]")) return 1;
    if (strstr(line, "[L = 48]")) return 2;
    if (strstr(line, "[L = 64]")) return 3;
    return -1;
}

static int extract_length_bits(const char* line) {
    if (!line || strncmp(line, "Len =", 5) != 0) return -1;
    line += 5;
    while (*line && isspace((unsigned char)*line)) line++;
    return atoi(line);
}

static const char* expect_field(const char* line, const char* field) {
    size_t len = strlen(field);
    if (strncmp(line, field, len) != 0) return NULL;
    const char* value = line + len;
    while (*value && isspace((unsigned char)*value)) value++;
    return value;
}

static void dump_bytes(const char* label, const uint8_t* buf, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

/**
 * @brief SHA-2 테스트 벡터 파일을 파싱하고 테스트하는 함수
 *
 * @details
 *   NIST 표준 테스트 벡터 파일을 읽어서 SHA-2 해시 알고리즘을 테스트한다.
 *   파일에서 섹션 헤더를 감지하여 SHA-224, SHA-256, SHA-384, SHA-512를 자동으로 구분한다.
 *
 * @param[in]  filename    테스트 벡터 파일 경로
 * @param[out] file_total  파일의 총 테스트 케이스 수
 * @param[out] file_pass   통과한 테스트 케이스 수
 *
 * @return int 성공 시 1, 실패 시 0
 */
static int test_sha2_file(const char* filename, int* file_total, int* file_pass) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("ERROR: 파일을 열 수 없습니다: %s\n", filename);
        return 0;
    }

    printf("\n=== %s 테스트 시작 ===\n", filename);

    int current_section = -1;
    int total_cases = 0;
    int total_pass = 0;

    while (1) {
        char* raw_line = read_full_line(file);
        if (!raw_line) break;

        char* trimmed = trim(raw_line);
        if (is_blank_or_comment(trimmed)) {
            free(raw_line);
            continue;
        }

        int section_idx = parse_section_header(trimmed);
        if (section_idx >= 0) {
            current_section = section_idx;
            printf("\n--- %s 섹션 ---\n", g_sha_info[section_idx].name);
            free(raw_line);
            continue;
        }

        int len_bits = extract_length_bits(trimmed);
        if (len_bits < 0) {
            free(raw_line);
            continue;
        }
        if (current_section < 0) {
            printf("WARN: 섹션이 지정되지 않은 Len 라인을 건너뜁니다.\n");
            free(raw_line);
            continue;
        }
        free(raw_line);

        size_t expected_bytes = (size_t)((len_bits + 7) / 8);
        if (expected_bytes > MAX_MESSAGE_LEN) {
            printf("ERROR: 메시지 길이가 MAX_MESSAGE_LEN을 초과합니다 (%zu 바이트).\n", expected_bytes);
            break;
        }

        char* msg_line_raw = read_full_line(file);
        if (!msg_line_raw) {
            printf("ERROR: Msg 라인을 읽는 중 EOF 또는 메모리 오류.\n");
            break;
        }
        char* msg_line = trim(msg_line_raw);
        const char* msg_hex = expect_field(msg_line, "Msg =");
        if (!msg_hex) {
            printf("WARN: Msg 라인을 찾지 못해 테스트를 건너뜁니다.\n");
            free(msg_line_raw);
            continue;
        }

        size_t parse_capacity = expected_bytes > 0 ? expected_bytes : 1;
        uint8_t* message_buf = expected_bytes > 0 ? (uint8_t*)malloc(expected_bytes) : NULL;
        uint8_t zero_buf[1] = {0};
        uint8_t* parse_target = expected_bytes > 0 ? message_buf : zero_buf;
        if (parse_target == NULL) {
            printf("ERROR: 메시지 버퍼 할당 실패\n");
            break;
        }

        size_t msg_bytes = 0;
        if (!collect_hex_bytes(msg_hex, parse_target, parse_capacity, &msg_bytes)) {
            printf("WARN: Msg 파싱 실패\n");
            free(message_buf);
            free(msg_line_raw);
            continue;
        }
        free(msg_line_raw);

        if (len_bits == 0) {
            if (!(msg_bytes == 0 || (msg_bytes == 1 && parse_target[0] == 0x00))) {
                printf("WARN: Len=0 이지만 Msg 데이터가 비어있지 않습니다.\n");
                free(message_buf);
                continue;
            }
            msg_bytes = 0;
        } else if (msg_bytes == 0) {
            printf("WARN: Len이 0이 아닌데 Msg가 비었습니다.\n");
            free(message_buf);
            continue;
        }

        if (msg_bytes != expected_bytes) {
            printf("WARN: Len(%d비트)과 Msg 바이트 수(%zu)가 일치하지 않습니다.\n", len_bits, msg_bytes);
            free(message_buf);
            continue;
        }

        if ((len_bits % 8) != 0 && msg_bytes > 0) {
            int unused = 8 - (len_bits % 8);
            uint8_t mask = (uint8_t)(0xFF << unused);
            parse_target[msg_bytes - 1] &= mask;
        }

        char* md_line_raw = read_full_line(file);
        if (!md_line_raw) {
            printf("ERROR: MD 라인을 읽는 중 EOF 또는 메모리 오류.\n");
            free(message_buf);
            break;
        }
        char* md_line = trim(md_line_raw);
        const char* md_hex = expect_field(md_line, "MD =");
        if (!md_hex) {
            printf("WARN: MD 라인을 찾지 못해 테스트를 건너뜁니다.\n");
            free(message_buf);
            free(md_line_raw);
            continue;
        }

        uint8_t expected_digest[SHA512_DIGEST_SIZE] = {0};
        size_t digest_bytes = 0;
        if (!collect_hex_bytes(md_hex, expected_digest, g_sha_info[current_section].digest_size, &digest_bytes) ||
            digest_bytes != g_sha_info[current_section].digest_size) {
            printf("WARN: MD 길이가 올바르지 않습니다.\n");
            free(message_buf);
            free(md_line_raw);
            continue;
        }
        free(md_line_raw);

        uint8_t computed_digest[SHA512_DIGEST_SIZE] = {0};
        const uint8_t* data_ptr = (msg_bytes > 0) ? message_buf : NULL;
        ERR_MSG err = sha2_hash(computed_digest, data_ptr, msg_bytes, g_sha_info[current_section].type);
        if (err != SUCCESS) {
            printf("ERROR: sha2_hash 실패 (코드 %d)\n", err);
            free(message_buf);
            continue;
        }

        int matched = memcmp(computed_digest, expected_digest, g_sha_info[current_section].digest_size) == 0;
        g_sha_info[current_section].total++;
        total_cases++;
        if (matched) {
            g_sha_info[current_section].passed++;
            total_pass++;
        } else if (g_sha_info[current_section].logged_failures < 2) {
            printf("[FAIL] %s Len=%d\n", g_sha_info[current_section].name, len_bits);
            dump_bytes(" Msg", parse_target, msg_bytes);
            dump_bytes(" Exp", expected_digest, g_sha_info[current_section].digest_size);
            dump_bytes(" Got", computed_digest, g_sha_info[current_section].digest_size);
            g_sha_info[current_section].logged_failures++;
        }

        free(message_buf);
    }

    fclose(file);

    if (file_total) *file_total = total_cases;
    if (file_pass) *file_pass = total_pass;

    if (total_cases > 0) {
        if (total_cases == total_pass) {
            printf("--- %s 결과: 모든 %d개 케이스 통과 ---\n", filename, total_cases);
        } else {
            printf("--- %s 결과: %d/%d 통과 (%d 실패) ---\n",
                   filename, total_pass, total_cases, total_cases - total_pass);
        }
    } else {
        printf("--- %s 결과: 처리된 테스트 케이스 없음 ---\n", filename);
    }

    return (total_cases > 0 && total_cases == total_pass) ? 1 : 0;
}

#ifdef SHA_TEST_MAIN
/**
 * @brief SHA-2 테스트 프로그램의 메인 함수
 *
 * @details
 *   SHA-2 테스트 벡터 파일들을 자동으로 찾아서 테스트를 수행한다.
 *   테스트 디렉토리에서 SHA* 테스트 벡터 파일들을 검색하여
 *   SHA-224, SHA-256, SHA-384, SHA-512 해시 알고리즘을 테스트한다.
 *
 * @return int 프로그램 종료 코드 (0: 성공, 1: 실패)
 */
int main(void) {
    printf("========================================\n");
    printf("SHA-2 테스트 벡터 파일 자동 테스트 시작\n");
    printf("========================================\n");

    const char* vector_files[] = {
        "SHA224ShortMsg.rsp",
        "SHA224LongMsg.rsp",
        "SHA256ShortMsg.rsp",
        "SHA256LongMsg.rsp",
        "SHA384ShortMsg.rsp",
        "SHA384LongMsg.rsp",
        "SHA512ShortMsg.rsp",
        "SHA512LongMsg.rsp",
    };

    const char* base_paths[] = {
        "test/tv_SHA2/",
        "../test/tv_SHA2/",
        "../../test/tv_SHA2/",
    };

    reset_sha_stats();

    int overall_cases = 0;
    int overall_pass = 0;
    int overall_success = 1;

    for (size_t i = 0; i < sizeof(vector_files) / sizeof(vector_files[0]); i++) {
        char resolved_path[512] = {0};
        int found = 0;

        for (size_t b = 0; b < sizeof(base_paths) / sizeof(base_paths[0]); b++) {
            int written = snprintf(resolved_path, sizeof(resolved_path), "%s%s", base_paths[b], vector_files[i]);
            if (written <= 0 || written >= (int)sizeof(resolved_path)) {
                continue;
            }

            FILE* probe = fopen(resolved_path, "r");
            if (probe) {
                fclose(probe);
                found = 1;
                break;
            }
        }

        if (!found) {
            printf("ERROR: 테스트 벡터 파일을 찾을 수 없습니다: %s\n", vector_files[i]);
            overall_success = 0;
            continue;
        }

        int file_cases = 0;
        int file_pass = 0;
        if (!test_sha2_file(resolved_path, &file_cases, &file_pass)) {
            overall_success = 0;
        }
        overall_cases += file_cases;
        overall_pass += file_pass;
    }

    printf("\n========================================\n");
    printf("=== SHA 타입별 테스트 결과 ===\n");
    printf("========================================\n");
    for (size_t i = 0; i < sizeof(g_sha_info) / sizeof(g_sha_info[0]); i++) {
        if (g_sha_info[i].total == 0) continue;
        if (g_sha_info[i].total == g_sha_info[i].passed) {
            printf("[PASS] %s: %d/%d 통과\n", g_sha_info[i].name, g_sha_info[i].passed, g_sha_info[i].total);
        } else {
            printf("[FAIL] %s: %d/%d 통과 (%d 실패)\n",
                   g_sha_info[i].name,
                   g_sha_info[i].passed,
                   g_sha_info[i].total,
                   g_sha_info[i].total - g_sha_info[i].passed);
        }
    }
    printf("========================================\n");
    printf("전체 테스트: %d개, 통과: %d개, 실패: %d개\n", overall_cases, overall_pass, overall_cases - overall_pass);
    printf("========================================\n");

    return (overall_success && overall_cases > 0 && overall_cases == overall_pass) ? 0 : 1;
}
#endif // !AES_TEST_MAIN
