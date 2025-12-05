#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "include/foundation.h"
#include "include/api.h"
#include "include/error.h"

// 간단한 헥스 문자열 → 바이트 변환
static int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex_string(const char* hex, uint8_t* out, size_t out_capacity, size_t* out_len) {
    size_t produced = 0;
    int high = -1;

    while (*hex) {
        unsigned char ch = (unsigned char)(*hex++);
        if (isspace(ch)) continue;

        int v = hex_char_to_int((char)ch);
        if (v < 0) return 0;

        if (high < 0) {
            high = v;
        } else {
            if (produced >= out_capacity) return 0;
            out[produced++] = (uint8_t)((high << 4) | v);
            high = -1;
        }
    }

    if (high >= 0) return 0; // 홀수 자릿수 허용 안 함
    if (out_len) *out_len = produced;
    return 1;
}

static void print_usage(const char* prog) {
    printf("Usage:\n");
    printf("  Encrypt: %s enc <in_file> <out_file> <key_hex> <iv_hex> <tag_file>\n", prog);
    printf("  Decrypt: %s dec <in_file> <out_file> <key_hex> <iv_hex> <tag_file>\n", prog);
    printf("\n");
    printf("  - key_hex : AES key in hex (32/48/64 hex chars for 128/192/256-bit keys)\n");
    printf("  - iv_hex  : IV in hex (32 hex chars = 16 bytes)\n");
    printf("  - tag_file: path to save/load authentication tag (SHA-256, 32 bytes)\n");
}

// 태그 파일 입출력 (그냥 바이너리로 32바이트 저장/로드)
static int write_tag_file(const char* path, const uint8_t* tag, size_t tag_len) {
    FILE* fp = fopen(path, "wb");
    if (!fp) return 0;
    if (fwrite(tag, 1, tag_len, fp) != tag_len) {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}

static int read_tag_file(const char* path, uint8_t* tag, size_t tag_len) {
    FILE* fp = fopen(path, "rb");
    if (!fp) return 0;
    size_t r = fread(tag, 1, tag_len, fp);
    fclose(fp);
    return r == tag_len;
}

#ifdef FILE_CRYPTO

static void read_line(char* buf, size_t size) {
    if (fgets(buf, (int)size, stdin)) {
        size_t len = strlen(buf);
        if (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
            buf[len - 1] = '\0';
            if (len > 1 && buf[len - 2] == '\r') {
                buf[len - 2] = '\0';
            }
        }
    } else {
        if (size > 0) buf[0] = '\0';
    }
}

int main(void) {
    char mode[8];
    char in_path[260];
    char out_path[260];
    char key_hex[129];   // 최대 64 hex + 널
    char iv_hex[65];     // 32 hex + 널
    char tag_path[260];

    printf("=== File Encrypt/Decrypt with AES-CTR + SHA-256 Tag ===\n");

    // 모드 입력 및 검증
    while (1) {
        printf("Mode (enc/dec): ");
        read_line(mode, sizeof(mode));
        if (strcmp(mode, "enc") == 0 || strcmp(mode, "dec") == 0) break;
        printf("ERROR: invalid mode. Please enter \"enc\" or \"dec\".\n");
    }

    // 입력 파일 경로
    while (1) {
        printf("Input file path : ");
        read_line(in_path, sizeof(in_path));
        if (in_path[0] != '\0') break;
        printf("ERROR: input file path cannot be empty.\n");
    }

    // 출력 파일 경로
    while (1) {
        printf("Output file path: ");
        read_line(out_path, sizeof(out_path));
        if (out_path[0] != '\0') break;
        printf("ERROR: output file path cannot be empty.\n");
    }

    // 키 입력 및 즉시 검증/파싱
    uint8_t key_buf[32];  // 최대 AES-256 (32 bytes)
    size_t key_len = 0;
    while (1) {
        printf("AES key (hex, 32/48/64 chars): ");
        read_line(key_hex, sizeof(key_hex));
        key_len = 0;
        if (!parse_hex_string(key_hex, key_buf, sizeof(key_buf), &key_len)) {
            printf("ERROR: invalid key hex string. Please try again.\n");
            continue;
        }
        if (key_len != 16 && key_len != 24 && key_len != 32) {
            printf("ERROR: key must be 16/24/32 bytes (32/48/64 hex chars). Current: %zu bytes.\n", key_len);
            continue;
        }
        break;
    }

    // IV 입력 및 즉시 검증/파싱
    uint8_t iv_buf[16];   // 16 bytes
    size_t iv_len = 0;
    while (1) {
        printf("IV (hex, 32 chars = 16 bytes): ");
        read_line(iv_hex, sizeof(iv_hex));
        iv_len = 0;
        if (!parse_hex_string(iv_hex, iv_buf, sizeof(iv_buf), &iv_len)) {
            printf("ERROR: invalid IV hex string. Please try again.\n");
            continue;
        }
        if (iv_len != 16) {
            printf("ERROR: IV must be 16 bytes (32 hex chars). Current: %zu bytes.\n", iv_len);
            continue;
        }
        break;
    }

    // 태그 파일 경로
    while (1) {
        printf("Tag file path   : ");
        read_line(tag_path, sizeof(tag_path));
        if (tag_path[0] != '\0') break;
        printf("ERROR: tag file path cannot be empty.\n");
    }

    const char* mode_str = mode;

    // SHA-256 기반 태그 (32 bytes)
    uint8_t tag[SHA256_DIGEST_SIZE];
    size_t tag_len = SHA256_DIGEST_SIZE;
    ERR_MSG err;

    if (strcmp(mode_str, "enc") == 0) {
        // 파일 암호화 + 태그 생성
        err = encrypt_file_with_tag_ex(
            in_path,
            key_buf,
            key_len,
            iv_buf,
            iv_len,
            out_path,
            tag,
            tag_len,
            SHA256
        );
        if (err != SUCCESS) {
            printf("Encrypt failed: 0x%04X\n", err);
            print_error_details(err);
            return 1;
        }

        if (!write_tag_file(tag_path, tag, tag_len)) {
            printf("ERROR: failed to write tag file: %s\n", tag_path);
            return 1;
        }

        printf("Encryption OK.\n");
        printf("  Input : %s\n", in_path);
        printf("  Output: %s\n", out_path);
        printf("  Tag   : %s (SHA-256, %zu bytes)\n", tag_path, tag_len);
        return 0;

    } else if (strcmp(mode_str, "dec") == 0) {
        // 태그 파일에서 expected_tag 읽기
        if (!read_tag_file(tag_path, tag, tag_len)) {
            printf("ERROR: failed to read tag file: %s\n", tag_path);
            return 1;
        }

        err = decrypt_file_with_tag_ex(
            in_path,
            key_buf,
            key_len,
            iv_buf,
            iv_len,
            out_path,
            tag,
            tag_len,
            SHA256
        );

        if (err == ERR_API_INVALID_DATA) {
            printf("Decrypt failed: TAG MISMATCH (data may be tampered)\n");
            return 1;
        } else if (err != SUCCESS) {
            printf("Decrypt failed: 0x%04X\n", err);
            print_error_details(err);
            return 1;
        }

        printf("Decryption OK.\n");
        printf("  Input : %s\n", in_path);
        printf("  Output: %s\n", out_path);
        printf("  Tag   : %s (verified)\n", tag_path);
        return 0;

    } else {
        printf("ERROR: invalid mode (use \"enc\" or \"dec\")\n");
        return 1;
    }
}

#endif // !FILE_CRYPTO