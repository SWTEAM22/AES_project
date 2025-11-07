#include <stdio.h>
#include <string.h>
#include "../include/api.h"
#include "../include/foundation.h"
#include "../include/error.h"
#include "../test/print.h"
#include "../aes/header/aes_ctr.h"
#include "../aes/header/aes.h"

void test_gf_mult() {
    printf("=== GF(2^8) 곱셈 테스트 ===\n");
    
    uint8_t src1 = 0x57;
    uint8_t src2 = 0x83;
    uint8_t dst = 0;
    uint8_t expected = 0xc1;  // 0x57 * 0x83 = 0xc1 (GF(2^8))
    
    ERR_MSG err = gf_mult(&dst, &src1, &src2);
    
    if (err != SUCCESS) {
        printf("ERROR: gf_mult failed with error code: %04x\n", err);
        return;
    }
    
    printf("Input: 0x%02x * 0x%02x\n", src1, src2);
    printf("Result: 0x%02x\n", dst);
    printf("Expected: 0x%02x\n", expected);
    
    if (dst == expected) {
        printf("✓ GF(2^8) 곱셈 테스트 통과!\n\n");
    } else {
        printf("✗ GF(2^8) 곱셈 테스트 실패!\n\n");
    }
}

void test_aes_128() {
    printf("=== AES-128 테스트 ===\n");
    
    // NIST 표준 테스트 벡터
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t pt[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    
    uint8_t expected_ct[16] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
    };
    
    AES_KEY aes_key;
    uint8_t ct[16];
    uint8_t decrypted[16];
    
    // 키 확장
    ERR_MSG err = key_expansion(&aes_key, key, 16);
    if (err != SUCCESS) {
        printf("ERROR: key_expansion failed: %04x\n", err);
        return;
    }
    printf("키확장 성공!\n");
    // 암호화
    err = aes_encrypt(ct, &aes_key, pt);
    if (err != SUCCESS) {
        printf("ERROR: aes_encrypt failed: %04x\n", err);
        return;
    }
    
    printf("Plaintext:  ");
    print_data(pt, 16);
    printf("Ciphertext: ");
    print_data(ct, 16);
    printf("Expected:   ");
    print_data(expected_ct, 16);
    
    // 암호문 검증
    int match = 1;
    for (int i = 0; i < 16; ++i) {
        if (ct[i] != expected_ct[i]) {
            match = 0;
            break;
        }
    }
    
    if (match) {
        printf("✓ 암호화 테스트 통과!\n");
    } else {
        printf("✗ 암호화 테스트 실패!\n");
    }
    
    // 복호화
    err = aes_decrypt(decrypted, &aes_key, ct);
    if (err != SUCCESS) {
        printf("ERROR: aes_decrypt failed: %04x\n", err);
        return;
    }
    
    printf("Decrypted:  ");
    print_data(decrypted, 16);
    
    // 복호문 검증
    match = 1;
    for (int i = 0; i < 16; ++i) {
        if (decrypted[i] != pt[i]) {
            match = 0;
            break;
        }
    }
    
    if (match) {
        printf("✓ 복호화 테스트 통과!\n\n");
    } else {
        printf("✗ 복호화 테스트 실패!\n\n");
    }
}

void test_aes_192() {
    printf("=== AES-192 테스트 ===\n");
    
    // NIST 표준 테스트 벡터
    uint8_t key[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };
    
    uint8_t pt[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    
    uint8_t expected_ct[16] = {
        0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
        0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc
    };
    
    AES_KEY aes_key;
    uint8_t ct[16];
    uint8_t decrypted[16];
    
    // 키 확장
    ERR_MSG err = key_expansion(&aes_key, key, 24);
    if (err != SUCCESS) {
        printf("ERROR: key_expansion failed: %04x\n", err);
        return;
    }
    
    // 암호화
    err = aes_encrypt(ct, &aes_key, pt);
    if (err != SUCCESS) {
        printf("ERROR: aes_encrypt failed: %04x\n", err);
        return;
    }
    
    printf("Plaintext:  ");
    print_data(pt, 16);
    printf("Ciphertext: ");
    print_data(ct, 16);
    printf("Expected:   ");
    print_data(expected_ct, 16);
    
    // 암호문 검증
    int match = 1;
    for (int i = 0; i < 16; ++i) {
        if (ct[i] != expected_ct[i]) {
            match = 0;
            break;
        }
    }
    
    if (match) {
        printf("✓ 암호화 테스트 통과!\n");
    } else {
        printf("✗ 암호화 테스트 실패!\n");
    }
    
    // 복호화
    err = aes_decrypt(decrypted, &aes_key, ct);
    if (err != SUCCESS) {
        printf("ERROR: aes_decrypt failed: %04x\n", err);
        return;
    }
    
    printf("Decrypted:  ");
    print_data(decrypted, 16);
    
    // 복호문 검증
    match = 1;
    for (int i = 0; i < 16; ++i) {
        if (decrypted[i] != pt[i]) {
            match = 0;
            break;
        }
    }
    
    if (match) {
        printf("✓ 복호화 테스트 통과!\n\n");
    } else {
        printf("✗ 복호화 테스트 실패!\n\n");
    }
}

void test_aes_256() {
    printf("=== AES-256 테스트 ===\n");
    
    // NIST 표준 테스트 벡터
    uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    
    uint8_t pt[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    
    uint8_t expected_ct[16] = {
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8
    };
    
    AES_KEY aes_key;
    uint8_t ct[16];
    uint8_t decrypted[16];
    
    // 키 확장
    ERR_MSG err = key_expansion(&aes_key, key, 32);
    if (err != SUCCESS) {
        printf("ERROR: key_expansion failed: %04x\n", err);
        return;
    }
    
    // 암호화
    err = aes_encrypt(ct, &aes_key, pt);
    if (err != SUCCESS) {
        printf("ERROR: aes_encrypt failed: %04x\n", err);
        return;
    }
    
    printf("Plaintext:  ");
    print_data(pt, 16);
    printf("Ciphertext: ");
    print_data(ct, 16);
    printf("Expected:   ");
    print_data(expected_ct, 16);
    
    // 암호문 검증
    int match = 1;
    for (int i = 0; i < 16; ++i) {
        if (ct[i] != expected_ct[i]) {
            match = 0;
            break;
        }
    }
    
    if (match) {
        printf("✓ 암호화 테스트 통과!\n");
    } else {
        printf("✗ 암호화 테스트 실패!\n");
    }
    
    // 복호화
    err = aes_decrypt(decrypted, &aes_key, ct);
    if (err != SUCCESS) {
        printf("ERROR: aes_decrypt failed: %04x\n", err);
        return;
    }
    
    printf("Decrypted:  ");
    print_data(decrypted, 16);
    
    // 복호문 검증
    match = 1;
    for (int i = 0; i < 16; ++i) {
        if (decrypted[i] != pt[i]) {
            match = 0;
            break;
        }
    }
    
    if (match) {
        printf("✓ 복호화 테스트 통과!\n\n");
    } else {
        printf("✗ 복호화 테스트 실패!\n\n");
    }
}

void test_aes_ctr_128() {
    printf("=== AES-CTR-128 테스트 ===\n");
    
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t iv[16] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };
    
    uint8_t pt[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };
    
    AES_KEY aes_key;
    uint8_t ct[32];
    uint8_t decrypted[32];
    
    // 키 확장
    ERR_MSG err = key_expansion(&aes_key, key, 16);
    if (err != SUCCESS) {
        printf("ERROR: key_expansion failed: %04x\n", err);
        return;
    }
    
    // CTR 암호화
    err = aes_ctr_crypto(ct, &aes_key, pt, 32, iv);
    if (err != SUCCESS) {
        printf("ERROR: aes_ctr_crypto (encrypt) failed: %04x\n", err);
        return;
    }
    
    printf("Plaintext:  ");
    print_data(pt, 32);
    printf("Ciphertext: ");
    print_data(ct, 32);
    
    // CTR 복호화 (암호화와 동일)
    err = aes_ctr_crypto(decrypted, &aes_key, ct, 32, iv);
    if (err != SUCCESS) {
        printf("ERROR: aes_ctr_crypto (decrypt) failed: %04x\n", err);
        return;
    }
    
    printf("Decrypted:  ");
    print_data(decrypted, 32);
    
    // 복호문 검증
    int match = 1;
    for (int i = 0; i < 32; ++i) {
        if (decrypted[i] != pt[i]) {
            match = 0;
            break;
        }
    }
    
    if (match) {
        printf("✓ AES-CTR-128 테스트 통과!\n\n");
    } else {
        printf("✗ AES-CTR-128 테스트 실패!\n\n");
    }
}

void test_aes_ctr_192() {
    printf("=== AES-CTR-192 테스트 ===\n");
    
    uint8_t key[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };
    
    uint8_t iv[16] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };
    
    uint8_t pt[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };
    
    AES_KEY aes_key;
    uint8_t ct[32];
    uint8_t decrypted[32];
    
    // 키 확장
    ERR_MSG err = key_expansion(&aes_key, key, 24);
    if (err != SUCCESS) {
        printf("ERROR: key_expansion failed: %04x\n", err);
        return;
    }
    
    // CTR 암호화
    err = aes_ctr_crypto(ct, &aes_key, pt, 32, iv);
    if (err != SUCCESS) {
        printf("ERROR: aes_ctr_crypto (encrypt) failed: %04x\n", err);
        return;
    }
    
    printf("Plaintext:  ");
    print_data(pt, 32);
    printf("Ciphertext: ");
    print_data(ct, 32);
    
    // CTR 복호화 (암호화와 동일)
    err = aes_ctr_crypto(decrypted, &aes_key, ct, 32, iv);
    if (err != SUCCESS) {
        printf("ERROR: aes_ctr_crypto (decrypt) failed: %04x\n", err);
        return;
    }
    
    printf("Decrypted:  ");
    print_data(decrypted, 32);
    
    // 복호문 검증
    int match = 1;
    for (int i = 0; i < 32; ++i) {
        if (decrypted[i] != pt[i]) {
            match = 0;
            break;
        }
    }
    
    if (match) {
        printf("✓ AES-CTR-192 테스트 통과!\n\n");
    } else {
        printf("✗ AES-CTR-192 테스트 실패!\n\n");
    }
}

void test_aes_ctr_256() {
    printf("=== AES-CTR-256 테스트 ===\n");
    
    uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    
    uint8_t iv[16] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };
    
    uint8_t pt[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };
    
    AES_KEY aes_key;
    uint8_t ct[32];
    uint8_t decrypted[32];
    
    // 키 확장
    ERR_MSG err = key_expansion(&aes_key, key, 32);
    if (err != SUCCESS) {
        printf("ERROR: key_expansion failed: %04x\n", err);
        return;
    }
    
    // CTR 암호화
    err = aes_ctr_crypto(ct, &aes_key, pt, 32, iv);
    if (err != SUCCESS) {
        printf("ERROR: aes_ctr_crypto (encrypt) failed: %04x\n", err);
        return;
    }
    
    printf("Plaintext:  ");
    print_data(pt, 32);
    printf("Ciphertext: ");
    print_data(ct, 32);
    
    // CTR 복호화 (암호화와 동일)
    err = aes_ctr_crypto(decrypted, &aes_key, ct, 32, iv);
    if (err != SUCCESS) {
        printf("ERROR: aes_ctr_crypto (decrypt) failed: %04x\n", err);
        return;
    }
    
    printf("Decrypted:  ");
    print_data(decrypted, 32);
    
    // 복호문 검증
    int match = 1;
    for (int i = 0; i < 32; ++i) {
        if (decrypted[i] != pt[i]) {
            match = 0;
            break;
        }
    }
    
    if (match) {
        printf("✓ AES-CTR-256 테스트 통과!\n\n");
    } else {
        printf("✗ AES-CTR-256 테스트 실패!\n\n");
    }
}

int main() {
    printf("========================================\n");
    printf("AES 테스트 시작\n");
    printf("========================================\n\n");
    
    // GF(2^8) 곱셈 테스트
    test_gf_mult();
    
    // AES-128 테스트
    test_aes_128();
    
    // AES-192 테스트
    test_aes_192();
    
    // AES-256 테스트
    test_aes_256();
    
    // AES-CTR-128 테스트
    test_aes_ctr_128();
    
    // AES-CTR-192 테스트
    test_aes_ctr_192();
    
    // AES-CTR-256 테스트
    test_aes_ctr_256();
    
    printf("========================================\n");
    printf("모든 AES 테스트 완료\n");
    printf("========================================\n");
    
    return 0;
}
