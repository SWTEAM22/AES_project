#include "../include/foundation.h"
#include "../include/error.h"
#include "../include/api.h"
#include "./header/aes.h"



/* ---------------------------------------  Standard  S-Box  ------------------------------------------*/


static const uint8_t AES_SBOX[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
  0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
  0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
  0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
  0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};


static const uint8_t AES_INV_SBOX[256] = {
  0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
  0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
  0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
  0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
  0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
  0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
  0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
  0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
  0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
  0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
  0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
  0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
  0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
  0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
  0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
  0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};




/*----------------------------------- GF128 상에서 곱셈 연산 -------------------------------------------*/

/**
 * @brief GF(2^8) 유한체에서 x 곱셈 연산 (xtimes)
 *
 * @details
 *   - GF(2^8) 유한체에서 입력 바이트에 x(다항식 표현: 0x02)를 곱하는 연산을 수행한다.
 *   - 이는 왼쪽으로 1비트 시프트하고, 최상위 비트가 1이면 기약 다항식 0x1B와 XOR한다.
 *   - MixColumns 연산에서 사용되는 기본 연산이다.
 *
 * @param[in,out] dat 곱셈 연산을 수행할 바이트 포인터 (연산 결과가 저장됨)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_INVALID_ARG: dat가 NULL
 *
 * @remark
 *   - GF(2^8)의 기약 다항식은 x^8 + x^4 + x^3 + x + 1 (0x11B)이다.
 *   - 최상위 비트가 1이면 모듈로 감소를 위해 0x1B와 XOR한다.
 *
 * @see gf_mult()
 * @see mix_columns()
 * @see inv_mix_columns()
 */
ERR_MSG xtimes(uint8_t* dat) {
    if (dat == NULL) return ERR_API_INVALID_ARG; 
    *dat = (uint8_t)((*dat << 1) ^ ((*dat & 0x80) ? 0x1B : 0x00));
	return SUCCESS;
}
/**
 * @brief GF(2^8) 유한체에서 두 바이트의 곱셈 연산
 *
 * @details
 *   - GF(2^8) 유한체에서 두 바이트(src1, src2)를 곱하여 결과를 dst에 저장한다.
 *   - 이진 필드 곱셈 알고리즘을 사용하여 구현되었다.
 *   - MixColumns 및 InvMixColumns 연산에서 사용된다.
 *
 * @param[out] dst  곱셈 결과를 저장할 바이트 포인터
 * @param[in]  src1 곱셈할 첫 번째 바이트
 * @param[in]  src2 곱셈할 두 번째 바이트
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_INVALID_ARG: dst, src1, src2 중 하나가 NULL
 *
 * @remark
 *   - 내부적으로 xtimes() 함수를 사용하여 구현된다.
 *   - 이진 필드 곱셈은 비트 단위 연산으로 효율적으로 구현된다.
 *
 * @see xtimes()
 * @see mix_columns()
 * @see inv_mix_columns()
 */
ERR_MSG gf_mult(OUT uint8_t* dst, IN const uint8_t* src1, IN const uint8_t* src2) {
    if (dst == NULL || src1 == NULL || src2 == NULL) return ERR_API_INVALID_ARG;
    uint8_t a = src1[0], b = src2[0], res = 0;
    uint8_t temp;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) res ^= a;
        temp = a;
        xtimes(&temp);
        a = temp;
        b >>= 1;
    }
    *dst = res;

	return SUCCESS;
}

/*--------------------------------- 키확장 및 키확장 내부함수 ----------------------------------------*/

/**
 * @brief 32비트 워드에 S-box를 적용하는 함수
 *
 * @details
 *   - 32비트 워드의 각 바이트에 AES S-box를 적용한다.
 *   - 키 확장(key expansion) 과정에서 사용된다.
 *   - 워드의 4개 바이트 각각을 S-box로 치환한다.
 *
 * @param[in,out] word S-box를 적용할 32비트 워드 포인터 (결과가 저장됨)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_INVALID_ARG: word가 NULL
 *
 * @remark
 *   - 워드는 빅엔디안 형식으로 저장된다 (최상위 바이트가 먼저).
 *   - AES_SBOX 테이블을 사용하여 바이트 치환을 수행한다.
 *
 * @see rot_word()
 * @see key_expansion_inline()
 * @see AES_SBOX
 */
ERR_MSG sub_word(uint32_t* word) {
    if (word == NULL) return ERR_API_INVALID_ARG;
    uint32_t w = *word;
    uint8_t b0 = (uint8_t)(w >> 24);
    uint8_t b1 = (uint8_t)(w >> 16);
    uint8_t b2 = (uint8_t)(w >> 8);
    uint8_t b3 = (uint8_t)(w);

    b0 = AES_SBOX[b0];
    b1 = AES_SBOX[b1];
    b2 = AES_SBOX[b2];
    b3 = AES_SBOX[b3];

    *word = ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) | ((uint32_t)b2 << 8) | (uint32_t)b3;
    return SUCCESS;
}

/**
 * @brief 4바이트 워드를 왼쪽으로 1바이트 회전하는 함수
 *
 * @details
 *   - 4바이트 배열을 왼쪽으로 1바이트 순환 시프트한다.
 *   - [a, b, c, d] -> [b, c, d, a]
 *   - 키 확장(key expansion) 과정에서 사용된다.
 *
 * @param[in,out] word 회전할 4바이트 배열 포인터 (결과가 저장됨)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_INVALID_ARG: word가 NULL
 *
 * @remark
 *   - word는 최소 4바이트의 연속된 메모리를 가리켜야 한다.
 *   - RotWord 연산은 키 확장의 일부로 수행된다.
 *
 * @see sub_word()
 * @see key_expansion_inline()
 */
ERR_MSG rot_word(uint8_t* word) {
    if (word == NULL) return ERR_API_INVALID_ARG;
    uint8_t t = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = t;
    return SUCCESS;
}

/**
 * @brief AES 키 확장(키 스케줄) 함수 (인라인 구현)
 *
 * @details
 *   - AES 마스터 키를 받아 라운드 키로 확장하여 AES_KEY 구조체에 저장한다.
 *   - AES-128, AES-192, AES-256을 모두 지원한다.
 *   - 키 확장 알고리즘은 AES 표준(FIPS 197)을 따른다.
 *   - 내부적으로 sub_word(), rot_word() 함수를 사용한다.
 *
 * @param[out] key        확장된 라운드 키를 저장할 AES_KEY 구조체 포인터
 * @param[in]  master_key 마스터 키 (16/24/32바이트)
 * @param[in]  key_len    마스터 키의 길이 (바이트 단위, 16/24/32 중 하나)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_INVALID_ARG: key 또는 master_key가 NULL
 *   - ERR_AES_KEY_SCHEDULE_INVALID_KEY: 유효하지 않은 키 길이
 *
 * @remark
 *   - AES-128: 10라운드, AES-192: 12라운드, AES-256: 14라운드
 *   - 각 라운드마다 4개의 32비트 워드가 필요하므로, 총 (라운드 수 + 1) * 4개의 워드가 생성된다.
 *   - Rcon(라운드 상수) 테이블을 사용하여 키 확장을 수행한다.
 *   - AES-256의 경우 추가적인 SubWord 연산이 필요하다.
 *
 * @see sub_word()
 * @see rot_word()
 * @see key_expansion()
 */
ERR_MSG key_expansion_inline(OUT AES_KEY* key, IN const uint8_t* master_key, IN size_t key_len) {
    if (key == NULL || master_key == NULL) return ERR_API_INVALID_ARG;
    
    // 키 길이 검증 및 라운드 수 설정
    size_t nk, nr;
    if (key_len == 16) {
        nk = 4;  // 4 words
        nr = 10; // 10 rounds
    } else if (key_len == 24) {
        nk = 6;  // 6 words
        nr = 12; // 12 rounds
    } else if (key_len == 32) {
        nk = 8;  // 8 words
        nr = 14; // 14 rounds
    } else {
        return ERR_AES_KEY_SCHEDULE_INVALID_KEY;
    }
    
    key->rounds = nr;
    
    // Rcon 테이블 (라운드 상수)
    static const uint32_t Rcon[11] = {
        0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000,
        0x36000000
    };
    
    // 마스터 키를 첫 번째 라운드 키로 복사
    for (size_t i = 0; i < nk; ++i) {
        key->rd_key[i] = ((uint32_t)master_key[4 * i] << 24) |
                         ((uint32_t)master_key[4 * i + 1] << 16) |
                         ((uint32_t)master_key[4 * i + 2] << 8) |
                         ((uint32_t)master_key[4 * i + 3]);
    }
    
    // 나머지 라운드 키 생성
    for (size_t i = nk; i < 4 * (nr + 1); ++i) {
        uint32_t temp = key->rd_key[i - 1];
        
        if (i % nk == 0) {
            // RotWord, SubWord, XOR with Rcon
            uint8_t temp_bytes[4];
            temp_bytes[0] = (uint8_t)(temp >> 24);
            temp_bytes[1] = (uint8_t)(temp >> 16);
            temp_bytes[2] = (uint8_t)(temp >> 8);
            temp_bytes[3] = (uint8_t)(temp);
            
            rot_word(temp_bytes);
            
            uint32_t word = ((uint32_t)temp_bytes[0] << 24) |
                           ((uint32_t)temp_bytes[1] << 16) |
                           ((uint32_t)temp_bytes[2] << 8) |
                           ((uint32_t)temp_bytes[3]);
            
            sub_word(&word);
            temp = word ^ Rcon[i / nk];
        } else if (nk > 6 && (i % nk == 4)) {
            // AES-256의 경우 추가 SubWord
            sub_word(&temp);
        }
        
        key->rd_key[i] = key->rd_key[i - nk] ^ temp;
    }
    
    return SUCCESS;
}

/*------------------------------ AES 암호화 및 암호화 내부함수 ------------------------------------------*/

/**
 * @brief AES SubBytes 변환 함수
 *
 * @details
 *   - AES state 행렬의 각 바이트를 S-box를 사용하여 치환한다.
 *   - 이는 AES 암호화의 첫 번째 주요 단계이다.
 *   - 각 바이트는 AES_SBOX 테이블을 통해 비선형 치환된다.
 *
 * @param[in,out] state AES state 행렬 (4x4 바이트 배열, 결과가 저장됨)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_INVALID_ARG: state가 NULL
 *
 * @remark
 *   - state는 열 우선 순서로 저장된다 (state[row][col]).
 *   - S-box 치환은 AES의 비선형성을 제공한다.
 *
 * @see shift_rows()
 * @see mix_columns()
 * @see add_round_key()
 * @see aes_encrypt()
 * @see AES_SBOX
 */
ERR_MSG sub_bytes(uint8_t state[4][4]) {
    if (state == NULL) return ERR_API_INVALID_ARG;
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] = AES_SBOX[state[r][c]];
    return SUCCESS;
}

/**
 * @brief AES ShiftRows 변환 함수
 *
 * @details
 *   - AES state 행렬의 각 행을 왼쪽으로 순환 시프트한다.
 *   - Row 0: 시프트 없음 (0바이트)
 *   - Row 1: 왼쪽으로 1바이트 시프트
 *   - Row 2: 왼쪽으로 2바이트 시프트
 *   - Row 3: 왼쪽으로 3바이트 시프트 (또는 오른쪽으로 1바이트)
 *
 * @param[in,out] state AES state 행렬 (4x4 바이트 배열, 결과가 저장됨)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_INVALID_ARG: state가 NULL
 *
 * @remark
 *   - ShiftRows는 AES의 확산(diffusion) 특성을 제공한다.
 *   - 각 행이 독립적으로 시프트되므로 병렬 처리에 유리하다.
 *
 * @see sub_bytes()
 * @see mix_columns()
 * @see add_round_key()
 * @see aes_encrypt()
 */
ERR_MSG shift_rows(uint8_t state[4][4]) {
    if (state == NULL) return ERR_API_INVALID_ARG;

    uint8_t t, t0, t1;

    /* r = 1 */
    t = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = t;

    /* r = 2 */
    t0 = state[2][0]; t1 = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = t0;
    state[2][3] = t1;

    /* r = 3 (= 1칸 우회전) */
    t = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = t;

    return SUCCESS;
}

/**
 * @brief AES MixColumns 변환 함수
 *
 * @details
 *   - AES state 행렬의 각 열에 고정 행렬을 곱하여 혼합한다.
 *   - GF(2^8) 유한체에서의 행렬 곱셈을 수행한다.
 *   - 각 열은 독립적으로 처리되며, 4x4 고정 행렬과 곱해진다.
 *   - 마지막 라운드에서는 MixColumns가 생략된다.
 *
 * @param[in,out] state AES state 행렬 (4x4 바이트 배열, 결과가 저장됨)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_INVALID_ARG: state가 NULL
 *
 * @remark
 *   - MixColumns는 AES의 확산(diffusion) 특성을 강화한다.
 *   - 내부적으로 gf_mult() 함수를 사용하여 GF(2^8) 곱셈을 수행한다.
 *   - 고정 행렬 계수: {0x02, 0x03, 0x01, 0x01}, {0x01, 0x02, 0x03, 0x01}, ...
 *
 * @see gf_mult()
 * @see sub_bytes()
 * @see shift_rows()
 * @see add_round_key()
 * @see aes_encrypt()
 */
ERR_MSG mix_columns(uint8_t state[4][4]) {
    if (state == NULL) return ERR_API_INVALID_ARG;

    const uint8_t M[4][4] = {   
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}
    };

    for (int c = 0; c < 4; ++c) {
        uint8_t col0 = state[0][c], col1 = state[1][c], col2 = state[2][c], col3 = state[3][c];
        uint8_t res[4] = { 0 }, t;

        // r=0..3, k=0..3
        const uint8_t col[4] = { col0, col1, col2, col3 };
        for (int r = 0; r < 4; ++r) {
            for (int k = 0; k < 4; ++k) {
                uint8_t coef = M[r][k];
                if (coef == 0x01) res[r] ^= col[k];
                else { gf_mult(&t, &col[k], &coef); res[r] ^= t; }
            }
        }

        state[0][c] = res[0]; state[1][c] = res[1];
        state[2][c] = res[2]; state[3][c] = res[3];
    }

	return SUCCESS;
}


/**
 * @brief AES AddRoundKey 변환 함수
 *
 * @details
 *   - AES state 행렬에 라운드 키를 XOR 연산으로 더한다.
 *   - 각 라운드마다 해당하는 라운드 키를 사용한다.
 *   - 암호화와 복호화 모두에서 동일하게 사용된다.
 *
 * @param[in,out] state AES state 행렬 (4x4 바이트 배열, 결과가 저장됨)
 * @param[in]     key   확장된 AES 키 구조체
 * @param[in]     round 라운드 번호 (0부터 시작)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_INVALID_ARG: state 또는 key가 NULL
 *
 * @remark
 *   - 라운드 키는 32비트 워드 단위로 저장되며, state의 각 열과 XOR된다.
 *   - 초기 라운드(round 0)와 모든 메인 라운드에서 사용된다.
 *
 * @see sub_bytes()
 * @see shift_rows()
 * @see mix_columns()
 * @see aes_encrypt()
 * @see aes_decrypt()
 */
ERR_MSG add_round_key(uint8_t state[4][4], const AES_KEY* key, size_t round) {
    if (state == NULL || key == NULL) return ERR_API_INVALID_ARG;
    for (int c = 0; c < 4; ++c) {
        uint32_t w = key->rd_key[4 * round + c];
        state[0][c] ^= (uint8_t)(w >> 24);
        state[1][c] ^= (uint8_t)(w >> 16);
        state[2][c] ^= (uint8_t)(w >> 8);
        state[3][c] ^= (uint8_t)(w);
    }
    return SUCCESS;
}

/**
 * @brief AES 블록 암호화 함수
 *
 * @details
 *   - 16바이트 평문 블록을 AES 알고리즘으로 암호화하여 16바이트 암호문을 생성한다.
 *   - AES 표준(FIPS 197)을 따르는 전체 암호화 과정을 수행한다.
 *   - 암호화 과정: AddRoundKey(초기) -> [SubBytes -> ShiftRows -> MixColumns -> AddRoundKey] (메인 라운드) -> [SubBytes -> ShiftRows -> AddRoundKey] (마지막 라운드)
 *   - AES-128, AES-192, AES-256을 모두 지원한다.
 *
 * @param[out] ct  생성된 암호문 블록 (16바이트)
 * @param[in]  key 확장된 AES 키 구조체 (key_expansion()으로 생성됨)
 * @param[in]  pt  암호화할 평문 블록 (16바이트)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_INVALID_ARG: ct, key, pt 중 하나가 NULL
 *   - ERR_AES_ENCRYPT_INVALID_DATA: 키 라운드 수가 유효하지 않음
 *
 * @remark
 *   - 평문과 암호문은 16바이트(128비트) 고정 크기이다.
 *   - key는 key_expansion() 또는 key_expansion_inline()으로 미리 확장되어 있어야 한다.
 *   - state 행렬은 열 우선 순서로 저장되며, 입력/출력은 바이트 배열로 변환된다.
 *
 * @see key_expansion()
 * @see key_expansion_inline()
 * @see sub_bytes()
 * @see shift_rows()
 * @see mix_columns()
 * @see add_round_key()
 * @see aes_decrypt()
 */
ERR_MSG aes_encrypt(
	OUT uint8_t* ct,
	IN const AES_KEY* key,
	IN const uint8_t* pt) {
    if (ct == NULL || key == NULL || pt == NULL) return ERR_API_INVALID_ARG;
    
    // 키 라운드 수 유효성 검사
    if (key->rounds == 0 || key->rounds > MAX_ROUNDS) {
        return ERR_AES_ENCRYPT_INVALID_DATA;
    }

    uint8_t state[4][4];
    ERR_MSG err;
    
    // 평문을 state 행렬로 변환
    for (int c = 0; c < 4; ++c)
        for (int r = 0; r < 4; ++r)
            state[r][c] = pt[4 * c + r];

    // 초기 라운드 키 추가
    err = add_round_key(state, key, 0);
    if (err != SUCCESS) return err;

    // 메인 라운드 처리
    for (size_t r = 1; r <= key->rounds; ++r) {
        err = sub_bytes(state);
        if (err != SUCCESS) return err;
        
        err = shift_rows(state);
        if (err != SUCCESS) return err;
        
        // 마지막 라운드에서는 MixColumns 생략
        if (r != key->rounds) {
            err = mix_columns(state);
            if (err != SUCCESS) return err;
        }
        
        err = add_round_key(state, key, r);
        if (err != SUCCESS) return err;
    }

    // state 행렬을 암호문으로 변환
    for (int c = 0; c < 4; ++c)
        for (int r = 0; r < 4; ++r)
            ct[4 * c + r] = state[r][c];

	return SUCCESS;
}

/*------------------------------ AES 복호화 및 복호화 내부함수 ------------------------------------------*/

/**
 * @brief AES InvSubBytes 변환 함수
 *
 * @details
 *   - AES state 행렬의 각 바이트를 역 S-box를 사용하여 치환한다.
 *   - 이는 SubBytes의 역연산으로, AES 복호화의 주요 단계이다.
 *   - 각 바이트는 AES_INV_SBOX 테이블을 통해 역 비선형 치환된다.
 *
 * @param[in,out] state AES state 행렬 (4x4 바이트 배열, 결과가 저장됨)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_INVALID_ARG: state가 NULL
 *
 * @remark
 *   - state는 열 우선 순서로 저장된다 (state[row][col]).
 *   - 역 S-box 치환은 암호화의 S-box 치환을 되돌린다.
 *
 * @see inv_shift_rows()
 * @see inv_mix_columns()
 * @see add_round_key()
 * @see aes_decrypt()
 * @see AES_INV_SBOX
 */
ERR_MSG inv_sub_bytes(uint8_t state[4][4]) {
    if (state == NULL) return ERR_API_INVALID_ARG;
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] = AES_INV_SBOX[state[r][c]];
	return SUCCESS;
}
/**
 * @brief AES InvShiftRows 변환 함수
 *
 * @details
 *   - AES state 행렬의 각 행을 오른쪽으로 순환 시프트한다.
 *   - 이는 ShiftRows의 역연산으로, AES 복호화의 주요 단계이다.
 *   - Row 0: 시프트 없음 (0바이트)
 *   - Row 1: 오른쪽으로 1바이트 시프트 (또는 왼쪽으로 3바이트)
 *   - Row 2: 오른쪽으로 2바이트 시프트 (또는 왼쪽으로 2바이트)
 *   - Row 3: 오른쪽으로 3바이트 시프트 (또는 왼쪽으로 1바이트)
 *
 * @param[in,out] state AES state 행렬 (4x4 바이트 배열, 결과가 저장됨)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_INVALID_ARG: state가 NULL
 *
 * @remark
 *   - InvShiftRows는 ShiftRows의 역연산이다.
 *   - 각 행이 독립적으로 시프트되므로 병렬 처리에 유리하다.
 *
 * @see inv_sub_bytes()
 * @see inv_mix_columns()
 * @see add_round_key()
 * @see aes_decrypt()
 * @see shift_rows()
 */
ERR_MSG inv_shift_rows(uint8_t state[4][4]) {
    if (state == NULL) return ERR_API_INVALID_ARG;
    
    uint8_t t, t0, t1;
    
    // Row 1: 오른쪽으로 1바이트 회전 (shift_rows의 역연산)
    t = state[1][0];
    state[1][0] = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = t;

    // Row 2: 오른쪽으로 2바이트 회전 (shift_rows의 역연산)
    // shift_rows: [a,b,c,d] -> [c,d,a,b]
    // inv_shift_rows: [c,d,a,b] -> [a,b,c,d]
    t0 = state[2][2];  // a 저장
    t1 = state[2][3];  // b 저장
    state[2][2] = state[2][0];  // c를 뒤로
    state[2][3] = state[2][1];  // d를 뒤로
    state[2][0] = t0;  // a를 앞으로
    state[2][1] = t1;  // b를 앞으로

    // Row 3: 왼쪽으로 1바이트 회전 (오른쪽으로 3바이트 = 왼쪽으로 1바이트)
    t = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = t;
    
	return SUCCESS;
}
/**
 * @brief AES InvMixColumns 변환 함수
 *
 * @details
 *   - AES state 행렬의 각 열에 역 고정 행렬을 곱하여 혼합을 되돌린다.
 *   - GF(2^8) 유한체에서의 역 행렬 곱셈을 수행한다.
 *   - 각 열은 독립적으로 처리되며, 4x4 역 고정 행렬과 곱해진다.
 *   - 이는 MixColumns의 역연산으로, AES 복호화의 주요 단계이다.
 *
 * @param[in,out] state AES state 행렬 (4x4 바이트 배열, 결과가 저장됨)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_INVALID_ARG: state가 NULL
 *
 * @remark
 *   - InvMixColumns는 MixColumns의 역연산이다.
 *   - 내부적으로 gf_mult() 함수를 사용하여 GF(2^8) 곱셈을 수행한다.
 *   - 역 고정 행렬 계수: {0x0e, 0x0b, 0x0d, 0x09}, {0x09, 0x0e, 0x0b, 0x0d}, ...
 *
 * @see gf_mult()
 * @see inv_sub_bytes()
 * @see inv_shift_rows()
 * @see add_round_key()
 * @see aes_decrypt()
 * @see mix_columns()
 */
ERR_MSG inv_mix_columns(uint8_t state[4][4]) {
    if (state == NULL) return ERR_API_INVALID_ARG;

    const uint8_t M[4][4] = {   // 역행렬 계수
        {0x0e, 0x0b, 0x0d, 0x09},
        {0x09, 0x0e, 0x0b, 0x0d},
        {0x0d, 0x09, 0x0e, 0x0b},
        {0x0b, 0x0d, 0x09, 0x0e}
    };

    for (int c = 0; c < 4; ++c) {
        uint8_t col0 = state[0][c], col1 = state[1][c], col2 = state[2][c], col3 = state[3][c];
        uint8_t res[4] = { 0 }, t;

        const uint8_t col[4] = { col0, col1, col2, col3 };
        for (int r = 0; r < 4; ++r) {
            for (int k = 0; k < 4; ++k) {
                uint8_t coef = M[r][k];
                if (coef == 0x01) res[r] ^= col[k];
                else { gf_mult(&t, &col[k], &coef); res[r] ^= t; }
            }
        }

        state[0][c] = res[0]; state[1][c] = res[1];
        state[2][c] = res[2]; state[3][c] = res[3];
    }
	return SUCCESS;
}
// add_round_key 함수는 암호화와 동일

/**
 * @brief AES 블록 복호화 함수
 *
 * @details
 *   - 16바이트 암호문 블록을 AES 알고리즘으로 복호화하여 16바이트 평문을 생성한다.
 *   - AES 표준(FIPS 197)을 따르는 전체 복호화 과정을 수행한다.
 *   - 복호화 과정: AddRoundKey(초기, 마지막 라운드 키) -> [InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns] (메인 라운드, 역순) -> [InvShiftRows -> InvSubBytes -> AddRoundKey] (마지막 라운드, 라운드 0 키)
 *   - AES-128, AES-192, AES-256을 모두 지원한다.
 *
 * @param[out] pt  생성된 평문 블록 (16바이트)
 * @param[in]  key 확장된 AES 키 구조체 (key_expansion()으로 생성됨)
 * @param[in]  ct  복호화할 암호문 블록 (16바이트)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_API_INVALID_ARG: pt, key, ct 중 하나가 NULL
 *   - ERR_AES_DECRYPT_INVALID_DATA: 키 라운드 수가 유효하지 않음
 *
 * @remark
 *   - 평문과 암호문은 16바이트(128비트) 고정 크기이다.
 *   - key는 key_expansion() 또는 key_expansion_inline()으로 미리 확장되어 있어야 한다.
 *   - state 행렬은 열 우선 순서로 저장되며, 입력/출력은 바이트 배열로 변환된다.
 *   - 복호화는 암호화의 역순으로 수행되며, 라운드 키도 역순으로 사용된다.
 *
 * @see key_expansion()
 * @see key_expansion_inline()
 * @see inv_sub_bytes()
 * @see inv_shift_rows()
 * @see inv_mix_columns()
 * @see add_round_key()
 * @see aes_encrypt()
 */
ERR_MSG aes_decrypt(
	OUT uint8_t* pt,
	IN const AES_KEY* key,
	IN const uint8_t* ct) {
    if (pt == NULL || key == NULL || ct == NULL) return ERR_API_INVALID_ARG;
    
    // 키 라운드 수 유효성 검사
    if (key->rounds == 0 || key->rounds > MAX_ROUNDS) {
        return ERR_AES_DECRYPT_INVALID_DATA;
    }

    uint8_t state[4][4];
    ERR_MSG err;
    
    // 암호문을 state 행렬로 변환
    for (int c = 0; c < 4; ++c)
        for (int r = 0; r < 4; ++r)
            state[r][c] = ct[4 * c + r];

    // 초기 라운드 키 추가 (마지막 라운드 키)
    err = add_round_key(state, key, key->rounds);
    if (err != SUCCESS) return err;

    // 메인 라운드 처리 (역순)
    for (int r = (int)key->rounds - 1; r >= 1; --r) {
        err = inv_shift_rows(state);
        if (err != SUCCESS) return err;
        
        err = inv_sub_bytes(state);
        if (err != SUCCESS) return err;
        
        err = add_round_key(state, key, r);
        if (err != SUCCESS) return err;
        
        err = inv_mix_columns(state);
        if (err != SUCCESS) return err;
    }

    // 마지막 라운드 (MixColumns 없음)
    err = inv_shift_rows(state);
    if (err != SUCCESS) return err;
    
    err = inv_sub_bytes(state);
    if (err != SUCCESS) return err;
    
    err = add_round_key(state, key, 0);
    if (err != SUCCESS) return err;

    // state 행렬을 평문으로 변환
    for (int c = 0; c < 4; ++c)
        for (int r = 0; r < 4; ++r)
            pt[4 * c + r] = state[r][c];
    
	return SUCCESS;
}