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

ERR_MSG xtimes(uint8_t* dat) {
    if (dat == NULL) return ERR_API_INVALID_ARG; 
    *dat = (uint8_t)((*dat << 1) ^ ((*dat & 0x80) ? 0x1B : 0x00));
	return SUCCESS;
}
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

ERR_MSG rot_word(uint8_t* word) {
    if (word == NULL) return ERR_API_INVALID_ARG;
    uint8_t t = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = t;
    return SUCCESS;
}

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

ERR_MSG sub_bytes(uint8_t state[4][4]) {
    if (state == NULL) return ERR_API_INVALID_ARG;
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] = AES_SBOX[state[r][c]];
    return SUCCESS;
}

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

ERR_MSG inv_sub_bytes(uint8_t state[4][4]) {
    if (state == NULL) return ERR_API_INVALID_ARG;
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] = AES_INV_SBOX[state[r][c]];
	return SUCCESS;
}
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