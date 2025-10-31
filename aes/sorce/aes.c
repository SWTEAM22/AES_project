#include "../include/foundation.h"
#include "../include/error.h"
#include "../include/api.h"
#include "./header/aes.h"



/* ---------------------------------------  STandard  S-Box  ------------------------------------------*/


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

/*-----------------------------------------    SubBytes 함수   ----------------------------------------- */
ERR_MSG sub_bytes(uint8_t state[4][4]) {
    if (!state) return ERR_API_INVALID_ARG;
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            state[r][c] = AES_SBOX[state[r][c]];
    return SUCCESS;
}

/* -----------------------------------------    ShiftRows 함수   --------------------------------------*/
ERR_MSG shift_rows(uint8_t state[4][4]) {
    if (!state) return ERR_API_INVALID_ARG;

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

/*--------------------------------------------   AddRoundKey  -------------------------------------------- */


ERR_MSG add_round_key(uint8_t state[4][4], const AES_KEY* key) {
    if (!state || !key) return ERR_API_INVALID_ARG;
    for (int c = 0; c < 4; ++c) {
        uint32_t w = key->rd_key[c];
        state[0][c] ^= (uint8_t)(w >> 24);
        state[1][c] ^= (uint8_t)(w >> 16);
        state[2][c] ^= (uint8_t)(w >> 8);
        state[3][c] ^= (uint8_t)(w);
    }
    return SUCCESS;
}

/*--------------------------------------------    SubWord   ---------------------------------------------- */


ERR_MSG sub_word(uint32_t* word) {
    if (!word) return ERR_API_INVALID_ARG;
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

/*---------------------------------------------  RotWord  ----------------------------------------------- */
ERR_MSG rot_word(uint8_t* word) {
    if (!word) return ERR_API_INVALID_ARG;
    uint8_t t = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = t;
    return SUCCESS;
}


/*----------------------------------- GF128 상에서 곱셈 연산 -------------------------------------------*/

ERR_MSG xtimes(uint8_t* dat) {
	return SUCCESS;
}
ERR_MSG gf_mult(OUT uint8_t* dst, IN const uint8_t* src1, IN const uint8_t* src2) {
	return SUCCESS;
}

/*--------------------------------- 키확장 및 키확장 내부함수 ----------------------------------------*/

ERR_MSG sub_word(uint32_t* word) {
	return SUCCESS;
}

ERR_MSG rot_word(uint8_t* word) {
	return SUCCESS;
}

ERR_MSG key_expansion(OUT AES_KEY* key, IN const uint8_t* master_key, IN size_t key_len) {
	return SUCCESS;
}

/*------------------------------ AES 암호화 및 암호화 내부함수 ------------------------------------------*/

ERR_MSG sub_bytes(uint8_t state[4][4]) {
	return SUCCESS;
}

ERR_MSG shift_rows(uint8_t state[4][4]) {
	return SUCCESS;
}

ERR_MSG mix_columns(uint8_t state[4][4]) {
	return SUCCESS;
}

ERR_MSG add_round_key(uint8_t state[4][4], const AES_KEY* key) {
	return SUCCESS;
}

ERR_MSG aes_encrypt(
	OUT uint8_t* ct,
	IN const AES_KEY* key,
	IN const uint8_t* pt) {
	return SUCCESS;
}

/*------------------------------ AES 복호화 및 복호화 내부함수 ------------------------------------------*/

ERR_MSG inv_sub_bytes(uint8_t state[4][4]) {
	return SUCCESS;
}
ERR_MSG inv_shift_rows(uint8_t state[4][4]) {
	return SUCCESS;
}
ERR_MSG inv_mix_columns(uint8_t state[4][4]) {
	return SUCCESS;
}
// add_round_key 함수는 암호화와 동일

ERR_MSG aes_decrypt(
	OUT uint8_t* pt,
	IN const AES_KEY* key,
	IN const uint8_t* ct) {
	return SUCCESS;
}