#include "../include/foundation.h"
#include "../include/error.h"
#include "../include/api.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/**
 * @file sha.c
 * @brief SHA-2 해시 알고리즘 구현
 *
 * @details
 *   이 파일은 SHA-2 계열 해시 알고리즘(SHA-224, SHA-256, SHA-384, SHA-512,
 *   SHA-512/224, SHA-512/256)의 구현을 포함한다.
 *
 * @author Secure Software Team
 * @date 2024
 * @see sha.h
 */

/*=====================================================================
 *  SHA-224 / SHA-256 IMPLEMENTATION
 *=====================================================================*/

/**
 * @brief 32비트 값을 오른쪽으로 순환 시프트하는 함수
 *
 * @param[in] x 시프트할 32비트 값
 * @param[in] n 시프트할 비트 수
 *
 * @return uint32_t 시프트된 32비트 값
 */
static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

/**
 * @brief SHA-256 Choice 함수 (ch)
 *
 * @param[in] x 첫 번째 32비트 값
 * @param[in] y 두 번째 32비트 값
 * @param[in] z 세 번째 32비트 값
 *
 * @return uint32_t (x & y) ^ (~x & z)
 */
static uint32_t ch32(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }

/**
 * @brief SHA-256 Majority 함수 (maj)
 *
 * @param[in] x 첫 번째 32비트 값
 * @param[in] y 두 번째 32비트 값
 * @param[in] z 세 번째 32비트 값
 *
 * @return uint32_t (x & y) ^ (x & z) ^ (y & z)
 */
static uint32_t maj32(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }

/**
 * @brief SHA-256 Sigma0 함수 (σ0)
 *
 * @param[in] x 입력 32비트 값
 *
 * @return uint32_t ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22)
 */
static uint32_t sigma0_32(uint32_t x) { return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22); }

/**
 * @brief SHA-256 Sigma1 함수 (σ1)
 *
 * @param[in] x 입력 32비트 값
 *
 * @return uint32_t ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25)
 */
static uint32_t sigma1_32(uint32_t x) { return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25); }

/**
 * @brief SHA-256 Gamma0 함수 (γ0)
 *
 * @param[in] x 입력 32비트 값
 *
 * @return uint32_t ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3)
 */
static uint32_t gamma0_32(uint32_t x) { return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3); }

/**
 * @brief SHA-256 Gamma1 함수 (γ1)
 *
 * @param[in] x 입력 32비트 값
 *
 * @return uint32_t ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10)
 */
static uint32_t gamma1_32(uint32_t x) { return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10); }

/** @brief SHA-256 라운드 상수 K (64개) */
static const uint32_t K256[64] = {
    0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
    0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
    0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
    0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
    0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
    0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
    0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
    0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

/**
 * @brief SHA-256 계열 공통 처리 함수 (SHA-224, SHA-256)
 *
 * @details
 *   SHA-224와 SHA-256의 공통 처리 로직을 수행한다.
 *   초기 해시 값과 출력 길이만 다르게 설정하여 각 알고리즘을 구현한다.
 *   SHA-256 표준(FIPS 180-4)을 따른다.
 *
 * @param[out] digest   계산된 해시 다이제스트를 저장할 버퍼
 * @param[in]  data     해시를 계산할 입력 데이터
 * @param[in]  data_len 입력 데이터의 길이 (바이트 단위)
 * @param[in]  iv       초기 해시 값 (8개의 32비트 워드)
 * @param[in]  out_len  출력 다이제스트 길이 (바이트 단위, 28 또는 32)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_SHA_HASH_NULL_PTR: digest 또는 iv가 NULL
 *   - ERR_SHA_HASH_INVALID_DATA: 잘못된 입력 데이터 또는 출력 길이
 *   - ERR_SHA_HASH_FAIL: 메모리 할당 실패
 *
 * @remark
 *   - 입력 데이터는 패딩되어 512비트(64바이트) 블록 단위로 처리된다.
 *   - 보안을 위해 사용된 메모리는 작업 후 0으로 초기화된다.
 *
 * @see sha224_hash()
 * @see sha256_hash()
 */
static ERR_MSG sha256_process(
    OUT uint8_t* digest,
    IN  const uint8_t* data,
    IN  size_t data_len,
    IN  const uint32_t* iv,
    IN  size_t out_len)
{
    if (digest == NULL) return ERR_SHA_HASH_NULL_PTR;
    if (data == NULL && data_len != 0) return ERR_SHA_HASH_INVALID_DATA;
    if (iv == NULL) return ERR_SHA_HASH_NULL_PTR;
    if (out_len == 0 || out_len > SHA256_DIGEST_SIZE) return ERR_SHA_HASH_INVALID_DATA;

    uint32_t h[8]; memcpy(h, iv, sizeof(h));

    size_t pad_len = (SHA256_BLOCK_SIZE - ((data_len + 9) % SHA256_BLOCK_SIZE)) % SHA256_BLOCK_SIZE;
    size_t total = data_len + 1 + pad_len + 8;
    uint8_t* msg = malloc(total);
    if (msg == NULL) return ERR_SHA_HASH_FAIL;

    if (data_len > 0) {
        memcpy(msg, data, data_len);
    }
    msg[data_len] = 0x80;
    memset(msg + data_len + 1, 0, pad_len);
    uint64_t bits = (uint64_t)data_len * 8;
    // 길이 필드를 big-endian으로 저장 (최상위 바이트부터)
    for (int i = 0; i < 8; i++) {
        msg[total - 8 + i] = (uint8_t)((bits >> (56 - i * 8)) & 0xFF);
    }

    for (size_t chunk = 0; chunk < total; chunk += SHA256_BLOCK_SIZE) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)msg[chunk + i * 4] << 24) |
            ((uint32_t)msg[chunk + i * 4 + 1] << 16) |
            ((uint32_t)msg[chunk + i * 4 + 2] << 8) |
            ((uint32_t)msg[chunk + i * 4 + 3]);
        for (int i = 16; i < 64; i++)
            w[i] = gamma1_32(w[i - 2]) + w[i - 7] + gamma0_32(w[i - 15]) + w[i - 16];

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + sigma1_32(e) + ch32(e, f, g) + K256[i] + w[i];
            uint32_t t2 = sigma0_32(a) + maj32(a, b, c);
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    for (size_t i = 0; i < out_len; i++)
        digest[i] = (uint8_t)(h[i / 4] >> (8 * (3 - (i % 4))));

    // 메모리 초기화 후 해제 (보안)
    memset(msg, 0, total);
    memset(h, 0, sizeof(h));
    free(msg);
    return SUCCESS;
}

/**
 * @brief SHA-224 해시 함수
 *
 * @details
 *   입력 데이터에 대해 SHA-224 해시를 계산하여 28바이트 다이제스트를 생성한다.
 *   SHA-224는 SHA-256과 동일한 알고리즘을 사용하지만, 다른 초기 해시 값과
 *   출력 길이(28바이트)를 사용한다.
 *
 * @param[out] digest   계산된 SHA-224 다이제스트를 저장할 버퍼 (28바이트)
 * @param[in]  data     해시를 계산할 입력 데이터
 * @param[in]  len      입력 데이터의 길이 (바이트 단위)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see sha256_hash()
 * @see sha256_process()
 */
ERR_MSG sha224_hash(OUT uint8_t* digest, IN const uint8_t* data, IN size_t len) {
    static const uint32_t IV[8] = {
        0xc1059ed8UL,0x367cd507UL,0x3070dd17UL,0xf70e5939UL,
        0xffc00b31UL,0x68581511UL,0x64f98fa7UL,0xbefa4fa4UL
    };
    return sha256_process(digest, data, len, IV, 28);
}

/**
 * @brief SHA-256 해시 함수
 *
 * @details
 *   입력 데이터에 대해 SHA-256 해시를 계산하여 32바이트 다이제스트를 생성한다.
 *   SHA-256은 가장 널리 사용되는 SHA-2 알고리즘이다.
 *
 * @param[out] digest   계산된 SHA-256 다이제스트를 저장할 버퍼 (32바이트)
 * @param[in]  data     해시를 계산할 입력 데이터
 * @param[in]  len      입력 데이터의 길이 (바이트 단위)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see sha224_hash()
 * @see sha256_process()
 */
ERR_MSG sha256_hash(OUT uint8_t* digest, IN const uint8_t* data, IN size_t len) {
    static const uint32_t IV[8] = {
        0x6a09e667UL,0xbb67ae85UL,0x3c6ef372UL,0xa54ff53aUL,
        0x510e527fUL,0x9b05688cUL,0x1f83d9abUL,0x5be0cd19UL
    };
    return sha256_process(digest, data, len, IV, 32);
}

/*=====================================================================
 *  SHA-512 계열 (원본 그대로 유지)
 *=====================================================================*/

/**
 * @brief 64비트 값을 오른쪽으로 순환 시프트하는 함수
 *
 * @param[in] x 시프트할 64비트 값
 * @param[in] n 시프트할 비트 수
 *
 * @return uint64_t 시프트된 64비트 값
 */
static uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

/**
 * @brief SHA-512 Choice 함수 (ch)
 *
 * @param[in] x 첫 번째 64비트 값
 * @param[in] y 두 번째 64비트 값
 * @param[in] z 세 번째 64비트 값
 *
 * @return uint64_t (x & y) ^ (~x & z)
 */
static uint64_t ch(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }

/**
 * @brief SHA-512 Majority 함수 (maj)
 *
 * @param[in] x 첫 번째 64비트 값
 * @param[in] y 두 번째 64비트 값
 * @param[in] z 세 번째 64비트 값
 *
 * @return uint64_t (x & y) ^ (x & z) ^ (y & z)
 */
static uint64_t maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }

/**
 * @brief SHA-512 Sigma0 함수 (σ0)
 *
 * @param[in] x 입력 64비트 값
 *
 * @return uint64_t ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39)
 */
static uint64_t sigma0(uint64_t x) { return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39); }

/**
 * @brief SHA-512 Sigma1 함수 (σ1)
 *
 * @param[in] x 입력 64비트 값
 *
 * @return uint64_t ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41)
 */
static uint64_t sigma1(uint64_t x) { return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41); }

/**
 * @brief SHA-512 Gamma0 함수 (γ0)
 *
 * @param[in] x 입력 64비트 값
 *
 * @return uint64_t ROTR(x, 1) ^ ROTR(x, 8) ^ (x >> 7)
 */
static uint64_t gamma0(uint64_t x) { return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7); }

/**
 * @brief SHA-512 Gamma1 함수 (γ1)
 *
 * @param[in] x 입력 64비트 값
 *
 * @return uint64_t ROTR(x, 19) ^ ROTR(x, 61) ^ (x >> 6)
 */
static uint64_t gamma1(uint64_t x) { return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6); }

/** @brief SHA-512 라운드 상수 K (80개) */
static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

/**
 * @brief SHA-512 변환 함수 (단일 블록 처리)
 *
 * @details
 *   SHA-512의 메인 변환 함수로, 1024비트(128바이트) 블록을 처리하여
 *   상태(state)를 업데이트한다.
 *
 * @param[in,out] state SHA-512 상태 배열 (8개의 64비트 워드, 업데이트됨)
 * @param[in]     block 처리할 128바이트 블록
 *
 * @remark
 *   - 내부적으로 80라운드를 수행한다.
 *   - 보안을 위해 사용된 메모리(w 배열)는 작업 후 0으로 초기화된다.
 */
static void sha512_transform(uint64_t state[8], const uint8_t* block) {
    uint64_t w[80];

    for (int i = 0; i < 16; i++) {
        int idx = i * 8;
        w[i] = ((uint64_t)block[idx] << 56) |
               ((uint64_t)block[idx + 1] << 48) |
               ((uint64_t)block[idx + 2] << 40) |
               ((uint64_t)block[idx + 3] << 32) |
               ((uint64_t)block[idx + 4] << 24) |
               ((uint64_t)block[idx + 5] << 16) |
               ((uint64_t)block[idx + 6] << 8) |
               ((uint64_t)block[idx + 7]);
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = gamma0(w[i - 15]);
        uint64_t s1 = gamma1(w[i - 2]);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint64_t a = state[0];
    uint64_t b = state[1];
    uint64_t c = state[2];
    uint64_t d = state[3];
    uint64_t e = state[4];
    uint64_t f = state[5];
    uint64_t g = state[6];
    uint64_t h = state[7];

    for (int i = 0; i < 80; i++) {
        uint64_t t1 = h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
        uint64_t t2 = sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
    memset(w, 0, sizeof(w));
}

/**
 * @brief SHA-512 계열 공통 처리 함수 (SHA-384, SHA-512, SHA-512/224, SHA-512/256)
 *
 * @details
 *   SHA-512 계열 알고리즘의 공통 처리 로직을 수행한다.
 *   초기 해시 값과 출력 길이만 다르게 설정하여 각 알고리즘을 구현한다.
 *   SHA-512 표준(FIPS 180-4)을 따른다.
 *
 * @param[out] digest       계산된 해시 다이제스트를 저장할 버퍼
 * @param[in]  data         해시를 계산할 입력 데이터
 * @param[in]  data_len     입력 데이터의 길이 (바이트 단위)
 * @param[in]  initial_hash 초기 해시 값 (8개의 64비트 워드)
 * @param[in]  output_len   출력 다이제스트 길이 (바이트 단위)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_SHA_HASH_NULL_PTR: digest 또는 initial_hash가 NULL
 *   - ERR_SHA_HASH_INVALID_DATA: 잘못된 입력 데이터 또는 출력 길이
 *   - ERR_SHA_HASH_FAIL: 메모리 할당 실패
 *
 * @remark
 *   - 입력 데이터는 패딩되어 1024비트(128바이트) 블록 단위로 처리된다.
 *   - 보안을 위해 사용된 메모리는 작업 후 0으로 초기화된다.
 *
 * @see sha384_hash()
 * @see sha512_hash()
 * @see sha512_224_hash()
 * @see sha512_256_hash()
 * @see sha512_transform()
 */
ERR_MSG sha512_process(
    OUT uint8_t* digest,
    IN  const uint8_t* data,
    IN  size_t data_len,
    IN  const uint64_t* initial_hash,
    IN  size_t output_len)
{
    if (digest == NULL) return ERR_SHA_HASH_NULL_PTR;
    if (data == NULL && data_len != 0) return ERR_SHA_HASH_INVALID_DATA;
    if (initial_hash == NULL) return ERR_SHA_HASH_NULL_PTR;
    if (output_len == 0 || output_len > SHA512_DIGEST_SIZE) return ERR_SHA_HASH_INVALID_DATA;

    uint64_t state[8];
    memcpy(state, initial_hash, sizeof(uint64_t) * 8);

    size_t pad_len = (SHA512_BLOCK_SIZE - ((data_len + 1 + 16) % SHA512_BLOCK_SIZE)) % SHA512_BLOCK_SIZE;
    size_t total_len = data_len + 1 + pad_len + 16;
    uint8_t* buffer = (uint8_t*)malloc(total_len);
    if (buffer == NULL) return ERR_SHA_HASH_FAIL;

    if (data_len > 0 && data != NULL) {
        memcpy(buffer, data, data_len);
    }
    buffer[data_len] = 0x80;
    memset(buffer + data_len + 1, 0, pad_len + 16);

    uint64_t bit_len_low = ((uint64_t)data_len) << 3;
    uint64_t bit_len_high = ((uint64_t)data_len) >> 61;


    uint8_t* length_ptr = buffer + total_len - 16;
    for (int i = 0; i < 8; i++) {
        length_ptr[i] = (uint8_t)((bit_len_high >> (56 - i * 8)) & 0xFF);
        length_ptr[8 + i] = (uint8_t)((bit_len_low >> (56 - i * 8)) & 0xFF);
    }

    for (size_t offset = 0; offset < total_len; offset += SHA512_BLOCK_SIZE) {
        sha512_transform(state, buffer + offset);
    }

    for (size_t i = 0; i < output_len; i++) {
        int word = (int)(i / 8);
        int byte_idx = 7 - (int)(i % 8);
        digest[i] = (uint8_t)((state[word] >> (byte_idx * 8)) & 0xFF);
    }

    memset(buffer, 0, total_len);
    free(buffer);
    memset(state, 0, sizeof(state));
    return SUCCESS;
}

/**
 * @brief SHA-384 해시 함수
 *
 * @details
 *   입력 데이터에 대해 SHA-384 해시를 계산하여 48바이트 다이제스트를 생성한다.
 *   SHA-384는 SHA-512와 동일한 알고리즘을 사용하지만, 다른 초기 해시 값과
 *   출력 길이(48바이트)를 사용한다.
 *
 * @param[out] digest   계산된 SHA-384 다이제스트를 저장할 버퍼 (48바이트)
 * @param[in]  data     해시를 계산할 입력 데이터
 * @param[in]  data_len 입력 데이터의 길이 (바이트 단위)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see sha512_hash()
 * @see sha512_process()
 */
ERR_MSG sha384_hash(
    OUT uint8_t* digest /*48*/,
    IN  const uint8_t* data,
    IN  size_t data_len) {
    static const uint64_t sha384_initial_hash[8] = {
        0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
        0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
    };
    return sha512_process(digest, data, data_len, sha384_initial_hash, 48);
}

/**
 * @brief SHA-512 해시 함수
 *
 * @details
 *   입력 데이터에 대해 SHA-512 해시를 계산하여 64바이트 다이제스트를 생성한다.
 *   SHA-512는 SHA-2 계열 중 가장 긴 다이제스트를 제공한다.
 *
 * @param[out] digest   계산된 SHA-512 다이제스트를 저장할 버퍼 (64바이트)
 * @param[in]  data     해시를 계산할 입력 데이터
 * @param[in]  data_len 입력 데이터의 길이 (바이트 단위)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see sha384_hash()
 * @see sha512_224_hash()
 * @see sha512_256_hash()
 * @see sha512_process()
 */
ERR_MSG sha512_hash(
    OUT uint8_t* digest /*64*/,
    IN  const uint8_t* data,
    IN  size_t data_len) {
    static const uint64_t sha512_initial_hash[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    return sha512_process(digest, data, data_len, sha512_initial_hash, 64);
}

/**
 * @brief SHA-512/224 해시 함수
 *
 * @details
 *   입력 데이터에 대해 SHA-512/224 해시를 계산하여 28바이트 다이제스트를 생성한다.
 *   SHA-512/224는 SHA-512와 동일한 알고리즘을 사용하지만, 다른 초기 해시 값과
 *   출력 길이(28바이트)를 사용한다.
 *
 * @param[out] digest   계산된 SHA-512/224 다이제스트를 저장할 버퍼 (28바이트)
 * @param[in]  data     해시를 계산할 입력 데이터
 * @param[in]  data_len 입력 데이터의 길이 (바이트 단위)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see sha512_hash()
 * @see sha512_256_hash()
 * @see sha512_process()
 */
ERR_MSG sha512_224_hash(
    OUT uint8_t* digest /*28*/,
    IN  const uint8_t* data,
    IN  size_t data_len) {
    static const uint64_t sha512_224_initial_hash[8] = {
        0x8c3d37c819544da2ULL, 0x73e1996689dcd4d6ULL, 0x1dfab7ae32ff9c82ULL, 0x679dd514582f9fcfULL,
        0x0f6d2b697bd44da8ULL, 0x77e36f7304c48942ULL, 0x3f9d85a86a1d36c8ULL, 0x1112e6ad91d692a1ULL
    };
    return sha512_process(digest, data, data_len, sha512_224_initial_hash, 28);
}

/**
 * @brief SHA-512/256 해시 함수
 *
 * @details
 *   입력 데이터에 대해 SHA-512/256 해시를 계산하여 32바이트 다이제스트를 생성한다.
 *   SHA-512/256는 SHA-512와 동일한 알고리즘을 사용하지만, 다른 초기 해시 값과
 *   출력 길이(32바이트)를 사용한다.
 *
 * @param[out] digest   계산된 SHA-512/256 다이제스트를 저장할 버퍼 (32바이트)
 * @param[in]  data     해시를 계산할 입력 데이터
 * @param[in]  data_len 입력 데이터의 길이 (바이트 단위)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *
 * @see sha512_hash()
 * @see sha512_224_hash()
 * @see sha512_process()
 */
ERR_MSG sha512_256_hash(
    OUT uint8_t* digest /*32*/,
    IN  const uint8_t* data,
    IN  size_t data_len) {
    static const uint64_t sha512_256_initial_hash[8] = {
        0x22312194fc2bf72cULL, 0x9f555fa3c84c64c2ULL, 0x2393b86b6f53b151ULL, 0x963877195940eabdULL,
        0x96283ee2a88effe3ULL, 0xbe5e1e2553863992ULL, 0x2b0199fc2c85b8aaULL, 0x0eb72ddc81c52ca2ULL
    };
    return sha512_process(digest, data, data_len, sha512_256_initial_hash, 32);
}
