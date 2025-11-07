#include "../include/foundation.h"
#include "../include/error.h"
#include "../include/api.h"
#include <string.h>
#include <stdlib.h>

ERR_MSG sha224_hash(
    OUT uint8_t* digest /*28*/,
    IN  const uint8_t* data,
    IN  size_t data_len) {
    return SUCCESS;
}

ERR_MSG sha256_hash(
    OUT uint8_t* digest /*32*/,
    IN  const uint8_t* data,
    IN  size_t data_len) {
    return SUCCESS;
}

// SHA-512 내부 함수들
static uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static uint64_t ch(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (~x & z);
}

static uint64_t maj(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static uint64_t sigma0(uint64_t x) {
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}

static uint64_t sigma1(uint64_t x) {
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}

static uint64_t gamma0(uint64_t x) {
    return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
}

static uint64_t gamma1(uint64_t x) {
    return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
}

// SHA-512 상수 K
static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2d8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde1ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

// SHA-512 공통 처리 함수
ERR_MSG sha512_process(
    OUT uint8_t* digest,
    IN  const uint8_t* data,
    IN  size_t data_len,
    IN  const uint64_t* initial_hash,
    IN  size_t output_len) {
    
    // NULL 포인터 체크
    if (digest == NULL) {
        return ERR_SHA_HASH_NULL_PTR;
    }
    
    // data가 NULL인 경우 data_len도 0이어야 함
    if (data == NULL && data_len != 0) {
        return ERR_SHA_HASH_INVALID_DATA;
    }
    
    uint64_t h[8];
    uint64_t a, b, c, d, e, f, g, h_temp;
    uint64_t w[80];
    uint64_t temp1, temp2;
    
    // 초기 해시 값 복사
    memcpy(h, initial_hash, 8 * sizeof(uint64_t));
    
    // 메시지 길이 (비트 단위)
    uint64_t total_bits = (uint64_t)data_len * 8;
    
    // 패딩 계산
    size_t padding_len = (128 - ((data_len + 17) % 128)) % 128;
    size_t total_len = data_len + 1 + padding_len + 16; // 데이터 + 0x80 + 패딩 + 길이
    
    // 전체 메시지 버퍼 할당 (간단한 구현을 위해 최대 크기로)
    uint8_t* message = (uint8_t*)malloc(total_len);
    if (message == NULL) {
        return ERR_SHA_HASH_FAIL;
    }
    
    // 메시지 복사 (data_len이 0이면 복사하지 않음)
    if (data_len > 0 && data != NULL) {
        memcpy(message, data, data_len);
    }
    message[data_len] = 0x80;
    memset(message + data_len + 1, 0, padding_len);
    
    // 길이 추가 (빅엔디안, 128비트 = 16바이트)
    // SHA-512는 메시지 길이를 128비트로 저장 (상위 8바이트는 일반적으로 0)
    uint64_t message_bits = (uint64_t)data_len * 8;
    size_t length_offset = data_len + 1 + padding_len;
    // 상위 8바이트는 0으로 설정 (일반적인 경우)
    memset(message + length_offset, 0, 8);
    // 하위 8바이트에 메시지 길이(비트)를 빅엔디안으로 저장
    for (int i = 0; i < 8; i++) {
        message[length_offset + 15 - i] = (uint8_t)(message_bits & 0xFF);
        message_bits >>= 8;
    }
    
    // 1024비트 블록 단위로 처리
    for (size_t chunk = 0; chunk < total_len; chunk += 128) {
        // 메시지 스케줄 준비 (W[0..15])
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint64_t)message[chunk + i * 8 + 0] << 56) |
                   ((uint64_t)message[chunk + i * 8 + 1] << 48) |
                   ((uint64_t)message[chunk + i * 8 + 2] << 40) |
                   ((uint64_t)message[chunk + i * 8 + 3] << 32) |
                   ((uint64_t)message[chunk + i * 8 + 4] << 24) |
                   ((uint64_t)message[chunk + i * 8 + 5] << 16) |
                   ((uint64_t)message[chunk + i * 8 + 6] << 8) |
                   ((uint64_t)message[chunk + i * 8 + 7] << 0);
        }
        
        // 메시지 스케줄 확장 (W[16..79])
        for (int i = 16; i < 80; i++) {
            w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
        }
        
        // 작업 변수 초기화
        a = h[0];
        b = h[1];
        c = h[2];
        d = h[3];
        e = h[4];
        f = h[5];
        g = h[6];
        h_temp = h[7];
        
        // 메인 루프
        for (int i = 0; i < 80; i++) {
            temp1 = h_temp + sigma1(e) + ch(e, f, g) + K[i] + w[i];
            temp2 = sigma0(a) + maj(a, b, c);
            h_temp = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        
        // 해시 값 업데이트
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += h_temp;
    }
    
    // 결과를 빅엔디안 바이트 배열로 변환
    for (size_t i = 0; i < output_len; i++) {
        int hash_idx = i / 8;
        int byte_idx = 7 - (i % 8);
        digest[i] = (uint8_t)(h[hash_idx] >> (byte_idx * 8));
    }
    
    free(message);
    return SUCCESS;
}

ERR_MSG sha384_hash(
    OUT uint8_t* digest /*48*/,
    IN  const uint8_t* data,
    IN  size_t data_len) {
    
    // SHA-384 초기 해시 값
    static const uint64_t sha384_initial_hash[8] = {
        0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
        0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
    };
    
    return sha512_process(digest, data, data_len, sha384_initial_hash, 48);
}

ERR_MSG sha512_hash(
    OUT uint8_t* digest /*64*/,
    IN  const uint8_t* data,
    IN  size_t data_len) {
    
    // SHA-512 초기 해시 값
    static const uint64_t sha512_initial_hash[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82aULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    
    return sha512_process(digest, data, data_len, sha512_initial_hash, 64);
}

ERR_MSG sha512_224_hash(
    OUT uint8_t* digest /*28*/,
    IN  const uint8_t* data,
    IN  size_t data_len) {
    
    // SHA-512/224 초기 해시 값
    static const uint64_t sha512_224_initial_hash[8] = {
        0x8c3d37c819544da2ULL, 0x73e1996689dcd4d6ULL, 0x1dfab7ae32ff9c82ULL, 0x679dd514582f9fcfULL,
        0x0f6d2b697bd44da8ULL, 0x77e36f7304c48942ULL, 0x3f9d85a86a1d36c8ULL, 0x1112e6ad91d692a1ULL
    };
    
    return sha512_process(digest, data, data_len, sha512_224_initial_hash, 28);
}

ERR_MSG sha512_256_hash(
    OUT uint8_t* digest /*32*/,
    IN  const uint8_t* data,
    IN  size_t data_len) {
    
    // SHA-512/256 초기 해시 값
    static const uint64_t sha512_256_initial_hash[8] = {
        0x22312194fc2bf72cULL, 0x9f555fa3c84c64c2ULL, 0x2393b86b6f53b151ULL, 0x963877195940eabdULL,
        0x96283ee2a88effe3ULL, 0xbe5e1e2553863992ULL, 0x2b0199fc2c85b8aaULL, 0x0eb72ddc81c52ca2ULL
    };
    
    return sha512_process(digest, data, data_len, sha512_256_initial_hash, 32);
}