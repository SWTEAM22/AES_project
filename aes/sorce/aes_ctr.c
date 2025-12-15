#include "../include/foundation.h"
#include "../include/error.h"
#include "./header/aes_ctr.h"

/**
 * @file aes_ctr.c
 * @brief AES-CTR 모드 암호화/복호화 구현
 *
 * @details
 *   이 파일은 AES-CTR(Counter) 모드의 암호화 및 복호화 기능을 구현한다.
 *
 *   ## AES-CTR 모드 개요
 *   - CTR(Counter) 모드는 블록암호 AES를 이용한 스트림 암호 방식이다.
 *   - 매 블록마다 카운터(counter)를 AES로 암호화한 값을 "키스트림"으로 사용하고,
 *     이를 평문과 XOR하여 암호문을 생성한다.
 *   - 복호화 과정도 동일하게 XOR 한 번만 수행하면 되므로 대칭 구조이다.
 *   - AES 블록 크기는 128비트(16바이트)로 고정된다.
 *
 *   ## 주요 처리 흐름
 *   1. counter(IV)를 AES로 암호화하여 keystream 생성
 *   2. plaintext XOR keystream → ciphertext
 *   3. counter 값 1 증가 (Big-endian 방식)
 *   4. 남은 바이트(부분 블록)가 있으면 마지막에 한 번 더 keystream XOR
 *
 *   ## 주요 함수
 *   - increment_counter(): 128비트 카운터를 1 증가시킨다.
 *   - aes_ctr_crypto_inline(): AES-CTR 모드로 암호화/복호화를 수행한다.
 *
 * @author Secure Software Team
 * @date 2024
 * @see aes_ctr.h
 * @see aes.c
 */


/**
 * @brief 128비트 카운터를 1 증가시키는 함수
 *
 * @details
 *   - CTR 모드에서는 블록마다 counter를 1씩 증가시켜 다음 키스트림을 생성한다.
 *   - Big-endian 방식으로 오른쪽(LSB)부터 올림(carry)을 전파한다.
 *   - AES 블록 크기(16바이트)의 카운터를 처리한다.
 *
 * @param[in,out] counter 증가시킬 128비트 카운터 (16바이트 배열, 결과가 저장됨)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_AES_CTR_INVALID_ARG: counter가 NULL
 *
 * @remark
 *   - 카운터는 Big-endian 형식으로 저장된다 (최상위 바이트가 먼저).
 *   - 오버플로우 시 모든 바이트가 0으로 초기화된다.
 *   - AES-CTR 모드에서 각 블록 처리 후 호출된다.
 *
 * @see aes_ctr_crypto_inline()
 */
ERR_MSG increment_counter(uint8_t* counter) {
    if (counter == NULL) {
        return ERR_AES_CTR_INVALID_ARG;
    }

    // 128-bit big-endian increment (AES block = 16 bytes)
    for (int i = AES_BLOCK_SIZE - 1; i >= 0; --i) {
        counter[i] += 1u;
        if (counter[i] != 0u) {
            break;  // carry stop → 더 이상 상위 바이트로 전파 안 함
        }
        // counter[i]가 0이 되면 상위 바이트로 carry 계속 진행
    }

    return SUCCESS;
}


/**
 * @brief AES-CTR 모드로 암호화/복호화 수행하는 함수 (인라인 구현)
 *
 * @details
 *   - CTR(Counter) 모드는 블록암호 AES를 이용한 스트림 암호 방식이다.
 *   - 매 블록마다 카운터(counter)를 AES로 암호화한 값을 "키스트림"으로 사용하고,
 *     이를 평문과 XOR하여 암호문을 생성한다.
 *   - 복호화 과정도 동일하게 XOR 한 번만 수행하면 되므로 암호화와 복호화가 대칭이다.
 *   - AES 블록 크기는 128비트(16바이트)로 고정된다.
 *
 * @details
 *   동작 과정:
 *   ① counter ← iv 초기화 (원본 IV 변경 방지를 위해 복사본 사용)
 *   ② 전체 블록 단위 처리 (16바이트씩):
 *      - AES_Encrypt(counter) → keystream 생성
 *      - ct_block = pt_block XOR keystream
 *      - counter++ (increment_counter 호출)
 *   ③ 마지막 부분 블록(16바이트 미만) 처리:
 *      - 마지막 키스트림 한 번 더 생성
 *      - 남은 바이트만큼만 XOR 수행
 *
 * @param[out] ct       출력 버퍼 (암호문 또는 복호문)
 * @param[in]  key      확장된 AES 키 구조체 (key_expansion()으로 생성됨)
 * @param[in]  pt       입력 평문/암호문 버퍼
 * @param[in]  data_len 입력 데이터 전체 길이 (바이트 단위)
 * @param[in]  iv       초기 카운터(IV, 16바이트)
 *
 * @return ERR_MSG 성공 시 SUCCESS, 실패 시 에러 코드 반환
 *   - ERR_AES_CTR_INVALID_ARG: ct, key, pt, iv 중 하나가 NULL
 *   - aes_encrypt() 또는 increment_counter()에서 발생한 에러 코드
 *
 * @remark
 *   - CTR 모드는 암호화와 복호화 과정이 동일하다 (대칭 구조).
 *   - IV(counter)는 입력에 따라 변하지 않도록 내부 복사본을 사용한다.
 *   - data_len이 0이면 즉시 SUCCESS를 반환한다.
 *   - 보안을 위해 사용된 메모리(counter, keystream)는 작업 후 0으로 초기화된다.
 *   - 부분 블록도 처리 가능하므로 임의 길이의 데이터를 암호화/복호화할 수 있다.
 *
 * @see increment_counter()
 * @see aes_encrypt()
 * @see key_expansion()
 * @see aes_ctr_crypto()
 */
ERR_MSG aes_ctr_crypto_inline(
    OUT uint8_t* ct,
    IN  const AES_KEY* key,
    IN  const uint8_t* pt,
    IN  size_t data_len,
    IN  const uint8_t* iv)
{
    // 인자 유효성 검사
    if (ct == NULL || key == NULL || pt == NULL || iv == NULL) {
        return ERR_AES_CTR_INVALID_ARG;
    }
    // IV 길이 검증 (AES 블록 크기 = 16바이트)
    // 참고: iv_len 파라미터가 없으므로 함수 시그니처를 변경하거나
    // 호출자가 16바이트를 보장해야 함. 여기서는 암묵적으로 16바이트로 가정
    if (data_len == 0) {
        return SUCCESS; // 처리할 데이터가 없음
    }

    uint8_t counter[AES_BLOCK_SIZE];   // 현재 블록용 카운터(IV 복사본)
    uint8_t keystream[AES_BLOCK_SIZE]; // AES로 생성된 키스트림

    // counter <- iv (원본 IV 변경 방지)
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        counter[i] = iv[i];
    }

    size_t off = 0;

    /********************************************
     * [1] 전체 블록 단위 처리 (16바이트씩)
     ********************************************/
    while (data_len - off >= AES_BLOCK_SIZE) {
        // ① keystream 생성: AES_Encrypt(counter)
        ERR_MSG err = aes_encrypt(keystream, key, counter);
        if (err != SUCCESS) {
            memset(counter, 0, sizeof(counter));
            memset(keystream, 0, sizeof(keystream));
            return err;
        }

        // ② XOR: 평문 블록과 keystream 결합 → 암호문 블록
        for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
            ct[off + i] = pt[off + i] ^ keystream[i];
        }

        // ③ counter++
        err = increment_counter(counter);
        if (err != SUCCESS) {
            memset(counter, 0, sizeof(counter));
            memset(keystream, 0, sizeof(keystream));
            return err;
        }

        off += AES_BLOCK_SIZE; // 다음 블록으로 이동
    }

    /********************************************
     * [2] 마지막 잔여 블록 처리 (16바이트 미만)
     ********************************************/
    size_t rem = data_len - off;
    if (rem > 0) {
        // 마지막 키스트림 한 번 더 생성
        ERR_MSG err = aes_encrypt(keystream, key, counter);
        if (err != SUCCESS) {
            memset(counter, 0, sizeof(counter));
            memset(keystream, 0, sizeof(keystream));
            return err;
        }

        // 남은 바이트만큼 XOR
        for (size_t i = 0; i < rem; ++i) {
            ct[off + i] = pt[off + i] ^ keystream[i];
        }
    }

    // 메모리 초기화 (보안)
    memset(counter, 0, sizeof(counter));
    memset(keystream, 0, sizeof(keystream));

    // CTR 모드는 암복호 동일 → SUCCESS 반환
    return SUCCESS;
}
