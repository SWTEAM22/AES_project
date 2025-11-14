#include "../include/foundation.h"
#include "../include/error.h"
#include "./header/aes_ctr.h"

/*******************************************************************************************
* === AES-CTR 모드 암호화 구현 ===
*
* - CTR(Counter) 모드는 블록암호 AES를 이용한 스트림 암호 방식으로,
*   매 블록마다 카운터(counter)를 AES로 암호화한 값을 "키스트림"으로 사용하고,
*   이를 평문과 XOR 하여 암호문을 생성한다.
*
* - 복호화 과정도 동일하게 XOR 한 번만 수행하면 된다. (대칭)
* - AES 블록 크기는 128비트(16바이트)로 고정된다.
*
* 주요 처리 흐름:
*   ① counter(IV)를 AES로 암호화하여 keystream 생성
*   ② plaintext XOR keystream → ciphertext
*   ③ counter 값 1 증가 (Big-endian)
*   ④ 남은 바이트(부분 블록)가 있으면 마지막에 한 번 더 keystream XOR
*******************************************************************************************/


/* =========================================================================================
 * 1) increment_counter: 128비트 카운터를 1 증가시키는 함수
 *    - CTR 모드에서는 블록마다 counter를 1씩 증가시켜 다음 키스트림을 생성한다.
 *    - Big-endian 방식: 오른쪽(LSB)부터 올림(carry)을 전파한다.
 * ========================================================================================= */
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


/* =========================================================================================
 * 2) aes_ctr_crypto: AES-CTR 모드로 암호화/복호화 수행
 *
 * 매개변수 설명:
 *   - ct       : 출력 버퍼 (암호문 또는 복호문)
 *   - key      : AES 키 구조체
 *   - pt       : 입력 평문/암호문 버퍼
 *   - data_len : 입력 데이터 전체 길이
 *   - iv       : 초기 카운터(IV, 16바이트)
 *
 * 동작 개요:
 *   ① counter ← iv 초기화
 *   ② while (남은 블록 있음)
 *        AES_Encrypt(counter) → keystream 생성
 *        ct_block = pt_block XOR keystream
 *        counter++
 *   ③ 마지막 부분 블록(rem) 처리
 *
 * 특징:
 *   - CTR은 암호화와 복호화 과정이 동일하다.
 *   - IV(counter)는 입력에 따라 변하지 않도록 내부 복사본 사용.
 * ========================================================================================= */
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
