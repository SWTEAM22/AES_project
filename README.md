# Secure Software - AES & SHA-2 Cryptographic Library

암호화 및 해시 함수를 구현한 C 라이브러리 및 파일 암복호화 도구입니다.

## 주요 기능

### 암호화 알고리즘
- **AES (Advanced Encryption Standard)**
  - AES-128, AES-192, AES-256 지원
  - CTR (Counter) 모드 구현
  - 단일 블록 암호화/복호화 지원

### 해시 알고리즘
- **SHA-2 계열**
  - SHA-224 (28 bytes)
  - SHA-256 (32 bytes)
  - SHA-384 (48 bytes)
  - SHA-512 (64 bytes)
  - SHA-512/224 (28 bytes)
  - SHA-512/256 (32 bytes)

### 파일 암복호화 도구
- AES-CTR 모드를 사용한 파일 암호화/복호화
- SHA-256 기반 인증 태그 생성 및 검증
- 절대 경로 및 상대 경로 지원

## 프로젝트 구조

```
secure sw/
├── aes/                    # AES 암호화 구현
│   ├── header/
│   │   ├── aes.h          # AES 기본 헤더
│   │   └── aes_ctr.h      # AES-CTR 모드 헤더
│   └── sorce/
│       ├── aes.c          # AES 블록 암호화 구현
│       └── aes_ctr.c      # AES-CTR 모드 구현
│
├── sha/                    # SHA-2 해시 함수 구현
│   ├── header/
│   │   └── sha.h          # SHA-2 헤더
│   └── sorce/
│       └── sha.c          # SHA-2 구현
│
├── api/                    # API 레이어
│   ├── aes_api.c          # AES API 래퍼
│   ├── sha_api.c          # SHA-2 API 래퍼
│   └── file_crypto_api.c  # 파일 암복호화 API
│
├── include/                # 공통 헤더
│   ├── api.h              # 메인 API 헤더
│   ├── foundation.h       # 기본 상수 및 타입 정의
│   ├── error.h            # 에러 코드 정의
│   └── error.c            # 에러 처리 구현
│
├── test/                   # 테스트 코드
│   ├── aes_test.c         # AES 테스트
│   ├── sha_test.c         # SHA-2 테스트
│   ├── print.c/h          # 테스트 출력 유틸리티
│   └── tv_*/              # 테스트 벡터 파일들
│
└── main.c                 # 파일 암복호화 CLI 프로그램
```

## 빌드 방법

### Visual Studio (Windows)

1. **Visual Studio 2022 이상**에서 `secure sw.sln` 열기
2. **실행 모드 선택**: `include/foundation.h` 파일에서 `TESTCASE` 값을 설정
   ```c
   #define TESTCASE 0  // 파일 암복호화 프로그램 (기본값)
   #define TESTCASE 1  // AES 테스트
   #define TESTCASE 2  // SHA-2 테스트
   ```
3. 빌드: `Ctrl+Shift+B` 또는 Build → Build Solution
4. 실행 파일 위치: `x64/Debug/secure sw.exe` 또는 `x64/Release/secure sw.exe`

### TESTCASE 설정 방법

`include/foundation.h` 파일의 32번째 줄을 수정:

- **`TESTCASE 0`** (기본값): 파일 암복호화 프로그램 실행 (`FILE_CRYPTO` 정의)
- **`TESTCASE 1`**: AES 테스트 실행 (`AES_TEST_MAIN` 정의)
- **`TESTCASE 2`**: SHA-2 테스트 실행 (`SHA_TEST_MAIN` 정의)

## 사용법

### 파일 암복호화 프로그램

`TESTCASE 0`으로 설정한 후 솔루션 탐색기에서 "모든 파일 표시 버튼"을 누르고 
main.c 파일을 우클릭 해 "프로젝트에 포함"버튼을 클릭,
프로그램을 실행하면 대화형으로 입력을 받습니다:

#### 암호화 (Encrypt)

```
=== File Encrypt/Decrypt with AES-CTR + SHA-256 Tag ===
Note: You can use absolute paths (e.g., C:\Users\...\file.txt) or relative paths (e.g., data\file.txt)

Mode (enc/dec): enc
Input file path (plaintext file, e.g., C:\data\plain.txt or data\plain.txt): plain.txt
Output file path (ciphertext file, e.g., C:\data\cipher.bin or data\cipher.bin): cipher.bin
AES key (hex, 32/48/64 chars): 00112233445566778899AABBCCDDEEFF
IV (hex, 32 chars = 16 bytes): 000102030405060708090A0B0C0D0E0F
Tag file path (e.g., C:\data\tag.bin or data\tag.bin): tag.bin

Encryption OK.
  Input : plain.txt
  Output: cipher.bin
  Tag   : tag.bin (SHA-256, 32 bytes)
```

#### 복호화 (Decrypt)

```
Mode (enc/dec): dec
Input file path (ciphertext file, e.g., C:\data\cipher.bin or data\cipher.bin): cipher.bin
Output file path (decrypted file, e.g., C:\data\decrypted.txt or data\decrypted.txt): decrypted.txt
AES key (hex, 32/48/64 chars): 00112233445566778899AABBCCDDEEFF
IV (hex, 32 chars = 16 bytes): 000102030405060708090A0B0C0D0E0F
Tag file path (e.g., C:\data\tag.bin or data\tag.bin): tag.bin

Decryption OK.
  Input : cipher.bin
  Output: decrypted.txt
  Tag   : tag.bin (verified)
```

#### 입력 형식

- **Mode**: `enc` (암호화) 또는 `dec` (복호화)
- **파일 경로**: 절대 경로 (`C:\Users\...\file.txt`) 또는 상대 경로 (`data\file.txt`) 모두 지원
- **AES Key**: 16진수 문자열
  - 32글자 (16바이트) → AES-128
  - 48글자 (24바이트) → AES-192
  - 64글자 (32바이트) → AES-256
- **IV**: 16진수 문자열, 32글자 (16바이트)
- **Tag File**: SHA-256 태그가 저장/읽혀질 파일 경로 (32바이트 바이너리)

### API 사용 예시

#### AES 암호화

```c
#include "include/api.h"

uint8_t key[16] = {0x00, 0x11, ...};  // 16/24/32 bytes
uint8_t plaintext[16] = {...};
uint8_t ciphertext[16];

AES_KEY aes_key;
ERR_MSG err = key_expansion(&aes_key, key, 16);
if (err != SUCCESS) {
    // 에러 처리
    return;
}

err = aes_encrypt_block(ciphertext, &aes_key, plaintext);
```

#### SHA-2 해시

```c
#include "include/api.h"

uint8_t data[] = "Hello, World!";
uint8_t digest[32];  // SHA-256

ERR_MSG err = sha2_hash(digest, data, strlen((char*)data), SHA256);
if (err != SUCCESS) {
    // 에러 처리
    return;
}
```

#### 파일 암복호화

```c
#include "include/api.h"

uint8_t key[16] = {...};
uint8_t iv[16] = {...};
uint8_t tag[32];

// 암호화
ERR_MSG err = encrypt_file_with_tag_ex(
    "input.txt",
    key, 16,
    iv, 16,
    "output.enc",
    tag, 32,
    SHA256
);

// 복호화
err = decrypt_file_with_tag_ex(
    "output.enc",
    key, 16,
    iv, 16,
    "decrypted.txt",
    tag, 32,
    SHA256
);
```

## 테스트

### 테스트 실행 방법

`include/foundation.h` 파일에서 `TESTCASE` 값을 변경하여 원하는 테스트를 실행할 수 있습니다:

#### AES 테스트

1. `include/foundation.h`에서 `TESTCASE`를 `1`로 설정:
   ```c
   #define TESTCASE 1
   ```
2. 프로젝트 빌드 및 실행
3. AES 테스트 벡터 파일을 읽어 자동으로 테스트 수행

#### SHA-2 테스트

1. `include/foundation.h`에서 `TESTCASE`를 `2`로 설정:
   ```c
   #define TESTCASE 2
   ```
2. 프로젝트 빌드 및 실행
3. SHA-2 테스트 벡터 파일을 읽어 자동으로 테스트 수행

테스트 벡터 파일 위치: `test/tv_SHA2/`

- SHA-224: `SHA224ShortMsg.rsp`, `SHA224LongMsg.rsp`
- SHA-256: `SHA256ShortMsg.rsp`, `SHA256LongMsg.rsp`
- SHA-384: `SHA384ShortMsg.rsp`, `SHA384LongMsg.rsp`
- SHA-512: `SHA512ShortMsg.rsp`, `SHA512LongMsg.rsp`
- SHA-512/224: `SHA512_224ShortMsg.rsp`, `SHA512_224LongMsg.rsp`
- SHA-512/256: `SHA512_256ShortMsg.rsp`, `SHA512_256LongMsg.rsp`

## 주요 API

### AES API

- `key_expansion()`: AES 키 스케줄 생성
- `aes_encrypt_block()`: 단일 블록 암호화
- `aes_decrypt_block()`: 단일 블록 복호화
- `aes_ctr_crypto()`: CTR 모드 암호화/복호화

### SHA-2 API

- `sha2_hash()`: SHA-2 해시 계산 (타입 선택 가능)

### 파일 암복호화 API

- `encrypt_file_with_tag()`: 파일 암호화 + SHA-256 태그 생성
- `encrypt_file_with_tag_ex()`: 파일 암호화 + 선택 가능한 SHA 타입 태그 생성
- `decrypt_file_with_tag()`: 파일 복호화 + SHA-256 태그 검증
- `decrypt_file_with_tag_ex()`: 파일 복호화 + 선택 가능한 SHA 타입 태그 검증

## 에러 처리

모든 API 함수는 `ERR_MSG` 타입의 에러 코드를 반환합니다:
- `SUCCESS (0)`: 성공
- 기타: 에러 코드 (폴더/함수/에러 타입 조합)

에러 상세 정보는 `print_error_details()` 함수로 출력할 수 있습니다.

## 주의사항

1. **키 관리**: 실제 사용 시 키는 안전하게 관리해야 합니다.
2. **IV 재사용**: 같은 키로 같은 IV를 재사용하면 보안 문제가 발생할 수 있습니다.
3. **태그 검증**: 복호화 시 태그 검증 실패는 데이터 위변조를 의미할 수 있습니다.
4. **파일 경로**: Windows 경로 구분자는 `\` 또는 `/` 모두 사용 가능합니다.

## 라이선스

이 프로젝트는 교육 목적으로 작성되었습니다.

## 참고 자료

- [NIST FIPS 197 - AES](https://csrc.nist.gov/publications/detail/fips/197/final)
- [NIST FIPS 180-4 - SHA-2](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [NIST CAVS Test Vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)

