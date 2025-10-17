#ifndef ERROR_H
#define ERROR_H

typedef enum {
	/* --- 일반 오류 (-1 ~ -9) --- */
	SUCCESS = 0,								// 성공
	ERROR_NULL_POINTER = -1,					// 널 포인터 오류
	ERROR_INVALID_ARGUMENT = -2,				// 잘못된 인자 오류

	/* --- 키 관련 오류 (-10 ~ -19) --- */
	ERROR_INVALID_KEY_LENGTH = -10,				// 잘못된 키 길이 오류
	ERROR_KEY_NOT_INITIALIZED = -11,			// 키가 초기화되지 않음

	/* --- 데이터 관련 오류 (-20 ~ -29) --- */
	ERROR_INVALID_DATA_LENGTH = -20,			// 잘못된 데이터 길이 오류

	/* --- 내부 오류 (-100 ~) --- */
	ERROR_INTERNAL = -100,						// 내부 오류
} ERR_MSG;

/*----------------------------------- 오류 출력 함수-------------------------------------------*/

#define SUCCESS 0
#define FAIL 1

#define ERR_MSG uint16_t
#define ERR_FUNC uint16_t

#define FOLDER_MASK             0xF000
#define FUNC_MASK               0x0FF0
#define ERR_MASK                0x00F0

#define FOLDER_AES				0x1000
#define FOLDER_API              0x2000
#define FOLDER_INCLUDE			0x3000
#define FOLDER_SHA				0x4000
#define FOLDER_TEST				0x5000

#define FUNC_INTERNAL			0x0100
#define FUNC_KEY_SCHEDULE		0x0200
#define FUNC_ENCRYPT			0x0300
#define FUNC_DECRYPT			0x0400
#define FUNC_HASH				0x0500

// 해당 형식으로 매크로를 추가 작성할 예정
// 작성 시, 어떤 폴더에서 에러가 발생했는지, 어떤 함수에서 에러가 발생했는지, 어떤 에러가 발생했는지를
// 알 수 있음

const char* error_to_string(ERR_MSG code);

#endif // !ERROR_H
