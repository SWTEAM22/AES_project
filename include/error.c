#include "error.h"
#include <stdio.h>
#include <string.h>

// 폴더 이름 추출 함수
const char* get_folder_name(uint16_t folder_code) {
    switch(folder_code) {
        case FOLDER_AES:     return "AES";
        case FOLDER_API:     return "API";
        case FOLDER_SHA:     return "SHA";
        case FOLDER_TEST:    return "TEST";
        case FOLDER_INCLUDE: return "INCLUDE";
        default:             return "UNKNOWN_FOLDER";
    }
}

// 함수 이름 추출 함수
const char* get_function_name(uint16_t func_code) {
    switch(func_code) {
        case FUNC_INTERNAL:         return "INTERNAL";
        case FUNC_KEY_SCHEDULE:     return "KEY_SCHEDULE";
        case FUNC_ENCRYPT:          return "ENCRYPT";
        case FUNC_DECRYPT:          return "DECRYPT";
        case FUNC_HASH:            return "HASH";
        case FUNC_CTR_CRYPTO:       return "CTR_CRYPTO";
        case FUNC_SUB_BYTES:        return "SUB_BYTES";
        case FUNC_SHIFT_ROWS:       return "SHIFT_ROWS";
        case FUNC_MIX_COLUMNS:      return "MIX_COLUMNS";
        case FUNC_ADD_ROUND_KEY:    return "ADD_ROUND_KEY";
        case FUNC_INV_SUB_BYTES:    return "INV_SUB_BYTES";
        case FUNC_INV_SHIFT_ROWS:  return "INV_SHIFT_ROWS";
        case FUNC_INV_MIX_COLUMNS:  return "INV_MIX_COLUMNS";
        case FUNC_XTIMES:           return "XTIMES";
        case FUNC_GF_MULT:          return "GF_MULT";
        case FUNC_SUB_WORD:         return "SUB_WORD";
        case FUNC_ROT_WORD:         return "ROT_WORD";
        case FUNC_INCREMENT_COUNTER: return "INCREMENT_COUNTER";
        case FUNC_SHA224_HASH:      return "SHA224_HASH";
        case FUNC_SHA256_HASH:      return "SHA256_HASH";
        case FUNC_SHA384_HASH:      return "SHA384_HASH";
        case FUNC_SHA512_HASH:      return "SHA512_HASH";
        case FUNC_SHA512_224_HASH:  return "SHA512_224_HASH";
        case FUNC_SHA512_256_HASH:  return "SHA512_256_HASH";
        case FUNC_SHA2_HASH:        return "SHA2_HASH";
        case FUNC_ENCRYPT_FILE:     return "ENCRYPT_FILE";
        case FUNC_DECRYPT_FILE:     return "DECRYPT_FILE";
        default:                    return "UNKNOWN_FUNCTION";
    }
}

// 에러 타입 메시지 추출 함수
const char* get_error_type_message(uint16_t err_type) {
    switch(err_type) {
        case ERR_TYPE_NULL_POINTER:    return "NULL pointer error";
        case ERR_TYPE_INVALID_ARG:     return "Invalid argument";
        case ERR_TYPE_INVALID_KEY:    return "Invalid key";
        case ERR_TYPE_INVALID_DATA:   return "Invalid data";
        case ERR_TYPE_INTERNAL:        return "Internal error";
        case ERR_TYPE_MEMORY_ALLOC:   return "Memory allocation failed";
        case ERR_TYPE_FILE_IO:        return "File I/O error";
        case ERR_TYPE_INVALID_LENGTH: return "Invalid length";
        case ERR_TYPE_CRYPTO_FAIL:    return "Cryptographic operation failed";
        case ERR_TYPE_HASH_FAIL:      return "Hash operation failed";
        default:                       return "Unknown error type";
    }
}

// 에러 메시지 포맷팅 함수
static const char* format_error_message(const char* folder, const char* func, const char* error_msg) {
    static char buffer[256];
    snprintf(buffer, sizeof(buffer), "[%s::%s] %s", folder, func, error_msg);
    return buffer;
}

// 기본 에러 메시지 변환 함수
const char* error_to_string(ERR_MSG code) {
    // 폴더별 에러 메시지
    uint16_t folder = GET_FOLDER(code);
    uint16_t func = GET_FUNCTION(code);
    uint16_t err_type = GET_ERROR_TYPE(code);
    
    // 폴더 이름 추출
    const char* folder_name = get_folder_name(folder);
    
    // 함수 이름 추출  
    const char* func_name = get_function_name(func);
    
    // 에러 타입 메시지 추출
    const char* error_msg = get_error_type_message(err_type);
    
    // 조합된 메시지 반환
    return format_error_message(folder_name, func_name, error_msg);
}

// 디버깅용 상세 정보 출력 함수
void print_error_details(ERR_MSG code) {
    uint16_t folder = GET_FOLDER(code);
    uint16_t func = GET_FUNCTION(code);
    uint16_t err_type = GET_ERROR_TYPE(code);
    
    printf("=== Error Details ===\n");
    printf("Error Code: 0x%04X\n", code);
    printf("Folder: 0x%04X (%s)\n", folder, get_folder_name(folder));
    printf("Function: 0x%04X (%s)\n", func, get_function_name(func));
    printf("Error Type: 0x%04X (%s)\n", err_type, get_error_type_message(err_type));
    printf("Full Message: %s\n", error_to_string(code));
}
