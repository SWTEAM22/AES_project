#include <stdio.h>
#include <string.h>
#include "../include/api.h"
#include "../include/error.h"
#include "../test/print.h"
#include "../aes/header/aes_ctr.h"
void test_gf_mult() {

}

void test_aes_128() {

}
void test_aes_192() {

}
void test_aes_256() {
}

void test_aes_ctr_128(){
}
void test_aes_ctr_192() {

}
void test_aes_ctr_256() {

}

int main() {
	uint8_t data[2] = {0x11, 0x22};
	uint8_t pt[2] = {0x23, 0x34};
	size_t pt_len = 2;
	SHA2_TYPE a = SHA512_224;
	sha2_hash(data, pt, pt_len, a);
	printf("SUCCESS!\n");
	return 0;
}