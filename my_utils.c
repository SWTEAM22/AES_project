#include "my_utils.h"

// Hello World 출력 함수
void say_hello(void) {
    printf("Hello, World!\n");
}

// 이름 출력 함수
void print_name(char name[]) {
    printf("안녕하세요, %s님!\n", name);
}

// 두 수 더하기
int add_numbers(int a, int b) {
    return a + b;
}

// 두 수 곱하기
int multiply_numbers(int a, int b) {
    return a * b;
}

// 범위의 숫자들 출력
void print_numbers(int start, int end) {
    for (int i = start; i <= end; i++) {
        printf("%d ", i);
    }
}

// 배열 출력
void print_array(int arr[], int size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
}

// 세 수 중 가장 큰 수 찾기
int find_biggest(int a, int b, int c) {
    if (a >= b && a >= c) {
        return a;
    } else if (b >= a && b >= c) {
        return b;
    } else {
        return c;
    }
}

// 별 출력
void print_stars(int count) {
    for (int i = 0; i < count; i++) {
        printf("*");
    }
}

// 정사각형 출력
void print_square(int size) {
    for (int i = 0; i < size; i++) {
        for (int j = 0; j < size; j++) {
            printf("* ");
        }
        printf("\n");
    }
}


