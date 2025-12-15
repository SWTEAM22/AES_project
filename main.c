#include "my_utils.h"

int main() {
    // Hello World 출력
    say_hello();
    
    // 이름 출력
    print_name("홍길동");
    
    // 숫자 계산
    int result = add_numbers(5, 3);
    printf("5 + 3 = %d\n", result);
    
    int product = multiply_numbers(4, 6);
    printf("4 * 6 = %d\n", product);
    
    // 가장 큰 수 찾기
    int biggest = find_biggest(10, 25, 15);
    printf("가장 큰 수: %d\n", biggest);
    
    // 숫자 범위 출력
    printf("1부터 5까지: ");
    print_numbers(1, 5);
    printf("\n");
    
    // 배열 출력
    int numbers[] = {1, 2, 3, 4, 5};
    printf("배열: ");
    print_array(numbers, 5);
    printf("\n");
    
    // 별 출력
    printf("별 5개: ");
    print_stars(5);
    printf("\n");
    
    // 정사각형 출력
    printf("3x3 정사각형:\n");
    print_square(3);
    
    return 0;
}
