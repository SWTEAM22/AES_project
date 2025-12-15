void prob_07() {
    int arr[10];
    int size = sizeof(arr)/sizeof(arr[0]);
    init_array(arr,size);
    int* pe = arr;
    int* po = arr + 1;

    int sume = 0;
    int sumo = 0;
    for (int i = 0; i < size/2; i++) 
    {
        sume += *pe;
        sumo += *po;
        pe = pe + 2;
        po = po + 2;
    }
    printf("sume = %d\n", sume);
    printf("sumo = %d\n", sumo);
}

void prob_13() {
    int arr[2][3] = {0, 1, 2, 3, 4, 5};
    int row = sizeof(arr) / sizeof(arr[0]);
    int col = sizeof(arr[0]) / sizeof(arr[0][0]);

    int *p = &arr[0][0];
    for (int i = 0; i < row; i++) {
        for (int j = 0; j < col; j++) {
            printf("%d ", p[i * col + j]);
        }
        printf("\n");
    }
}
