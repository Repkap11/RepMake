#include <stdio.h>

extern void lib_hello();

int main() {
    printf("Hello, World3\n");
    lib_hello();
    return 0;
}