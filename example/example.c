#include <stdio.h>

extern void lib_hello();

int main() {
    printf("Hello, World\n");
    lib_hello();
    return 0;
}