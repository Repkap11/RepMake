#include <fcntl.h>
#include <malloc.h>
#include <stdio.h>
#include <unistd.h>

extern void lib_hello();

int main() {
    printf("Hello, World\n");
    for (int i = 0; i < 1000; i++) {
        int fd = open("TWO.txt", O_RDONLY);
        char* buff = malloc(100);
        int size = read(fd, buff, 100);
        printf("Read %d bytes\n", size);

        close(fd);
    }
    lib_hello();
    return 0;
}