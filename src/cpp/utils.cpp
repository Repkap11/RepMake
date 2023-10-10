#include <fcntl.h>
#include <stdio.h>
#include <string.h>

void flagsToString(long flags, char* result, size_t result_size) {
    // Initialize the result string as empty
    int length = 0;

    // Check each flag and append its description to the result string
    if (flags == O_RDONLY) {
        length += sprintf(result + length, "O_RDONLY ");
    }
    if (flags & O_WRONLY) {
        length += sprintf(result + length, "O_WRONLY ");
    }
    if (flags & O_RDWR) {
        length += sprintf(result + length, "O_RDWR ");
    }
    if (flags & O_CREAT) {
        length += sprintf(result + length, "O_CREAT ");
    }
    if (flags & O_TRUNC) {
        length += sprintf(result + length, "O_TRUNC ");
    }
    if (flags & O_APPEND) {
        length += sprintf(result + length, "O_APPEND ");
    }
    if (flags & O_CLOEXEC) {
        length += sprintf(result + length, "O_CLOEXEC ");
    }

    // Add more flag checks as needed

    // Remove the trailing space, if any
    size_t len = strlen(result);
    if (len > 0 && result[len - 1] == ' ') {
        result[len - 1] = '\0';
    }
}

int startsWith(const char* str, const char** prefixes) {
    int i = 0;
    const char* prefix = prefixes[i++];
    while (prefix != NULL) {
        if (strncmp(str, prefix, strlen(prefix)) == 0) {
            return 1;  // String starts with one of the prefixes
        }
        prefix = prefixes[i++];
    }
    return 0;  // String does not start with any of the prefixes
}