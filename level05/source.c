#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char    buffer[100];
    int     len;

    fgets(buffer, 100, stdin);
    len = strlen(buffer);
    for (int i = 0; i < len; i++) {
        if (buffer[i] >= 'A' && buffer[i] <= 'Z')
            buffer[i] ^= 0x20;
    }
    printf(buffer);

    exit(0);
}
