#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    char    *original = "Q}|u`sfg~sf{}|a3";
    int     len = strlen(original);
    char    entry[len + 1];
    char    *key;

    for (int i = 0; i < 21; i++) {
        strcpy(entry, original);
        for (int j = 0; j < len; j++) {
            entry[j] ^= i;
        }
        printf("%2d - %s\n", i, entry);
    }
}
