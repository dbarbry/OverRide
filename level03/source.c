#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

void    decrypt(unsigned int key) {
    int     len;
    char    str[29];

    strcpy(str, "Q}|u`sfg~sf{}|a3");
    len = strlen(str);

    for (int i = 0; i < len; i++)
        str[i] ^= key;
    
    if (!strcmp(str, "Congratulations!")) {
        system("/bin/sh");
    }
    
    puts("\nInvalid Password");
}

void    test(int input, int secret) {
    int diff;

    diff = secret - input;
    if ((diff > 0 && diff < 10) || (diff > 15 && diff < 22))
        decrypt(diff);
    else
        decrypt(rand());

    return;
}

int main(void) {
    unsigned int    __seed;
    int             input;

    __seed = time((time_t *)0);
    srand(__seed);

    puts("***********************************");
    puts("*\t\tlevel03\t\t**");
    puts("***********************************");

    printf("Password:");
    scanf("%d", &input);
    test(input, 322424845);

    return 0;
}
