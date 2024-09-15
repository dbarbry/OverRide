#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
    char    password[41];
    char    username[96];
    char    input_password[96];
    int     length;
    FILE    *fd;
    
    memset(password, 0, 41);
    memset(username, 0, 96);
    memset(input_password, 0, 96);

    fd = fopen("home/users/level03/.pass", "r");
    if (!fd) {
        fwrite("ERROR: failed to open password file\n", 1, 36, stderr);
        exit(1);
    }

    length = fread(password, 1, 41, fd);
    if (length != 41) {
        fwrite("ERROR: failed to read password file\n", 1, 36, stderr);
        fwrite("ERROR: failed to read password file\n", 1, 36, stderr);
        exit(1);
    }
    fclose(fd);

    puts("===== [ Secure Access System v1.0 ] =====");
    puts("/***************************************\\");
    puts("| You must login to access this system. |");
    puts("\\**************************************/");
    
    printf("--[ Username: ");
    fgets(input_password, sizeof(input_password), stdin);
    puts("*****************************************");

    if (strncmp(password, input_password, 41) == 0) {
        printf("Greetings, %s!\n", username);
        system("/bin/sh");
        return 0;
    }

    printf(username);
    puts(" does not have access!");
    exit(1);
}
