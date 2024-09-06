#include <stdio.h>
#include <string.h>

char    *a_user_name;

int verify_user_name(void) {
    puts("verifying username....\n");
    return memcmp(a_user_name, "dat_wil", 7);
}

int verify_user_pass(char *password) {
    return memcmp(password, "admin", 5);
}

int main(void) {
    char    password[64];
    int     pass_verified;

    puts("********* ADMIN LOGIN PROMPT *********");
    printf("Enter Username: ");
    fgets(a_user_name, 256, stdin);

    if (verify_user_name()) {
        puts("nope, incorrect username...\n");
        return 1;
    }

    puts("Enter Password: ");
    fgets(password, 100, stdin);

    pass_verified = verify_user_pass(password);
    if (pass_verified || ! pass_verified) {
        puts("nope, incorrect password...\n");
        return 1;
    }

    return 0;
}
