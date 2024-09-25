#include <stdio.h>
#include <string.h>

int main(int ac, char **av) {
    char    login[32];
    int     len;
    int     serial;

    if (ac < 2) {
        printf("Usage: %s <login>\n", av[0]);
        return 1;
    }

    len = strlen(av[1]);
    if (len < 6 || len > 30) {
        printf("Login must be between 6 and 30 chars.\n");
        return 1;
    }
    strncpy(login, av[1], 30);

    serial = (login[3] ^ 0x1337) + 0x5eeded;

    for (int i = 0; i < len; ++i)
        serial += (login[i] ^ serial) % 0x539;

    printf("Login: %s - Password: %d\n", login , serial);

    return 0;
}
