#include <string.h>
#include <stdio.h>

unsigned int    get_unum() {
    unsigned int    input;

    fflush(stdout);
    scanf("%u", &input);

    return input;
}

int store_number(int *tab) {
    unsigned int    nbr;
    unsigned int    index;

    printf(" Number: ");
    nbr = get_unum();
    printf(" Index: ");
    index = get_unum();

    if (index % 3 == 0 || (nbr >> 24) == 183) // 30601641984
    {
        puts(" *** ERROR! ***");
        puts("   This index is reserved for wil!");
        puts(" *** ERROR! ***");
        return 1;
    }
    tab[index] = nbr;

    return 0;
}

int read_number(int *tab) {
    unsigned int    index;

    printf(" Index: ");
    index = get_unum();
    printf(" Number at data[%u] is %u\n", index, tab[index]);

    return 0;
}

int main(int ac, char **av, char **env) {
    unsigned int    tab[100];
    char            cmd[24];
    int             cmd_res;

    memset(tab, 0, 0x190);
    memset(cmd, 0, 0x18);

    while (*av) {
        memset((void *)*av, 0, strlen(*av));
        ++av;
    }
    while (*env) {
        memset((void *)*env, 0, strlen(*env));
        ++env;
    }
    puts("----------------------------------------------------");
    puts("  Welcome to wil's crappy number storage service!   ");
    puts("----------------------------------------------------");
    puts(" Commands:                                          ");
    puts("    store - store a number into the data storage    ");
    puts("    read  - read a number from the data storage     ");
    puts("    quit  - exit the program                        ");
    puts("----------------------------------------------------");
    puts("   wil has reserved some storage :>                 ");
    puts("----------------------------------------------------");

    while (1) {
        printf("Input Command: ");
        fgets(cmd, sizeof(cmd), stdin);
        cmd[strlen(cmd) - 1] = '\0';

        if (!strncmp(cmd, "store", 5)) {
            cmd_res = store_number(tab);
        } else if (!strncmp(cmd, "read", 4)) {
            cmd_res = read_number(tab);
        } else if (!strncmp(cmd, "quit", 4)) {
            return 0;
        }

        if (cmd_res) {
            printf(" Failed to do %s command\n", cmd);
        } else {
            printf(" Completed %s command successfully\n", cmd);
        }

        memset(cmd, 0, sizeof(cmd));
    }

    return 0;
}
