#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>

int auth(char *login, int password) {
    size_t      len;
    uint32_t    hash;

    login[strcspn(login, "\n")] = '\0';
    len = strnlen(login, 32);

    if (len < 6)
        return 1;

    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        puts("\x1b[32m.---------------------------.");
        puts("\x1b[31m| !! TAMPERING DETECTED !!  |");
        puts("\x1b[32m'---------------------------'");
        return 1;
    }

    hash = ((login[3] ^ 0x1337) + 0x5eeded);

    for (int i = 0; i < len; i++) {
        if (login[i] < ' ')
            return 1;
        
        hash += ((login[i] ^ hash) % 0x539);
    }

    if (hash == password)
        return 0;

    return 1;
}

int main(void) {
    char        buffer[32];
    uint32_t    password;

    puts("***********************************");
    puts("*\t\tlevel06\t\t  *");
    puts("***********************************");

    printf("-> Enter Login: ");
    fgets(buffer, sizeof(buffer), stdin);

    puts("***********************************");
    puts("***** NEW ACCOUNT DETECTED ********");
    puts("***********************************");

    printf("-> Enter Serial: ");
    scanf("%u", &password);

    if (!auth(buffer, password)) {  
        puts("Authenticated!");
        system("/bin/sh");
    }

    return 0;
}
