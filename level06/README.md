# level06

### First analysis

As always let's start with the checksec:

```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   /home/users/level06/level06
```

This one has some great security, a Partial RELRO, a stack Canary and NX is enabled. That will be problematic to use a shellcode, or to make overflows that works. Now let's analyse the code.

```c
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
```

It is a code hard to understand at first glance but it is actually fast to explain, this code asks two input, a login and a password. The login will go through some encryption process, and the result of this is compared to the password, if they are the same then we get a shell. The login must be 6 characters and can't contain non printable characters, other than that can be anything. So for that we made a little C script that generate the hash made by the program with a custom login. It can be any login, since the password expected depends on the login:

```c
int main(int ac, char **av) {
    char    login[32];
    int     len;
    int     serial;

    strncpy(login, av[1], 30);
    serial = (login[3] ^ 0x1337) + 0x5eeded;

    for (int i = 0; i < len; ++i)
        serial += (login[i] ^ serial) % 0x539;

    printf("Login: %s - Password: %d\n", login , serial);

    return 0;
}
```

With that we can enter any login we want, it will give us the the password:

```sh
level06@OverRide:/tmp$ ./pass passwordyouwant123
Login: passwordyouwant123 - Password: 6238490
level06@OverRide:~$ ./level06 
***********************************
*		level06		  *
***********************************
-> Enter Login: passwordyouwant123
***********************************
***** NEW ACCOUNT DETECTED ********
***********************************
-> Enter Serial: 6238490
Authenticated!
$ whoami
level07
$ cat /home/users/level07/.pass
GbcPDRgsFK77LNnnuh7QyFYA2942Gp8yKj9KrWD8
```

And this is already the end of the exercise.

## Important doc
