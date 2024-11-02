# level09

### First analysis

For this first and only bonus, this last level of override, and the last level of the cybersecurity branch, of 42 let's analyse the checksec and the code as always starting with the checksec:

```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   /home/users/level09/level09
```

This time no stack canary, so we can overflow buffers as we want, shouldn't be a problem, we have a Partial RELRO, we described enough this parameter to know that it doesn't protect a lot the GOT exploit. However we have NX enabled, which means the stack won't be executable probably, and also PIE enabled which is an option we never encountered before. What PIE does when enabled is that it randomize the addresses to avoid fix addresses in the code. PIE means Position Independent Execution and what it does is that it create an offset, apply it to every address of the code, so we can't know where a function's address is for instance. However this offset can be found in the stack so if we have a way to read the stack with the code, shouldn't be that much of a problem.

Now for the code:

```c
typedef struct  s_msg {
    char    msg[140];
    char    username[40];
    int     len;
}   t_msg;

void    secret_backdoor() {
    char    cmd[128];

    fgets(cmd, sizeof(cmd), stdin);
    system(cmd);
}

void    set_username(t_msg *msg) {
    char    username[128];

    memset(username, 0, 128);
    puts(">: Enter your username");
    printf(">>: ");
    fgets(username, 128, stdin);

    for (int i = 0; i <= 40 && username[i]; i++) {
        msg->username[i] = username[i];
    }
    printf(">: Welcome %s", msg->username);

    return;
}

void    set_msg(t_msg *msg) {
    char    buffer[1024];

    memset(buffer, 0, 1024);
    puts(">: Msg @Unix-Dude");
    printf(">>: ");
    fgets(buffer, 1024, stdin);
    strncpy(msg->msg, buffer, msg->len);

    return;
}

void    handle_msg() {
    t_msg   *msg;

    memset(msg->username, 0, 40);
    set_username(msg);
    set_msg(msg);
    puts(">: Msg sent!");

    return;
}

int main(void) {
    puts("--------------------------------------------\n");
    puts("|   ~Welcome to l33t-m$n ~    v1337        |\n");
    puts("--------------------------------------------");
    handle_msg();

    return 0;
}
```

## Important doc
