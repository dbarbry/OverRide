#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
    msg->len = 140;
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
