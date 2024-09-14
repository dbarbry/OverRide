# level01

### First analysis

Let's analyse the code and checksec of the binary for level01. For the checksec we can observe this:

```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/users/level01/level01
```

So again we can see that we have a partial RELRO, however this time NX is deactivated, which means the very powerfull method we found in RainFall with the env variable could potentially work. Let's analyse the code to see if it is the kind to use this method:

```c
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
```

The code is pretty straightforward again, we get asked 2 user input, one for username, one for password. The username is a global variable, and even after 256 chars we know it can't be overflowed. It has to be equal to "dat_wil" so the code continues its execution. Then a password prompt open, and we have to enter into password, a 64 chars buffer, up to 100 chars. We can already see that 36 chars can be overflowed (probably a little less). So we tested this very quickly to see if something happen, searching for eip to be overflowed:

```sh
(gdb) r
Starting program: /home/users/level01/level01 
********* ADMIN LOGIN PROMPT *********
Enter Username: dat_wil
verifying username....

Enter Password: 
aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnnooooppppqqqqrrrrssssttttuuuuvvvvwwwwxxxxyyyyzzzz
nope, incorrect password...


Program received signal SIGSEGV, Segmentation fault.
0x75757575 in ?? ()
(gdb) info registers
eax            0x1	1
ecx            0xffffffff	-1
edx            0xf7fd08b8	-134412104
ebx            0x72727272	1920103026
esp            0xffffd510	0xffffd510
ebp            0x74747474	0x74747474
esi            0x0	0
edi            0x73737373	1936946035
eip            0x75757575	0x75757575
eflags         0x10286	[ PF SF IF RF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99
```

By testing that we can re-construct the memory layout that interests us thanks to this info registers command. With that we understand that we have:

```
[   buffer 68   ][  ebx  ][  edi  ][  ebp  ][  eip  ]
```

Here EIP is just the address of segfault but we wanted to show more of what happen in the registers of the CPU. So we now know that there is a payload of 80 char before accessing EIP.

### Env shellcode method

We followed the exact same steps that we use to do in [RainFall](https://github.com/kbarbry/RainFall/blob/main/~bonus2/walkthrough.md) adapted to this binary however it didn't work. And we had to figure out why since everything seemed to be aligned for this method.

By searching a little more we discovered that OverRide is actually different than RainFall on several elements. The most important one is this one:

```sh
level01@OverRide:~$ uname -a
Linux OverRide 3.13.0-95-generic #142~precise1-Ubuntu SMP Fri Aug 12 18:20:15 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
```

This command gives some informations about the machine and look at this element "x86_64". Where RainFall was a x86 32bit machine, here in OverRide we are in a 64bit machine. Which means addresses are now 16 char long, not just 8, this is a little part of what strace gives us: (yes we have access to strace and ltrace on this machine, that's another difference)

```sh
map2(0xf7fcd000, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1a0) = 0xfffffffff7fcd000
mmap2(0xf7fd0000, 10972, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0xfffffffff7fd0000
close(3)                                = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xfffffffff7e2b000
```

As we can see the addresses are definitely different as RainFall. But in this case why did gdb gave us 32bit alike addresses ? Well the answer is here:

```sh
level01@OverRide:~$ file ./level01 
./level01: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x923fd646950abba3d31df70cad30a6a5ab5760e8, not stripped
```

level01 is compiled as a 32bit ELF file, in a 64bit machine. That's why we had 32bit alike addresses even while being in a 64bit machine.

Now that we know that, why our shellcode in env didn't work ? The code is still in 32bit so the shellcode should still be correct and adapted for this binary ? Well the problem does not come from the shellcode but its address. We wrote a little c file that has to print a 32bit address in little endian format of a specific env variable (accessible at .[/Resources/env_address.c](https://github.com/kbarbry/OverRide/blob/main/level01/Resources/env_address.c))

## Important doc

[Overflow example x86_64](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/64-bit-stack-based-buffer-overflow)