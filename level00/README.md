# level00

Here we go again, for OverRide this time. The rules are the same as our [Rainfall](https://github.com/kbarbry/RainFall) and we will organize it the same way. So let's start with level00.

### First analysis

The very first element we can observe when joining this project is the result of the hecksec command automatically printed when login in as level00:

```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   /home/users/level00/level00
```

We can observe that PIE (Position Independent Executable) is still not activated same for RPATH and RUNPATH, and same for the STACK CANARY. However RELRO is partially activated apparently, and NX is enabled. For more informations on what all of this means check [here](https://github.com/kbarbry/RainFall/blob/7548e94133c768d509c06f371aa61ba6306837a0/level3/README.md#strange-login-output-digression), we made a more detailed explanation of each parameters. To simply describe what happens here, RELRO is a security added to protect from GOT (Global Offset Table) arbitrary write. We used this type of attacks in RainFall where we override the address of a libc function such as exit() and we redirected it to a malicious part of the binary. When RELRO is activated, the GOT, PLT (Procedure Linkage Table), so the .got, .got.plt and .fini_array are in read only and this exploit is not possible anymore. However when being only partially activated (which is the default option in gcc), only the GOT (so .got) is in read only, the .got.plt and .fini_array are still vulnerable. For NX, it simply defines if certains zone of the memory is executable or not, depending on the OS and distribution, here for exemple we can expect the stack to block execution, which stops us from using a lot of other exploits we used in RainFall.

Now that we are okay and clear about what these 2 lines mean (we probably will have to pay attention to that in the next levels), we can analyze the actual code of level00 present in source.c like always:

```c
int main(void) {
    int password;

    puts("***********************************");
    puts("* \t     -Level00 -\t\t  *");
    puts("***********************************");
    printf("Password:");

    scanf("%d", password);

    if (password == 0x149c) {
        puts("\nAuthenticated!");
        system("/bin/sh");
    } else {
        puts("\nInvalid Password!");
        return 1;
    }

    return 0;
}
```

The program prints some sort of header, then open a scanf, and wait for a user input, if this input = 0x149c, we get a shell, else we leave the program.

### Finding the solution

The solution seems very easy and logic, simply convert 0x149c in decimal gives us 5276 (we have to convert it because scanf accept base10 number input). And by using this password we get:

```sh
level00@OverRide:~$ ./level00 
***********************************
* 	     -Level00 -		  *
***********************************
Password:5276

Authenticated!
$ whoami
level01
$ cat /home/users/level01/.pass 
uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL
```

## Important doc

[Partial RELRO vs Full RELRO](https://book.hacktricks.xyz/binary-exploitation/common-binary-protections-and-bypasses/relro)