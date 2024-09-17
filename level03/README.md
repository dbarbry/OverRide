# level03

### First analysis

As always let's analyse the checksec first because this time we can find some good security.

```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   /home/users/level03/level03
```

Here we have the partial RELRO, we know that being partial some GOT overwrite are still possible but the .got is in readonly. However here we have a Stack canary, and we have NX enabled. For NX we know that it probably means that the stack is not executable, so probably no shellcode possible in the stack nor the environment variables (which are in the stack too). For the Stack Canary it is supposed to place random values at the end of some part of the stack, so if some overflows are caused, the canary will be moved, and not be correct anymore. The stack canary is supposed to protect the stack from oveflows.

Now let's analyse the code, which is very special:

```c
void    decrypt(unsigned int key) {
    int     len;
    char    str[29];

    strcpy(str, "Q}|u`sfg~sf{}|a3");
    len = strlen(str);

    for (int i = 0; i < len; i++)
        str[i] ^= key;
    
    if (!strcmp(str, "Congratulations!"))
        return system("/bin/sh");
    
    return puts("\nInvalid Password");
}

void    test(int input, int secret) {
    int diff;

    diff = secret - input;
    if ((diff > 0 && diff < 10) || (diff > 15 && diff < 22))
        decrypt(diff);
    else
        decrypt(rand());

    return;
}

int main(void) {
    unsigned int    __seed;
    int             input;

    __seed = time((time_t *)0);
    srand(__seed);

    puts("***********************************");
    puts("*\t\tlevel03\t\t**");
    puts("***********************************");

    printf("Password:");
    scanf("%d", &input);
    test(input, 322424845);

    return 0;
}
```

We have a user input that will be used in a test function, in this test function we are going to subsctract the user input by 322424845. And if the result is betwen 0 and 10 or 15 and 22, we will call a decrypt function with this result, else we will call this decrypt function with a random number. In the decrypt function we make something called a XOR-based encryption, an encryption system comparing the bytes of every character and making a XOR operation on it. This is a very weak way to encrypt data, plus we have two elements, the base or entry value which is "Q}|u`sfg~sf{}|a3" and the solutions that has to be equal to "Congratulations!". We only have to find the key.

In order to do that we have 2 ways possible, first we have to try solutions between 0 and 10 and between 15 and 22 if the solution is here, this won't be too hard. However if no solutions are found, we might have to go deeper into the rand function, change the date and hour to a precise second where the result is a key of decryption since srand use the timestamp in order to randomize the seed and that for a same seed we can predict the result.

Let's explore the first option to begin with, we wrote a little code decrypt.c that simply try all the options between 0 and 20 and check if they work as key and gives us the result expected:

```c
int main(void) {
    char    *original = "Q}|u`sfg~sf{}|a3";
    int     len = strlen(original);
    char    entry[len + 1];
    char    *key;

    for (int i = 0; i < 21; i++) {
        strcpy(entry, original);
        for (int j = 0; j < len; j++) {
            entry[j] ^= i;
        }
        printf("%2d - %s\n", i, entry);
    }
}
```

Very straightforward and there are probably way easier ways of doing that but this is what we did. Now let's try to execute it and see the result:

```
level01@OverRide:/tmp$ gcc decrypt.c -o decrypt
level01@OverRide:/tmp$ ./decrypt 
 0 - Q}|u`sfg~sf{}|a3
 1 - P|}targfrgz|}`2
 2 - S~wbqde|qdy~c1
 3 - R~vcped}pex~b0
 4 - Uyxqdwbczwbyxe7
 5 - Txypevcb{vc~xyd6
 6 - W{zsfu`axu`}{zg5
 7 - Vz{rgta`yta|z{f4
 8 - Yut}h{nov{nsuti;
 9 - Xtu|izonwzortuh:
10 - [wvjylmtylqwvk9
11 - Zvw~kxmluxmpvwj8
12 - ]qpyljkrjwqpm?
13 - \pqxm~kjs~kvpql>
14 - _sr{n}hip}husro=
15 - ^rszo|ihq|itrsn<
16 - Amlepcvwncvkmlq#
17 - @lmdqbwvobwjlmp"
18 - Congratulations!
19 - Bnofs`utm`uhnor 
20 - Eihatgrsjgroihu'
```

As we can see, 18 gives us the result expected, we won't have to go through a probably tedious process to manipulate random() functions. Now that we know that 18 is the solutions, we just have to do 322424845 - 18 = 322424827 ans we get:

```sh
level03@OverRide:~$ ./level03 
***********************************
*		level03		**
***********************************
Password:322424827
$ whoami
level04
$ cat /home/users/level04/.pass
kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
```

## Important doc

[XOR Cipher](https://en.wikipedia.org/wiki/XOR_cipher)
