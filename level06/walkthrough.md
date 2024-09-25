You can compile the password_generator.c file with -std=c99 and generate your own password with the login you want, then simply login:

```sh
level06@OverRide:/tmp$ gcc -std=c99 password_generator.c -o pass
level06@OverRide:/tmp$ ./pass passwordyouwant123
Login: passwordyouwant123 - Password: 6238490
level06@OverRide:~$ ./level06 
***********************************
*		level06		  *
***********************************
-> Enter Login: passwordyouwant123
***********************************
***** NEW ACCOUNT DETECTED ********
***********************************
-> Enter Serial: 6238490
Authenticated!
$ whoami
level07
$ cat /home/users/level07/.pass
GbcPDRgsFK77LNnnuh7QyFYA2942Gp8yKj9KrWD8
```
