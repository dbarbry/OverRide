You can compile with gcc adding the -std=c99 flag and execute it to have the password printed, then use it to connect to level03.

```sh
level03@OverRide:/tmp$ gcc -std=c99 reverse_translate.c 
level03@OverRide:/tmp$ ./a.out

[...]

Final ASCII: Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
level03@OverRide:/tmp$ su level03
```
