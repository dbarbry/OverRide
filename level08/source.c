#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

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
