#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>

int main(void) {
    int     status;
    int     tracer;
    char    buffer[128];
    __pid_t pid;

    pid = fork();
    status = 0;
    tracer = 0;
    memset(buffer, 0, sizeof(buffer));

    if (!pid) {
        prctl(1, 1);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        puts("Give me some shellcode, k");
        gets(buffer);
    }
    else {
        do {
            wait(&status);
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                puts("child is exiting...");
                return 0;
            }

            tracer = ptrace(PTRACE_PEEKUSER, pid, 44, 0);
        } while (tracer != 11);     // 11 = execve syscall number (x86)

        puts("no exec() for you");
        kill(pid, SIGKILL);
    }

    return 0;
}
