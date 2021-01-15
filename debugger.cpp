#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>

pid_t run_target(const char* programname, const char* args){
    pid_t pid;

    pid = fork();

    if (pid > 0) {
        return pid;

    } else if (pid == 0) {
        /* Allow tracing of this process */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        /* Replace this process's image with the given program */
        execl(programname, args, NULL);

    } else {
        // fork error
        perror("fork");
        exit(1);
    }
}

void super_nice_and_fancy_debugger(){

}

int main(int argc, char** argv){
    void* func_addr = argv[1];
    char* copy_flag = argv[2];
    char* ouput_filename = argv[3];
    char* command = argv + 3;

    pid_t child_pid;
    child_pid = run_target(command[0], command + 1);
    super_nice_and_fancy_debugger();
    return 0;
}