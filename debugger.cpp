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

void super_nice_and_fancy_debugger(pid_t child_pid, void* address, char* copy_flag,
        char* output_filename){
    int wait_status;
    struct user_regs_struct regs;

    /* Wait for child to stop on its first instruction */

    unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)address, NULL);
    unsigned long data_trap = (data & 0xFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap);

    wait(&wait_status);
    while(WIFSTOPPED(wait_status)){
        /* Iterating breakpoints*/
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);

        /* See where the child is now */
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

        /* Remove the breakpoint by restoring the previous data and set rdx = 5 */
        ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data);
        regs.rip -= 1;
//        regs.rdx = 5; // Not sure we need this
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

        /* Make the child execute another instruction */
        if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
            perror("ptrace");
            return;
        }
        /* Wait for child to stop on its next instruction */
        wait(&wait_status);
        if(!WIFSTOPPED(wait_status)){
            break;
        }

    /*
     * TODO need to determine function exit address
     * TODO Iterate over sys.write and handle as specified
    */

    }
    wait(&wait_status);
    if (WIFEXITED(wait_status)) {
        /* Child process exited */
        return;
    } else {
        printf("Not a good place to be in");
    }
}

int main(int argc, char** argv){
    void* func_addr = argv[1];
    char* copy_flag = argv[2];
    char* ouput_filename = argv[3];
    char* command = argv + 3;

    pid_t child_pid;
    child_pid = run_target(command[0], command + 1);
    super_nice_and_fancy_debugger(child_pid, func_addr, copy_flag, ouput_filename);
    return 0;
}