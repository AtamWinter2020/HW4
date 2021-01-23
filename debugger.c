#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

#define PREFIX "PRF:: "
#define CONTINUE                                              \
    do {                                                      \
        if (ptrace(PTRACE_CONT, child_pid, NULL, NULL) < 0) { \
            perror("ptrace CONT");                            \
            exit(1);                                          \
        }                                                     \
    } while (0)
#define SYSCALL                                                  \
    do {                                                         \
        if (ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL) < 0) { \
            perror("ptrace SYSCALL");                            \
            exit(1);                                             \
        }                                                        \
    } while (0)

#define GETREGS(regs_ptr)                                         \
    do {                                                          \
        if (ptrace(PTRACE_GETREGS, child_pid, 0, regs_ptr) < 0) { \
            perror("ptrace GETREGS");                             \
            exit(1);                                              \
        }                                                         \
    } while (0)

#define SETREGS(regs_ptr)                                         \
    do {                                                          \
        if (ptrace(PTRACE_SETREGS, child_pid, 0, regs_ptr) < 0) { \
            perror("ptrace SETREGS");                             \
            exit(1);                                              \
        }                                                         \
    } while (0)

#define PEEKDATA(DATA_VAR, ADDR)                                            \
    do {                                                                    \
        DATA_VAR =                                                          \
            (void*)ptrace(PTRACE_PEEKDATA, child_pid, (void*)(ADDR), NULL); \
        if ((void*)(DATA_VAR) == (void*)0xffffffffffffffff) {               \
            perror("ptrace PEEKDATA");                                      \
            exit(1);                                                        \
        }                                                                   \
    } while (0)

#define CEIL(x) ((x) == (int)(x) ? (x) : ((int)(x) + 1))

pid_t run_target(const char* programname, char* const* args) {
    pid_t pid;

    pid = fork();

    if (pid > 0) {
        return pid;

    } else if (pid == 0) {
        /* Allow tracing of this process */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace1");
            exit(1);
        }
        /* Replace this process's image with the given program */
        execv(programname, args);

    } else {
        // fork error
        perror("fork");
        exit(1);
    }
    // perror("weird");
    // exit(1);
}

void place_breakpoint(pid_t child_pid, void* func_addr, long* data_backup) {
    *data_backup = ptrace(PTRACE_PEEKTEXT, child_pid, func_addr, NULL);
    if (*data_backup == 0xffffffffffffffff) {
        perror("ptrace PEEKTEXT");
        exit(1);
    }
    long ret = ptrace(PTRACE_POKETEXT, child_pid, (void*)func_addr,
                      (void*)(((*data_backup) & 0xFFFFFFFFFFFFFF00) | 0xCC));
    if (ret == 0xffffffffffffffff) {
        perror("ptrace POKETEXT");
        exit(1);
    }
}

void restore_data(pid_t child_pid, void* func_addr, unsigned long data_backup,
                  struct user_regs_struct* regs_ptr) {
    long ret;
    GETREGS(regs_ptr);
    regs_ptr->rip -= 1;
    if ((void*)regs_ptr->rip != func_addr) {
        fprintf(stderr,
                "Restore data called when rip (0x%lx) is not on the expected "
                "address (0x%lx).\n",
                (unsigned long)regs_ptr->rip, (unsigned long)func_addr);
        exit(1);
    }
    SETREGS(regs_ptr);

    ret = ptrace(PTRACE_POKETEXT, child_pid, func_addr, data_backup);
    if (ret < 0) {
        perror("ptrace POKETEXT");
        exit(1);
    }
}

int run_to(pid_t child_pid, void* func_addr,
           struct user_regs_struct* regs_ptr) {
    unsigned long data_backup;

    // Set breakpoint
    place_breakpoint(child_pid, func_addr, &data_backup);

    // Continue until breakpoint hit
    CONTINUE;
    int wait_status;
    wait(&wait_status);
    if (!WIFSTOPPED(wait_status)) {
        if (WIFEXITED(wait_status)) {
            return 1;
        }
        perror("ptrace continue");
        exit(1);
    }
    // Remove breakpoint (restore original instruction)
    restore_data(child_pid, func_addr, data_backup, regs_ptr);
    return 0;
}

void read_to_buffer(pid_t child_pid, void* start_addr, size_t bytes,
                    char* buffer) {
    int words_count = CEIL(bytes / 8.0);
    void* data;
    for (int i = 0; i < words_count; i++) {
        PEEKDATA(data, start_addr + 8 * i);
        if ((i + 1) * 8 > bytes) {
            memcpy(buffer + 8 * i, &data, bytes - i * 8);
            // for(int j = 0; j<(((i + 1) * 8)-bytes); j++){
            //     (buffer+8*i)[j] = data[j];
            // }
            // TODO: Take only part
        } else {
            ((unsigned long*)buffer)[i] =
                (unsigned long)data;  // TODO: Read data
        }
    }
}

void super_nice_and_fancy_debugger(pid_t child_pid, void* address,
                                   char* copy_flag, char* output_filename) {
    int wait_status;
    long orig_rsp;
    long ret_data_backup;
    struct user_regs_struct regs;
    void* ret_addr;
    FILE* out_file = fopen(output_filename, "w");
    if (out_file == NULL) {
        perror("fopen");
        exit(1);
    }

    /* Wait for child to stop on its first instruction */

    wait(&wait_status);
    if (!WIFSTOPPED(wait_status)) {
        fprintf(stderr, "Expected breakpoint but never got one.\n");
        exit(1);
    }
    while (1) {
        // Run to func entry
        if (run_to(child_pid, address, &regs) == 1) {
            fclose(out_file);
            return;
        }
        orig_rsp = regs.rsp;

        // Put breakpoint in ret addr
        // Get ret addr
        PEEKDATA(ret_addr, regs.rsp);
        place_breakpoint(child_pid, ret_addr, &ret_data_backup);

        do {
            SYSCALL;
            wait(&wait_status);
            if (!WIFSTOPPED(wait_status)) {
                fprintf(stderr,
                        "Function never returned. Expected syscall or "
                        "interrupt.\n");
                exit(1);
            }
            GETREGS(&regs);
            long orig_rdx = regs.rdx;
            if ((void*)(regs.rip - 1) == ret_addr) {
                if (orig_rsp <= regs.rsp) {
                    break;
                } else {
                    restore_data(child_pid, ret_addr, ret_data_backup, &regs);
                    ptrace(PTRACE_SINGLESTEP, child_pid, 0, NULL);
                    wait(&wait_status);
                    if (!WIFSTOPPED(wait_status)) {
                        fprintf(stderr, "Wait for single step failed.\n");
                        exit(1);
                    }
                    place_breakpoint(child_pid, ret_addr, &ret_data_backup);
                    continue;
                }
            } else if (regs.orig_rax == 1 &&
                       (regs.rdi == 1 ||
                        regs.rdi == 2)) {  // sys_write and to stdout
                char* data = calloc(regs.rdx + 1, sizeof(char));
                read_to_buffer(child_pid, (void*)regs.rsi, regs.rdx, data);
                fwrite(PREFIX, 1, strlen(PREFIX), out_file);
                fwrite(data, 1, regs.rdx, out_file);
                fflush(out_file);
                free(data);

                if (*copy_flag == 'm' && copy_flag[1] == '\0') {
                    regs.rdx = 0;
                    SETREGS(&regs);
                }
                // else { // Uncomment this section if you want prefix when printing to the screen as well.
                //     // Assumed as copy ('c') so don't skip the syscall
                //     printf(PREFIX);
                //     fflush(stdout);
                // }
            }
            SYSCALL;
            wait(&wait_status);
            if (!WIFSTOPPED(wait_status)) {
                fprintf(stderr, "Function never returned from syscall.\n");
                exit(1);
            }
            regs.rdx = orig_rdx;
            SETREGS(&regs);
        } while (1);
        restore_data(child_pid, ret_addr, ret_data_backup, &regs);
    }
}

int main(int argc, char** argv) {
    char* func_addr_str = argv[1];
    char* copy_flag = argv[2];
    char* ouput_filename = argv[3];
    char** command = argv + 4;
    char* end_ptr;
    long long func_addr = strtol(func_addr_str, &end_ptr, 16);
    if (end_ptr != func_addr_str + strlen(func_addr_str)) {
        fprintf(stderr, "Failed to convert input from hex to long.\n");
        exit(1);
    }

    pid_t child_pid;
    child_pid = run_target(command[0], command);
    super_nice_and_fancy_debugger(child_pid, (void*)func_addr, copy_flag,
                                  ouput_filename);
    return 0;
}