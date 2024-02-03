#include "trace_tasks.hpp"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>
#include <queue>

#include "utils.hpp"

#define VERBOSE_DEBUG 0

// https://www.alfonsobeato.net/tag/seccomp/
// https://github.com/alfonsosanchezbeato/ptrace-redirect/blob/master/redir_filter.c
//  https://github.com/skeeto/ptrace-examples/blob/master/minimal_strace.c
// register order https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-and-user-space-f
static void read_file(pid_t pid, long reg, char* file) {
    char* child_addr;
    unsigned long i;

    child_addr = (char*)reg;

    do {
        long val;
        char* p;

        val = ptrace(PTRACE_PEEKTEXT, pid, child_addr, NULL);
        if (val == -1) {
            fprintf(stderr, "PTRACE_PEEKTEXT error: %s", strerror(errno));
            exit(1);
        }
        child_addr += sizeof(long);

        p = (char*)&val;
        for (i = 0; i < sizeof(long); ++i, ++file) {
            *file = *p++;
            if (*file == '\0') break;
        }
    } while (i == sizeof(long));
}

static int parent(std::queue<Rule*>& tasksToRun, std::map<std::string, Rule>& rules, Rule* rule, pid_t child, pid_t current_pid, int* didFinish) {
    int status;
    while (1) {
        ptrace(PTRACE_CONT, current_pid, 0, 0);

        current_pid = waitpid(0, &status, 0);

        if (WIFEXITED(status)) {
            int child_status = WEXITSTATUS(status);
            if (current_pid == child) {
                // printf("[Child exit with status %d]\n", child_status);
                *didFinish = true;
                return child_status;
            } else {
                // printf("[Proc exit with status %d]\n", child_status);
                continue;
            }
        }

        int isSECTrap = status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8));
        if (!isSECTrap) {
            continue;
        }
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, current_pid, 0, &regs) == -1) {
            if (errno == ESRCH) {
                printf("Child is exiting:%d: %s\n", errno, strerror(errno));
            } else {
                printf("Get Regs Error %d: %s\n", errno, strerror(errno));
            }
        }
        long syscall = regs.orig_rax;
        char orig_file[PATH_MAX];
        if (syscall == SYS_access) {
            read_file(current_pid, regs.rdi, orig_file);
        } else if (syscall == SYS_execve) {
            read_file(current_pid, regs.rdi, orig_file);
        } else if (syscall == SYS_openat) {
            long dirfd = regs.rdi;
            long flags = regs.rdx;
            bool isRelativeFile = (int)dirfd == AT_FDCWD;
            if (!isRelativeFile) {
                // Not a relitive path, it's something strange give up.
                continue;
            }
            // char flags_str[1024];
            // flagsToString(flags, flags_str, sizeof(flags_str));
            if (!(flags == O_RDONLY) || (flags & O_RDWR)) {
                // Not reading the file, don't care.
                continue;
            }
            read_file(current_pid, regs.rsi, orig_file);
        } else {
            // Some other syscall, we don't care.
            continue;
        }

        char resolved_path[PATH_MAX];
        realpath(orig_file, resolved_path);
        const char* prefix_strs[] = {"/tmp/", "/usr/", "/etc/", "/lib/", "/dev/", NULL};
        // const char* prefix_strs[] = {NULL};
        if (str_startsWith(orig_file, prefix_strs)) {
            // Starts with a path we don't care about.
            continue;
        }
        const char* equal_strs[] = {"/tmp", NULL};
        // const char* equal_strs[] = {NULL};
        if (str_equalsAny(orig_file, equal_strs)) {
            // Starts with a path we don't care about.
            continue;
        }

        int fd = openat(AT_FDCWD, resolved_path, O_RDONLY);
        bool file_avail = fd >= 0;
        close(fd);

        Rule* matching_rule = NULL;
        for (auto& it : rules) {
            Rule& rule = it.second;
            if (strcmp(rule.resolved_name, resolved_path) == 0) {
                matching_rule = &rule;
                break;
            }
        }
        if (matching_rule == NULL) {
            // This file isn't one of our rules, just let the open fail.
            if (file_avail) {
                // The file exists.
                rule->dep_files.insert(orig_file);
            }
            continue;
        }

        if (VERBOSE_DEBUG) {
            printf("[Our rule is missing: %s]\n", matching_rule->name.c_str());
        }

        matching_rule->hasBeenAddedToTasks = true;
        tasksToRun.push(matching_rule);

        matching_rule->triggers.insert(rule);
        rule->dep_rules.insert(matching_rule);
        rule->dep_files.insert(matching_rule->name);
        // rule->num_triggs_left += 1;
        rule->blocked_child = child;
        rule->blocked_work = current_pid;
        *didFinish = false;
        return 0;
    }
}

static void child(char** args) {
    /* If open syscall, trace */
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SYS_openat, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SYS_access, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SYS_execve, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    /* To avoid the need for CAP_SYS_ADMIN */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        perror("when setting seccomp filter");
        return;
    }
    kill(getpid(), SIGSTOP);
    execvp(args[0], args);
}

int trace_tasks(std::queue<Rule*>& tasksToRun, std::map<std::string, Rule>& rules, Rule* rule, char** args, int* didFinish) {
    if (rule->blocked_work != 0) {
        pid_t child = rule->blocked_child;
        pid_t current_pid = rule->blocked_work;
        ptrace(PTRACE_SYSCALL, current_pid, 0, 0);  // do the syscall
        int status;
        struct user_regs_struct regs;
        current_pid = waitpid(0, &status, 0);
        if (ptrace(PTRACE_GETREGS, current_pid, 0, &regs) == -1) {
            if (errno == ESRCH) {
                printf("Child is exiting2:%d: %s\n", errno, strerror(errno));
            } else {
                printf("Get Regs Error2 %d: %s\n", errno, strerror(errno));
            }
        }
        long syscall_ret = regs.rax;
        bool openAtSuccess = syscall_ret >= 0;
        if (VERBOSE_DEBUG) {
            printf("[Resuming work:%s fd:%ld]\n", rule->name.c_str(), syscall_ret);
        }
        return parent(tasksToRun, rules, rule, child, current_pid, didFinish);
    }
    pid_t pid = fork();
    if (pid == -1) {
        std::cout << "Fork error" << std::endl;
    }
    if (pid == 0) {
        child(args);
        exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK);
    return parent(tasksToRun, rules, rule, pid, pid, didFinish);
}