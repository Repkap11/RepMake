#include "rules.hpp"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/limits.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>
#include <queue>
#include <sstream>

#include "sys_map.hpp"

// https://www.alfonsobeato.net/tag/seccomp/
// https://github.com/alfonsosanchezbeato/ptrace-redirect/blob/master/redir_filter.c
//  https://github.com/skeeto/ptrace-examples/blob/master/minimal_strace.c
// register order https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-and-user-space-f
#if USE_PTRACE
static void read_file(pid_t child, long* dirfd, char* file, long* flags) {
    char* child_addr;
    unsigned long i;

    *dirfd = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RDI, 0);
    *flags = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RDX, 0);

    child_addr = (char*)ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RSI, 0);

    do {
        long val;
        char* p;

        val = ptrace(PTRACE_PEEKTEXT, child, child_addr, NULL);
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

#ifdef __x86_64__
#define SC_NUMBER (8 * ORIG_RAX)
#define SC_RETCODE (8 * RAX)
#else
#define SC_NUMBER (4 * ORIG_EAX)
#define SC_RETCODE (4 * EAX)
#endif

size_t get_tids(pid_t** const listptr, size_t* const sizeptr, const pid_t pid) {
    char dirname[64];
    DIR* dir;
    pid_t* list;
    size_t size, used = 0;

    if (!listptr || !sizeptr || pid < (pid_t)1) {
        errno = EINVAL;
        return (size_t)0;
    }

    if (*sizeptr > 0) {
        list = *listptr;
        size = *sizeptr;
    } else {
        list = *listptr = NULL;
        size = *sizeptr = 0;
    }

    if (snprintf(dirname, sizeof dirname, "/proc/%d/task/", (int)pid) >= (int)sizeof dirname) {
        errno = ENOTSUP;
        return (size_t)0;
    }

    dir = opendir(dirname);
    if (!dir) {
        errno = ESRCH;
        return (size_t)0;
    }

    while (1) {
        struct dirent* ent;
        int value;
        char dummy;

        errno = 0;
        ent = readdir(dir);
        if (!ent)
            break;

        /* Parse TIDs. Ignore non-numeric entries. */
        if (sscanf(ent->d_name, "%d%c", &value, &dummy) != 1)
            continue;

        /* Ignore obviously invalid entries. */
        if (value < 1)
            continue;

        /* Make sure there is room for another TID. */
        if (used >= size) {
            size = (used | 127) + 128;
            list = (pid_t*)realloc(list, size * sizeof(list[0]));
            if (!list) {
                closedir(dir);
                errno = ENOMEM;
                return (size_t)0;
            }
            *listptr = list;
            *sizeptr = size;
        }

        /* Add to list. */
        list[used++] = (pid_t)value;
    }
    if (errno) {
        const int saved_errno = errno;
        closedir(dir);
        errno = saved_errno;
        return (size_t)0;
    }
    if (closedir(dir)) {
        errno = EIO;
        return (size_t)0;
    }

    /* None? */
    if (used < 1) {
        errno = ESRCH;
        return (size_t)0;
    }

    /* Make sure there is room for a terminating (pid_t)0. */
    if (used >= size) {
        size = used + 1;
        list = (pid_t*)realloc(list, size * sizeof list[0]);
        if (!list) {
            errno = ENOMEM;
            return (size_t)0;
        }
        *listptr = list;
        *sizeptr = size;
    }

    /* Terminate list; done. */
    list[used] = (pid_t)0;
    errno = 0;
    return used;
}

void flagsToString(long flags, char* result, size_t result_size) {
    // Initialize the result string as empty
    int length = 0;

    // Check each flag and append its description to the result string
    if (flags == O_RDONLY) {
        length += sprintf(result + length, "O_RDONLY ");
    }
    if (flags & O_WRONLY) {
        length += sprintf(result + length, "O_WRONLY ");
    }
    if (flags & O_RDWR) {
        length += sprintf(result + length, "O_RDWR ");
    }
    if (flags & O_CREAT) {
        length += sprintf(result + length, "O_CREAT ");
    }
    if (flags & O_TRUNC) {
        length += sprintf(result + length, "O_TRUNC ");
    }
    if (flags & O_APPEND) {
        length += sprintf(result + length, "O_APPEND ");
    }
    if (flags & O_CLOEXEC) {
        length += sprintf(result + length, "O_CLOEXEC ");
    }

    // Add more flag checks as needed

    // Remove the trailing space, if any
    size_t len = strlen(result);
    if (len > 0 && result[len - 1] == ' ') {
        result[len - 1] = '\0';
    }
}

int startsWith(const char* str, const char** prefixes) {
    int i = 0;
    const char* prefix = prefixes[i++];
    while (prefix != NULL) {
        if (strncmp(str, prefix, strlen(prefix)) == 0) {
            return 1;  // String starts with one of the prefixes
        }
        prefix = prefixes[i++];
    }
    return 0;  // String does not start with any of the prefixes
}

static int process_signals(pid_t child) {
    const char** sys_map = getSysMap();
    int status;
    // int clone_flag = 0;
    pid_t current_pid = child;
    while (1) {
        // if (clone_flag) {
        //     ptrace(PTRACE_SYSCALL, child, 0, 0);
        // } else {
        ptrace(PTRACE_CONT, current_pid, 0, 0);
        // }
        current_pid = waitpid(0, &status, 0);

        // if (status >> 16 == PTRACE_EVENT_FORK) {
        //     long newpid;
        //     ptrace(PTRACE_GETEVENTMSG, child, NULL, (long)&newpid);
        //     ptrace(PTRACE_SYSCALL, newpid, NULL, NULL);
        //     printf("Attached to offspring %ld\n", newpid);
        // }

        if (WIFEXITED(status)) {
            int child_status = WEXITSTATUS(status);
            if (current_pid == child) {
                // printf("[Child exit with status %d]\n", child_status);
                return child_status;
            } else {
                // printf("[Proc exit with status %d]\n", child_status);
                continue;
            }
        }

        // if (WIFSIGNALED(status)) {
        //     printf("Child exit due to signal %d\n", WTERMSIG(status));
        //     return -1;
        // }
        // if (!WIFSTOPPED(status)) {
        //     printf("wait() returned unhandled status 0x%x\n", status);
        //     return -1;
        // }

        // if (WIFEXITED(status)) {
        //     printf("Child exit with status %d\n", WEXITSTATUS(status));
        //     exit(0);
        // }
        // if (WIFSIGNALED(status)) {
        //     printf("Child exit due to signal %d\n", WTERMSIG(status));
        //     exit(0);
        // }
        // if (!WIFSTOPPED(status)) {
        //     printf("wait() returned unhandled status 0x%x\n", status);
        //     exit(0);
        // }

        // if (WSTOPSIG(status) == SIGTRAP) {
        //     long sc_number, sc_retcode;
        //     /* Note that there are *three* reasons why the child might stop
        //      * with SIGTRAP:
        //      *  1) syscall entry
        //      *  2) syscall exit
        //      *  3) child calls exec
        //      */
        //     sc_number = ptrace(PTRACE_PEEKUSER, child, SC_NUMBER, NULL);
        //     sc_retcode = ptrace(PTRACE_PEEKUSER, child, SC_RETCODE, NULL);
        //     printf("SIGTRAP: syscall %ld, rc = %ld\n", sc_number, sc_retcode);
        // } else {
        //     printf("Child stopped due to signal %d\n", WSTOPSIG(status));
        // }
        //

#if 0
        pid_t* tid = 0;
        size_t tids = 0;
        size_t tids_max = 0;
        size_t t, s;
        long r;
        tids = get_tids(&tid, &tids_max, child);
        if (!tids)
            return -1;

        printf("Process %d has %d tasks,\n", (int)child, (int)tids);
        fflush(stdout);

        /* Attach to all tasks. */
        for (t = 0; t < tids; t++) {
            do {
                r = ptrace(PTRACE_ATTACH, tid[t], (void*)0, (void*)0);
            } while (r == -1L && (errno == EBUSY || errno == EFAULT || errno == ESRCH));
            if (r == -1L) {
                const int saved_errno = errno;
                while (t-- > 0)
                    do {
                        r = ptrace(PTRACE_DETACH, tid[t], (void*)0, (void*)0);
                    } while (r == -1L && (errno == EBUSY || errno == EFAULT || errno == ESRCH));
                tids = 0;
                errno = saved_errno;
                break;
            }
        }
#endif

        int isSECTrap = status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8));

        if (isSECTrap) {
            long syscall = ptrace(PTRACE_PEEKUSER, current_pid, sizeof(long) * ORIG_RAX, 0);
            if (syscall == SYS_openat) {
                char orig_file[PATH_MAX];
                long flags = 0;
                long dirfd = 0;
                read_file(current_pid, &dirfd, orig_file, &flags);
                char flags_str[1024];
                char resolved_path[PATH_MAX];
                realpath(orig_file, resolved_path);

                flagsToString(flags, flags_str, sizeof(flags_str));
                bool isRelativeFile = (int)dirfd == AT_FDCWD;
                const char* prefix_strs[] = {"/tmp/", "/usr/", "/etc/", "/lib/", "/dev/", NULL};
                if (!startsWith(resolved_path, prefix_strs)) {
                    // if (!isRelativeFile) {
                    printf("[Open %d: (%s) %s]\n", isRelativeFile, flags_str, resolved_path);
                }

                // if ((flags & O_CREAT) || (flags & O_WRONLY)) {
                //     printf("[Writing (%s) %s]\n", flags_str, orig_file);
                // }
                // if ((flags == O_RDONLY) || (flags & O_RDWR)) {
                //     printf("[Reading (%s) %s]\n", flags_str, orig_file);
                // }
                // }
            } else {
                printf("Syscall OTHER:%ld:%s\n", syscall, sys_map[syscall]);
            }
        } else {
            // printf("Not isSECTrap\n");
        }
        /* Find out file and re-direct if it is the target */
    }
}
#endif  // USE_PTRACE

static int runTasks(const std::string& name, const std::vector<std::string>& tasks) {
    // TODO make all of these run in the same shell.
    char* cmd = strdup("/usr/bin/bash");
    char* dash_c = strdup("-c");

    std::stringstream ss;
    for (const std::string& task : tasks) {
        std::cout << task << std::endl;
        ss << task << "\n";
        // ss << task;
    }
    std::string comands = ss.str();
    char* args[4] = {cmd, dash_c, (char*)(comands.c_str()), NULL};

    int return_status = 0;
#if DRY_RUN
#else  // not DRY_RUN
#if USE_PTRACE

    pid_t pid = fork();
    if (pid == -1) {
        std::cout << "Fork error" << std::endl;
    }
    if (pid == 0) {  // child pid
        /* If open syscall, trace */
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SYS_openat, 0, 1),
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
            return 1;
        }
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
            perror("when setting seccomp filter");
            return 1;
        }
        kill(getpid(), SIGSTOP);
        execvp(args[0], args);
        // printf("Child process ending\n");
        free(dash_c);
        free(cmd);
        exit(0);
    }
    // orig pid
    // const char** sysMap = getSysMap();
    int status;
    // printf("Parent pid:%d\n\n", pid);
    waitpid(pid, &status, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK);
    return_status = process_signals(pid);
    // printf("Done processing signals.\n");
#else   // not USE_STRACE
    execvp(args[0], args);
#endif  // USE_STRACE
#endif  // DRY_RUN
    free(dash_c);
    free(cmd);
    return return_status;
}

static REPMAKE_TIME getFileTimestamp(REPMAKE_TIME start_time, std::string fileName) {
    struct stat result;
    if (stat(fileName.c_str(), &result) == 0) {
        REPMAKE_TIME mod_time = result.st_mtime * 1000 + result.st_mtim.tv_nsec / 1000000;
        // printf("Mod Ago:%.2f %s\n", -(mod_time - (start_time + 1) * 1000) / 1000.0f, fileName.c_str());
#if RELATIVE_TIME
        return mod_time - start_time;
#else
        return mod_time;
#endif
    } else {
        // printf("Mod Ago:N/A %s\n", fileName.c_str());
        return REPMAKE_OLDEST_TIMESTAMP;
    }
}
REPMAKE_TIME currentTime(void) {
    long ms;   // Milliseconds
    time_t s;  // Seconds
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    REPMAKE_TIME cur_time = spec.tv_sec * 1000 + spec.tv_nsec / 1000000;
    return cur_time;
}

void Rule::runTasksInOrder(const std::unordered_set<std::string>& targets_to_run, std::unordered_map<std::string, Rule>& rules) {
    bool did_any_work;

    REPMAKE_TIME cur_time = currentTime();

    std::queue<Rule*> tasksToRun;
    // Mark any rule directly asked for.
    // Mark every rule with their change_timestamp.
    for (auto it = rules.begin(); it != rules.end(); it++) {
        Rule* rule = &it->second;
        auto pos = targets_to_run.find(rule->name);
        rule->self_modified_timestamp = getFileTimestamp(cur_time, it->first);
        if (pos != targets_to_run.end()) {
            // The rules given in our task are directly asked for, give it a timestamp of right now so it will always be run.
            // targets_to_run.erase(pos);
            rule->hasBeenAddedToTasks = true;
            tasksToRun.push(rule);
        }

        REPMAKE_TIME timestamp = REPMAKE_TIME_MAX;
        for (std::string dep_file : rule->dep_files) {
            REPMAKE_TIME dep_timestamp = getFileTimestamp(cur_time, dep_file);
            if (dep_timestamp < timestamp) {
                timestamp = dep_timestamp;
            }
        }
        rule->deps_modified_timestamp = timestamp;
    }

    // Add all the dependent rules of the requested rules to the tasksToRun queue.
    while (!tasksToRun.empty()) {
        Rule* rule = tasksToRun.front();
        tasksToRun.pop();
        for (Rule* dep : rule->dep_rules) {
            if (!dep->hasBeenAddedToTasks) {
                dep->hasBeenAddedToTasks = true;
                tasksToRun.push(dep);
            }
        }
    }

    // Go through all the rules, and mark as runnable the ones that: 1: We want to run, and 2:Have no dependencies
    std::queue<const Rule*> runnableRules;
    for (auto it = rules.begin(); it != rules.end(); it++) {
        Rule* rule = &it->second;
        if (!rule->hasBeenAddedToTasks) {
            continue;
        }
        int numDepsToRun = 0;
        for (Rule* dep : rule->dep_rules) {
            if (dep->hasBeenAddedToTasks) {
                numDepsToRun++;
            }
        }
        rule->num_triggs_left = numDepsToRun;
        if (rule->num_triggs_left == 0) {
            runnableRules.push(rule);
        }
    }
    bool did_any_task = false;
    // Go through the runnable rules and run them, queueing any dependent rule which can now also be run.
    while (!runnableRules.empty()) {
        const Rule* rule = runnableRules.front();
        runnableRules.pop();

        REPMAKE_TIME self_modified_timestamp = rule->self_modified_timestamp;
        REPMAKE_TIME deps_modified_timestamp = rule->deps_modified_timestamp;
        if (self_modified_timestamp < deps_modified_timestamp) {
            const std::vector<std::string>& tasks = rule->tasks;
            if (tasks.size() != 0) {
                did_any_task = true;
                int ret = runTasks(rule->name, tasks);
                if (ret) {
                    return;
                }
            }
#if RELATIVE_TIME
            self_modified_timestamp = 0;
#else
            self_modified_timestamp = cur_time;
#endif
        }

        // }
        // for (const auto& it : rules) {}
        for (auto trigger : rule->triggers) {
            trigger->num_triggs_left -= 1;
            REPMAKE_TIME trig_deps_modified_timestamp = trigger->deps_modified_timestamp;
            if (trig_deps_modified_timestamp < self_modified_timestamp) {
                trigger->deps_modified_timestamp = self_modified_timestamp;
            }
            if (trigger->hasBeenAddedToTasks && trigger->num_triggs_left == 0) {
                runnableRules.push(trigger);
            }
        }
    }
    if (!did_any_task) {
        std::cout << "Nothing to be done for: [";
        for (std::string target : targets_to_run) {
            std::cout << " " << target;
        }
        std::cout << " ]" << std::endl;
        return;
    }
    bool hasDoneLabel = false;
    for (const auto& it : rules) {
        const Rule& rule = it.second;
        if (rule.hasBeenAddedToTasks && rule.num_triggs_left != 0) {
            if (!hasDoneLabel) {
                std::cout << "Finished with  un-run task(s). You must have a loop!" << std::endl;
                hasDoneLabel = true;
            }
            std::string name = it.first;
            std::cout << "  " << name << std::endl;
        }
    }
    return;
}