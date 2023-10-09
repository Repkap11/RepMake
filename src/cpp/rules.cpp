#include "rules.hpp"

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

static int wait_for_open(pid_t child) {
    int status;

    while (1) {
        ptrace(PTRACE_CONT, child, 0, 0);
        waitpid(child, &status, 0);
        // printf("[waitpid status: 0x%08x]\n", status);
        /* Is it our filter for the open syscall? */
        int got = status >> 8;
        int expected = (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8));
        long peek = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * ORIG_RAX, 0);
        if (status >> 8 == expected && peek == __NR_openat) {
            return 0;
        }
        if (WIFEXITED(status)) {
            return 1;
        }
    }
}

static void read_file(pid_t child, char* file) {
    char* child_addr;
    unsigned long i;


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

static void redirect_file(pid_t child, const char* file) {
    char *stack_addr, *file_addr;

    stack_addr = (char*)ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RSP, 0);
    /* Move further of red zone and make sure we have space for the file name */
    stack_addr -= 128 + PATH_MAX;
    file_addr = stack_addr;

    /* Write new file in lower part of the stack */
    do {
        unsigned long i;
        char val[sizeof(long)];

        for (i = 0; i < sizeof(long); ++i, ++file) {
            val[i] = *file;
            if (*file == '\0') break;
        }

        ptrace(PTRACE_POKETEXT, child, stack_addr, *(long*)val);
        stack_addr += sizeof(long);
    } while (*file);

    /* Change argument to open */
    ptrace(PTRACE_POKEUSER, child, sizeof(long) * RSI, file_addr);
}
static void process_signals(pid_t child) {
    const char* file_to_redirect = "ONE.txt";
    const char* file_to_avoid = "TWO.txt";

    while (1) {
        char orig_file[PATH_MAX];

        /* Wait for open syscall start */
        if (wait_for_open(child) != 0) break;

        /* Find out file and re-direct if it is the target */

        read_file(child, orig_file);
        printf("[Opening %s]\n", orig_file);

        if (strcmp(file_to_avoid, orig_file) == 0){
            redirect_file(child, file_to_redirect);
        }
    }
}

static int runTasks(const std::string& name, const std::vector<std::string>& tasks) {
    // TODO make all of these run in the same shell.
    char* cmd = strdup("/usr/bin/bash");
    char* dash_c = strdup("-c");

    std::stringstream ss;
    for (const std::string& task : tasks) {
        std::cout << task << std::endl;
        ss << task << "\n";
    }
    std::string comands = ss.str();
    char* args[4] = {cmd, dash_c, (char*)(comands.c_str()), NULL};

#if DRY_RUN
#else
    pid_t pid = fork();
    if (pid == -1) {
        std::cout << "Fork error" << std::endl;
    }
    if (pid == 0) {  // child pid
        /* If open syscall, trace */
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 0, 1),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE),
            BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = {
            .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
            .filter = filter,
        };
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        /* To avoid the need for CAP_SYS_ADMIN */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
            perror("prctl(PR_SET_NO_NEW_PRIVS)");
            return 1;
        }
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
            perror("when setting seccomp filter");
            return 1;
        }
        kill(getpid(), SIGSTOP);
        execvp(args[0], args);
        exit(0);
    }
    // orig pid
    const char** sysMap = getSysMap();
    int status;
    waitpid(pid, &status, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP);
    process_signals(pid);

#endif
    free(dash_c);
    free(cmd);
    return 0;
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