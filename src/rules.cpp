#include "rules.hpp"

#include <string.h>
#include <sys/stat.h>

#include <queue>
#include <sstream>

#include "trace_tasks.hpp"

static void runTasks(std::queue<Rule*>& tasksToRun,                 //
                     std::map<std::string, Rule>& rules,  //
                     Rule* rule,                                    //
                     const std::vector<std::string>& tasks,
                     int* ret, int* didFinish) {
    // TODO make all of these run in the same shell.
    char* cmd = strdup("/usr/bin/bash");
    char* dash_c = strdup("-c");
    char* dash_x = strdup("-x");

    std::stringstream ss;
    for (const std::string& task : tasks) {
        ss << task << "\n";
    }
    std::string comands = ss.str();
    char* args[5] = {cmd, dash_x, dash_c, (char*)(comands.c_str()), NULL};

    *ret = trace_tasks(tasksToRun, rules, rule, args, didFinish);

    free(dash_c);
    free(dash_x);
    free(cmd);
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

void Rule::runTasksInOrder(const std::unordered_set<std::string>& targets_to_run, std::map<std::string, Rule>& rules) {
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

    bool did_any_task = false;
    // Add all the dependent rules of the requested rules to the tasksToRun queue.
    while (!tasksToRun.empty()) {
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
        std::queue<Rule*> runnableRules;
        for (auto it = rules.begin(); it != rules.end(); it++) {
            Rule* rule = &it->second;
            if (rule->isFinished) {
                continue;
            }
            if (!rule->hasBeenAddedToTasks) {
                continue;
            }
            int numDepsToRun = 0;
            for (Rule* dep : rule->dep_rules) {
                if (dep->hasBeenAddedToTasks && !dep->isFinished) {
                    numDepsToRun++;
                }
            }
            rule->num_triggs_left = numDepsToRun;
            if (rule->num_triggs_left == 0) {
                runnableRules.push(rule);
            }
        }
        // Go through the runnable rules and run them, queueing any dependent rule which can now also be run.
        while (!runnableRules.empty()) {
            Rule* rule = runnableRules.front();
            runnableRules.pop();

            if (rule->num_triggs_left != 0) {
                continue;
            }

            REPMAKE_TIME self_modified_timestamp = rule->self_modified_timestamp;
            REPMAKE_TIME deps_modified_timestamp = rule->deps_modified_timestamp;
            int didFinish = true;
            if (self_modified_timestamp < deps_modified_timestamp) {
                const std::vector<std::string>& tasks = rule->tasks;
                if (tasks.size() != 0) {
                    did_any_task = true;
                    int ret;
                    runTasks(tasksToRun, rules, rule, tasks, &ret, &didFinish);
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
            if (!didFinish) {
                continue;
            }
            rule->isFinished = true;
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