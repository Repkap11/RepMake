#include "rules.hpp"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <queue>

static int runTasks(const Rule* rule) {
    // TODO make all of these run in the same shell.
    for (std::string task : rule->tasks) {
        std::cout << task << std::endl;
        int ret = system(task.c_str());
        if (ret != 0) {
            std::cout << "Task failed for Target: " << rule->name << std::endl;
            return ret;
        }
    }
    return 0;
}

static uint64_t getFileTimestamp(std::string fileName) {
    struct stat result;
    if (stat(fileName.c_str(), &result) == 0) {
        uint64_t mod_time = result.st_mtime * 1000 + result.st_mtim.tv_nsec / 1000000;
        // printf("Mod Ago:%.2f %s\n", -(mod_time - (start_time + 1) * 1000) / 1000.0f, fileName.c_str());
        return mod_time;
    } else {
        // printf("Mod Ago:N/A %s\n", fileName.c_str());
        return OLDEST_TIMESTAMP;
    }
}
uint64_t currentTime(void) {
    long ms;   // Milliseconds
    time_t s;  // Seconds
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    uint64_t cur_time = spec.tv_sec * 1000 + spec.tv_nsec / 1000000;
    return cur_time;
}

void Rule::runTasksInOrder(std::unordered_set<std::string>& targets_to_run, std::unordered_map<std::string, Rule>& rules) {
    bool did_any_work;

    uint64_t cur_time = currentTime();

    std::queue<Rule*> tasksToRun;
    // Mark any rule directly asked for.
    // Mark every rule with their change_timestamp.
    for (auto it = rules.begin(); it != rules.end(); it++) {
        Rule* rule = &it->second;
        auto pos = targets_to_run.find(rule->name);
        if (pos != targets_to_run.end()) {
            // The rules given in our task are directly asked for, give it a timestamp of right now so it will always be run.
            rule->self_modified_timestamp = OLDEST_TIMESTAMP;
            targets_to_run.erase(pos);
            rule->hasBeenAddedToTasks = true;
            tasksToRun.push(rule);
        } else {
            // The rule wasn't asked for, give it it's real modified timestamp based in the files it depends on.
            rule->self_modified_timestamp = getFileTimestamp(it->first);
            uint64_t timestamp = UINT64_MAX;
            for (std::string dep_file : rule->dep_files) {
                uint64_t dep_timestamp = getFileTimestamp(dep_file);
                if (dep_timestamp < timestamp) {
                    timestamp = dep_timestamp;
                }
            }
            rule->deps_modified_timestamp = timestamp;
            std::cout << "";
        }
    }

    // Print any errors if an asked for rule wasn't found.
    if (!targets_to_run.empty()) {
        std::cout << "No targets found: [";
        for (std::string target : targets_to_run) {
            std::cout << " " << target;
        }
        std::cout << " ]" << std::endl;

        std::cout << "Known rules are: [";
        for (auto rule : rules) {
            std::cout << " " << rule.first;
        }
        std::cout << " ]" << std::endl;
        return;
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
    // Go through the runnable rules and run them, queueing any dependent rule which can now also be run.
    while (!runnableRules.empty()) {
        const Rule* rule = runnableRules.front();
        runnableRules.pop();

        uint64_t self_modified_timestamp = rule->self_modified_timestamp;
        uint64_t deps_modified_timestamp = rule->deps_modified_timestamp;
        int64_t time_diff = self_modified_timestamp - deps_modified_timestamp;
        if (time_diff < 0) {
            int ret = runTasks(rule);
            if (ret) {
                std::cout << "Task failed!" << std::endl;
                return;
            }
            self_modified_timestamp = cur_time;
        }

        // }
        // for (const auto& it : rules) {}
        for (auto trigger : rule->triggers) {
            trigger->num_triggs_left -= 1;
            uint64_t trig_deps_modified_timestamp = trigger->deps_modified_timestamp;
            if (trig_deps_modified_timestamp < self_modified_timestamp) {
                trigger->deps_modified_timestamp = self_modified_timestamp;
            }
            if (trigger->hasBeenAddedToTasks && trigger->num_triggs_left == 0) {
                runnableRules.push(trigger);
            }
        }
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