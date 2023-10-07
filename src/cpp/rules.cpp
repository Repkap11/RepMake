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

static long getFileTimestamp(long start_time, std::string fileName) {
    struct stat result;
    if (stat(fileName.c_str(), &result) == 0) {
        long mod_time = result.st_mtime;
        printf("Mod Ago:%ld %s\n", -(mod_time - start_time), fileName.c_str());
        return mod_time;
    } else {
        printf("Mod Ago:N/A %s\n", fileName.c_str());
        return start_time;
    }
}

void Rule::runTasksInOrder(std::unordered_set<std::string>& targets_to_run, std::unordered_map<std::string, Rule>& rules) {
    bool did_any_work;

    long start_time = time(NULL);
    std::queue<Rule*> tasksToRun;
    // Mark any rule directly asked for.
    // Mark every rule with their change_timestamp.
    for (auto it = rules.begin(); it != rules.end(); it++) {
        Rule* rule = &it->second;
        auto pos = targets_to_run.find(rule->name);
        if (pos != targets_to_run.end()) {
            // The rules given in our task are directly asked for, give it a timestamp of right now so it will always be run.
            rule->change_timestamp = 0;
            targets_to_run.erase(pos);
            if (rule->change_timestamp <= start_time) {
                rule->hasBeenAddedToTasks = true;
                tasksToRun.push(rule);
            }
        } else {
            // The rule wasn't asked for, give it it's real modified time stamp.
            rule->change_timestamp = getFileTimestamp(start_time, it->first);
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
        for (Rule* dep : rule->deps) {
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
        for (Rule* dep : rule->deps) {
            if (dep->hasBeenAddedToTasks) {
                numDepsToRun++;
            }
        }
        rule->num_triggs_left = numDepsToRun;
        if (rule->num_triggs_left == 0) {
            rule->newest_dep_timestamp = rule->change_timestamp;
            runnableRules.push(rule);
        }
    }
    // Go through the runnable rules and run them, queueing any dependent rule which can now also be run.
    while (!runnableRules.empty()) {
        const Rule* rule = runnableRules.front();
        runnableRules.pop();
        long rule_timestamp = rule->newest_dep_timestamp;

        if (rule_timestamp > rule->change_timestamp) {
            int ret = runTasks(rule);
            if (ret) {
                return;
            }
        }
        // }
        // for (const auto& it : rules) {}
        for (auto trigger : rule->triggers) {
            trigger->num_triggs_left -= 1;
            long trig_newest_dep_timestamp = trigger->newest_dep_timestamp;
            if (rule_timestamp > trig_newest_dep_timestamp) {
                trigger->newest_dep_timestamp = rule_timestamp;
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