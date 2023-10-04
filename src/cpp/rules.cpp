#include "rules.hpp"

#include <iostream>
#include <queue>

#include "tasks.hpp"

void Rule::runTasksInOrder(std::unordered_set<std::string>& targets_to_run, std::unordered_map<std::string, Rule>& rules) {
    bool did_any_work;

    std::queue<const Rule*> tasksToRun;
    for (auto it = rules.begin(); it != rules.end(); it++) {
        Rule* rule = &it->second;
        auto pos = targets_to_run.find(rule->name);
        if (pos != targets_to_run.end()) {
            rule->hasBeenAddedToTasks = true;
            tasksToRun.push(rule);
        }
    }

    while (!tasksToRun.empty()) {
        const Rule* rule = tasksToRun.front();
        tasksToRun.pop();
        for (Rule* dep : rule->deps) {
            if (!dep->hasBeenAddedToTasks) {
                dep->hasBeenAddedToTasks = true;
                tasksToRun.push(dep);
            }
        }
    }

    std::queue<const Rule*> queue;
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
            queue.push(rule);
        }
    }
    while (!queue.empty()) {
        const Rule* rule = queue.front();
        queue.pop();
        // std::cout << "Running: " << rule->name << std::endl;
        for (std::string task : rule->tasks) {
            Task::run(task);
        }
        // for (const auto& it : rules) {}

        for (auto trigger : rule->triggers) {
            trigger->num_triggs_left -= 1;
            if (trigger->hasBeenAddedToTasks && trigger->num_triggs_left == 0) {
                queue.push(trigger);
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