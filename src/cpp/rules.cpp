#include "rules.hpp"

#include <iostream>
#include <queue>

#include "tasks.hpp"

void Rule::runTasksInOrder(std::unordered_set<std::string>& tasks, std::unordered_map<std::string, Rule>& rules) {
    bool did_any_work;

    std::queue<const Rule*> queue;
    for (auto it = rules.begin(); it != rules.end(); it++) {
        Rule* rule = &it->second;
        rule->hasBeenRun = false;
        rule->num_triggs_left = rule->deps_str.size();
        if (rule->num_triggs_left == 0) {
            queue.push(rule);
        }
    }
    do {
        const Rule* rule = queue.front();
        queue.pop();
        // std::cout << "Running: " << rule->name << std::endl;
        for (std::string task : rule->tasks) {
            Task::run(task);
        }
        // for (const auto& it : rules) {}

        for (auto trigger : rule->triggers) {
            trigger->num_triggs_left -= 1;
            if (trigger->num_triggs_left == 0) {
                queue.push(trigger);
            }
        }
    } while (!queue.empty());
    bool hasDoneLabel = false;
    for (const auto& it : rules) {
        if (it.second.num_triggs_left != 0) {
            auto name = it.first;
            if (!hasDoneLabel) {
                std::cout << "Finished with  un-run task(s). You must have a loop!" << std::endl;
                hasDoneLabel = true;
            }
            std::cout << "  " << name << std::endl;
        }
    }
    return;
}