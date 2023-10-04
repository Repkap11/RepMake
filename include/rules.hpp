#pragma once

#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

class Rule;

class Rule {
   public:
    Rule(std::string name, std::unordered_set<std::string> deps_str, std::vector<std::string> tasks) : name(name), deps_str(deps_str), tasks(tasks) {}

    bool operator==(const Rule& otherRule) const {
        return this->name == otherRule.name;
    }

    struct HashFunction {
        size_t operator()(const Rule& rule) const {
            return std::hash<std::string>()(rule.name);
        }
    };
    bool hasBeenRun = false;
    std::string name;
    std::unordered_set<std::string> deps_str;
    size_t num_triggs_left;
    std::unordered_set<Rule*> triggers;
    std::vector<std::string> tasks;
    static void runTasksInOrder(std::unordered_set<std::string>& tasks, std::unordered_map<std::string, Rule>& rules);
};
