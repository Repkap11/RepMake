#pragma once

#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

class Rule;

#define OLDEST_TIMESTAMP 0L

class Rule {
   public:
    Rule(std::string name, std::unordered_set<std::string> deps_str, std::vector<std::string> tasks)  //
        : name(name),
          deps_str(deps_str),
          tasks(tasks) {}

    bool operator==(const Rule& otherRule) const {
        return this->name == otherRule.name;
    }

    struct HashFunction {
        size_t operator()(const Rule& rule) const {
            return std::hash<std::string>()(rule.name);
        }
    };
    bool hasBeenRun = false;
    bool hasBeenAddedToTasks = false;
    std::string name;
    std::unordered_set<std::string> deps_str;
    size_t num_triggs_left;
    std::unordered_set<Rule*> triggers;
    std::unordered_set<Rule*> dep_rules;
    std::unordered_set<std::string> dep_files;
    std::vector<std::string> tasks;
    uint64_t self_modified_timestamp;
    uint64_t deps_modified_timestamp;
    static void runTasksInOrder(std::unordered_set<std::string>& targets_to_run, std::unordered_map<std::string, Rule>& rules);
};
