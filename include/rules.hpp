#pragma once

#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "limits.h"

class Rule;

#define RELATIVE_TIME 0

#if RELATIVE_TIME
#define REPMAKE_TIME int64_t
#define REPMAKE_TIME_MAX INT64_MAX
#define REPMAKE_OLDEST_TIMESTAMP INT64_MIN

#else
#define REPMAKE_TIME uint64_t
#define REPMAKE_TIME_MAX UINT64_MAX
#define REPMAKE_OLDEST_TIMESTAMP 0
#endif

class Rule {
   public:
    Rule(std::string name, std::unordered_set<std::string> deps_str, std::vector<std::string> tasks)  //
        : name(name),
          deps_str(deps_str),
          tasks(tasks) {
        realpath(name.c_str(), resolved_name);
        int fish = 2;
    }

    bool operator==(const Rule& otherRule) const {
        return this->name == otherRule.name;
    }

    struct HashFunction {
        size_t operator()(const Rule& rule) const {
            return std::hash<std::string>()(rule.name);
        }
    };
    char resolved_name[PATH_MAX];
    bool hasBeenRun = false;
    bool hasBeenAddedToTasks = false;
    std::string name;
    std::unordered_set<std::string> deps_str;
    size_t num_triggs_left;
    std::unordered_set<Rule*> triggers;
    std::unordered_set<Rule*> dep_rules;
    std::unordered_set<std::string> dep_files;
    std::vector<std::string> tasks;
    REPMAKE_TIME self_modified_timestamp;
    REPMAKE_TIME deps_modified_timestamp;
    std::unordered_set<Rule*> tasks_blocked_on_me;
    pid_t blocked_work;
    bool isFinished = false;
    static void runTasksInOrder(const std::unordered_set<std::string>& targets_to_run, std::unordered_map<std::string, Rule>& rules);
};
