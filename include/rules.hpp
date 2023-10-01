#pragma once

#include <iostream>
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
    std::string name;
    std::unordered_set<std::string> deps_str;
    std::unordered_set<Rule*> deps;
    std::vector<std::string> tasks;
};