#pragma once
#include <queue>

#include "rules.hpp"

int trace_tasks(std::queue<Rule*>& tasksToRun, std::unordered_map<std::string, Rule>& rules, Rule* rule, char** args, int* didFinish);