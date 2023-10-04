#include "tasks.hpp"

#include <unistd.h>

#include <iostream>

int Task::run(std::string task) {
    std::cout << task << std::endl;
    return system(task.c_str());
}
