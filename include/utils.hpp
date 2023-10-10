#pragma once

#include <stddef.h>

void flagsToString(long flags, char* result, size_t result_size);
int startsWith(const char* str, const char** prefixes);