#pragma once

#include <stddef.h>

void flagsToString(long flags, char* result, size_t result_size);
int str_startsWith(const char* str, const char** prefixes);
int str_equalsAny(const char* str, const char** prefixes);