#pragma once

#include <stddef.h>

void flagsToString( long flags, char *result, size_t result_size );
int str_startsWith( const std::string &str, const std::vector<std::string> &prefixes );
int str_equalsAny( const std::string &str, const std::vector<std::string> &prefixes );
