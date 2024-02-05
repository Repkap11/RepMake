#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

void flagsToString( long flags, char *result, size_t result_size ) {
    // Initialize the result string as empty
    int length = 0;

    // Check each flag and append its description to the result string
    if ( flags == O_RDONLY ) {
        length += sprintf( result + length, "O_RDONLY " );
    }
    if ( flags & O_WRONLY ) {
        length += sprintf( result + length, "O_WRONLY " );
    }
    if ( flags & O_RDWR ) {
        length += sprintf( result + length, "O_RDWR " );
    }
    if ( flags & O_CREAT ) {
        length += sprintf( result + length, "O_CREAT " );
    }
    if ( flags & O_TRUNC ) {
        length += sprintf( result + length, "O_TRUNC " );
    }
    if ( flags & O_APPEND ) {
        length += sprintf( result + length, "O_APPEND " );
    }
    if ( flags & O_CLOEXEC ) {
        length += sprintf( result + length, "O_CLOEXEC " );
    }

    // Add more flag checks as needed

    // Remove the trailing space, if any
    size_t len = strlen( result );
    if ( len > 0 && result[ len - 1 ] == ' ' ) {
        result[ len - 1 ] = '\0';
    }
}

int str_startsWith( const std::string &str, const std::vector<std::string> &prefixes ) {
    int len = str.length( );
    for ( const std::string &prefix : prefixes ) {
        int pref_len = prefix.length( );
        if ( len < pref_len ) {
            continue;
        }
        if ( str.rfind( prefix, 0 ) == 0 ) {
            return 1; // String starts with one of the prefixes
        }
    }
    return 0; // String does not start with any of the prefixes
}

int str_equalsAny( const std::string &str, const std::vector<std::string> &prefixes ) {
    for ( const std::string &prefix : prefixes ) {
        int pref_len = prefix.length( );
        if ( str == prefix ) {
            return 1; // String starts with one of the prefixes
        }
    }
    return 0; // String does not start with any of the prefixes
}