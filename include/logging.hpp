#pragma once

// #define pr_debug( fmt, ... ) fprintf( stderr, "%s:%d :%s():" fmt "\n", __FILE__, __LINE__, __func__, ##__VA_ARGS__ )
#define pr_debug( fmt, ... ) fprintf( stderr, fmt "\n", ##__VA_ARGS__ )
#define pr_debug_raw( fmt, ... ) fprintf( stderr, fmt, ##__VA_ARGS__ )