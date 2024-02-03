#include "trace_tasks.hpp"
#include <string.h>
#include <sstream>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>
#include <queue>
#include "utils.hpp"

static void runBash( int argc, char *argv[] ) {
    printf( "Bash args: " );
    for ( int i = 0; i < argc; i++ ) {
        printf( "%s ", argv[ i ] );
    }
    printf( "\n" );

    /* If open syscall, trace */
    struct sock_filter filter[] = {
        BPF_STMT( BPF_LD + BPF_W + BPF_ABS, offsetof( struct seccomp_data, nr ) ),
        BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, SYS_openat, 0, 1 ),
        BPF_STMT( BPF_RET + BPF_K, SECCOMP_RET_TRACE ),
        BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, SYS_access, 0, 1 ),
        BPF_STMT( BPF_RET + BPF_K, SECCOMP_RET_TRACE ),
        BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, SYS_execve, 0, 1 ),
        BPF_STMT( BPF_RET + BPF_K, SECCOMP_RET_TRACE ),
        BPF_STMT( BPF_RET + BPF_K, SECCOMP_RET_ALLOW ),
    };
    struct sock_fprog prog = {
        .len = ( unsigned short )( sizeof( filter ) / sizeof( filter[ 0 ] ) ),
        .filter = filter,
    };
    ptrace( PTRACE_TRACEME, 0, 0, 0 );
    /* To avoid the need for CAP_SYS_ADMIN */
    if ( prctl( PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0 ) < 0 ) {
        perror( "prctl(PR_SET_NO_NEW_PRIVS)" );
        return;
    }
    if ( prctl( PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog ) < 0 ) {
        perror( "when setting seccomp filter" );
        return;
    }
    kill( getpid( ), SIGSTOP );
    execvp( argv[ 0 ], argv );
}

// https://www.alfonsobeato.net/tag/seccomp/
// https://github.com/alfonsosanchezbeato/ptrace-redirect/blob/master/redir_filter.c
//  https://github.com/skeeto/ptrace-examples/blob/master/minimal_strace.c
// register order https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-and-user-space-f
static void read_file( pid_t pid, long reg, char *file ) {
    char *child_addr;
    unsigned long i;

    child_addr = ( char * )reg;

    do {
        long val;
        char *p;

        val = ptrace( PTRACE_PEEKTEXT, pid, child_addr, NULL );
        if ( val == -1 ) {
            fprintf( stderr, "PTRACE_PEEKTEXT error: %s", strerror( errno ) );
            exit( 1 );
        }
        child_addr += sizeof( long );

        p = ( char * )&val;
        for ( i = 0; i < sizeof( long ); ++i, ++file ) {
            *file = *p++;
            if ( *file == '\0' )
                break;
        }
    } while ( i == sizeof( long ) );
}

static int traceBash( pid_t child, pid_t current_pid ) {
    int status;
    while ( 1 ) {
        ptrace( PTRACE_CONT, current_pid, 0, 0 );

        current_pid = waitpid( 0, &status, 0 );

        if ( WIFEXITED( status ) ) {
            int child_status = WEXITSTATUS( status );
            if ( current_pid == child ) {
                printf( "Child quit!\n" );

                return child_status;
            } else {
                // printf("[Proc exit with status %d]\n", child_status);
                continue;
            }
        }

        int isSECTrap = status >> 8 == ( SIGTRAP | ( PTRACE_EVENT_SECCOMP << 8 ) );
        if ( !isSECTrap ) {
            continue;
        }
        struct user_regs_struct regs;
        if ( ptrace( PTRACE_GETREGS, current_pid, 0, &regs ) == -1 ) {
            if ( errno == ESRCH ) {
                printf( "Child is exiting:%d: %s\n", errno, strerror( errno ) );
            } else {
                printf( "Get Regs Error %d: %s\n", errno, strerror( errno ) );
            }
        }
        long syscall = regs.orig_rax;
        char orig_file[ PATH_MAX ];
        if ( syscall == SYS_access ) {
            read_file( current_pid, regs.rdi, orig_file );
        } else if ( syscall == SYS_execve ) {
            read_file( current_pid, regs.rdi, orig_file );
        } else if ( syscall == SYS_openat ) {
            long dirfd = regs.rdi;
            long flags = regs.rdx;
            bool isRelativeFile = ( int )dirfd == AT_FDCWD;
            if ( !isRelativeFile ) {
                // Not a relitive path, it's something strange give up.
                continue;
            }
            // char flags_str[1024];
            // flagsToString(flags, flags_str, sizeof(flags_str));
            if ( !( flags == O_RDONLY ) || ( flags & O_RDWR ) ) {
                // Not reading the file, don't care.
                continue;
            }
            read_file( current_pid, regs.rsi, orig_file );
        } else {
            // Some other syscall, we don't care.
            continue;
        }

        char resolved_path[ PATH_MAX ];
        realpath( orig_file, resolved_path );
        const char *prefix_strs[] = { "/tmp/", "/usr/", "/etc/", "/lib/", "/dev/", NULL };
        // const char* prefix_strs[] = {NULL};
        if ( str_startsWith( resolved_path, prefix_strs ) ) {
            // Starts with a path we don't care about.
            continue;
        }
        const char *equal_strs[] = { "/tmp", NULL };
        // const char* equal_strs[] = {NULL};
        if ( str_equalsAny( orig_file, equal_strs ) ) {
            // Starts with a path we don't care about.
            continue;
        }

        int fd = openat( AT_FDCWD, resolved_path, O_RDONLY );
        bool file_avail = fd >= 0;
        close( fd );
        if (!file_avail){
            //File doesn't exist, we don't care.
            continue;
        }

        // printf( "REP: orig_file: \"%s\"  resolved: \"%s\"\n", orig_file, resolved_path );
        printf( "REP: \"%s\"\n", resolved_path );
    }
    printf( "Exiting loop\n" );
}

int main( int argc, char *argv[] ) {
    // printf( "Args: " );
    // for ( int i = 0; i < argc; i++ ) {
    //     printf( "%s ", argv[ i ] );
    // }
    // printf( "\n" );

    printf( "Traceing task:%s\n", argv[ 1 ] );

    char *cmd = strdup( "/usr/bin/bash" );

    pid_t pid = fork( );
    if ( pid == -1 ) {
        std::cout << "Fork error" << std::endl;
    }
    if ( pid == 0 ) {
        argv[ 1 ] = cmd;
        runBash( argc - 1, &argv[ 1 ] );
        exit( 0 );
    }
    int status;
    waitpid( pid, &status, 0 );
    ptrace( PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK );
    int ret = traceBash( pid, pid );
    free( cmd );
    printf( "Exiting with:%d (%s)\n", ret, strerror( ret ) );
    return ret;
}
