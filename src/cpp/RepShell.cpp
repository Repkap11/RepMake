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
#include <set>
#include <map>
#include <fstream>
#include "utils.hpp"
#include "logging.hpp"
#include "rules.hpp"

#include "RepShellLexer.h"
#include "RepShellParser.h"
#include "antlr4-runtime.h"

using namespace antlr4;
using namespace antlr4::tree;

static void runBash( int argc, char *argv[] ) {
    // pr_debug_raw( "Bash args: " );
    // for ( int i = 0; i < argc; i++ ) {
    //     pr_debug_raw( "%s ", argv[ i ] );
    // }
    // pr_debug_raw( "\n" );

    /* If open syscall, trace */
    struct sock_filter filter[] = {
        BPF_STMT( BPF_LD + BPF_W + BPF_ABS, offsetof( struct seccomp_data, nr ) ),
        BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, SYS_openat, 0, 1 ),
        BPF_STMT( BPF_RET + BPF_K, SECCOMP_RET_TRACE ),
        BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, SYS_access, 0, 1 ),
        BPF_STMT( BPF_RET + BPF_K, SECCOMP_RET_TRACE ),
        BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, SYS_execve, 0, 1 ),
        BPF_STMT( BPF_RET + BPF_K, SECCOMP_RET_TRACE ),
        // BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, SYS_newfstatat, 0, 1 ),
        // BPF_STMT( BPF_RET + BPF_K, SECCOMP_RET_TRACE ),
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
            pr_debug( "PTRACE_PEEKTEXT error: %s", strerror( errno ) );
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

static int traceBash( pid_t child, pid_t current_pid, Rule &new_rules ) {
    int status;
    while ( 1 ) {
        ptrace( PTRACE_CONT, current_pid, 0, 0 );

        current_pid = waitpid( 0, &status, 0 );
        // pr_debug( "PID:%d", current_pid );

        if ( WIFEXITED( status ) ) {
            int child_status = WEXITSTATUS( status );
            if ( current_pid == child ) {
                // pr_debug( "Child quit!" );
                return child_status;
            } else {
                // pr_debug("[Proc exit with status %d]", child_status);
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
                pr_debug( "Child is exiting:%d: %s", errno, strerror( errno ) );
            } else {
                pr_debug( "Get Regs Error %d: %s", errno, strerror( errno ) );
            }
        }
        long syscall = regs.orig_rax;
        char orig_file[ PATH_MAX ];
        bool isWrite = false;
        bool isRead = false;
        // if ( syscall == SYS_newfstatat ) {
        //     long dirfd = regs.rdi;
        //     bool isRelativeFile = ( int )dirfd == AT_FDCWD;
        //     if ( !isRelativeFile ) {
        //         // Not a relitive path, it's something strange give up.
        //         continue;
        //     }
        //     // pr_debug( "rsi:%s", orig_file );
        //     read_file( current_pid, regs.rsi, orig_file );
        //     isRead = true;
        if ( syscall == SYS_access ) {
            read_file( current_pid, regs.rdi, orig_file );
            isRead = true;
        } else if ( syscall == SYS_execve ) {
            read_file( current_pid, regs.rdi, orig_file );
            isRead = true;
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
            if ( ( flags & O_ACCMODE ) == O_RDONLY ) {
                isRead = true;
            } else if ( ( flags & O_ACCMODE ) == O_WRONLY ) {
                isWrite = true;
            } else if ( ( flags & O_ACCMODE ) == O_RDWR ) {
                isWrite = true;
                isRead = true;
            }
            read_file( current_pid, regs.rsi, orig_file );
        } else {
            // Some other syscall, we don't care.
            continue;
        }

        char resolved_path[ PATH_MAX ];
        realpath( orig_file, resolved_path );
        // const char *prefix_strs[] = { "/tmp/", "/usr/", "/etc/", "/lib/", "/dev/", "/sys/", "/proc/", "/run/", "/snap/", NULL };
        const char *prefix_strs[] = { "/", NULL }; // any nont relative files.
        // const char* prefix_strs[] = {NULL};
        if ( str_startsWith( orig_file, prefix_strs ) ) {
            // Starts with a path we don't care about.
            continue;
        }
        const char *equal_strs[] = { "/tmp", ".", NULL };
        // const char* equal_strs[] = {NULL};
        if ( str_equalsAny( orig_file, equal_strs ) ) {
            // Starts with a path we don't care about.
            continue;
        }

        int fd = openat( AT_FDCWD, resolved_path, O_RDONLY );
        bool file_avail = fd >= 0;
        close( fd );

        // pr_debug( "WroteFile: orig_file: \"%s\"  resolved: \"%s\"", orig_file, resolved_path );
        pr_debug( "Access: r:%d w:%d \"%s\"", isRead, isWrite, orig_file );
        // pr_debug( "" );
        if ( isRead ) {
            if ( strcmp( "libgcc_s.so.1", orig_file ) == 0 ) {
                // Bad dep
            } else {
                new_rules.deps.insert( orig_file );
            }
        }
        if ( new_rules.name.empty( ) && isWrite ) {
            new_rules.name = orig_file;
        }
    }
    // pr_debug( "Exiting loop" );
}

std::pair<char *, std::streampos> readEntireFile( const char *inputFile ) {
    std::ifstream stream;
    stream.open( inputFile );
    stream.seekg( 0, std::ios::end );
    std::streampos fileSize = stream.tellg( );
    fileSize += 1;
    stream.seekg( 0, std::ios::beg );

    char *buffer = new char[ fileSize ];
    // Add a new line since i couldn't figure out how to write my rule without needing start of line token.
    // Use \n instead of \n so it doesn't offset the line count (kinda hacky, but works).
    buffer[ 0 ] = '\r';
    stream.read( &buffer[ 1 ], fileSize );
    return { buffer, fileSize };
}

bool parseExistingRules( std::set<Rule> &all_rules ) {
    const char *inputFile = ".RepDep";
    auto inputBuffer = readEntireFile( inputFile );
    ANTLRInputStream input( inputBuffer.first, inputBuffer.second );
    delete[] inputBuffer.first;
    input.name = inputFile;
    RepShellLexer lexer( &input );
    CommonTokenStream tokens( &lexer );
    RepShellParser parser( &tokens );
    if ( parser.getNumberOfSyntaxErrors( ) != 0 ) {
        return 1;
    }
    auto context = parser.repshell( );
    if ( parser.repshell( ) == NULL ) {
        return 1;
    }

    std::vector<RepShellParser::Rep_shell_ruleContext *> parseRules = context->rep_shell_rule( );
    for ( RepShellParser::Rep_shell_ruleContext *const parseRule : parseRules ) {
        std::string rule_name = parseRule->rule_name( )->IDENTIFIER( )->getText( );

        std::set<Rule>::iterator iter = all_rules.find( rule_name );

        std::set<std::string> *deps;
        if ( iter != all_rules.end( ) ) {
            // Already exists in rules, add the deps we found, if any.
            const Rule &previous_rule = *iter;
            // Cast away const since the deps of a rules don't impact the hash of the item in the set.
            Rule &editable_rules = const_cast<Rule &>( previous_rule );
            deps = &editable_rules.deps;
        } else {
            // Rule is new, add it to the set;
            auto it = all_rules.emplace( rule_name );
            const Rule &emplaced_rule = *it.first;
            // Cast away const since the deps of a rules don't impact the hash of the item in the set.
            Rule &editable_rules = const_cast<Rule &>( emplaced_rule );
            deps = &editable_rules.deps;
        }

        auto parseDepList = parseRule->dependency_list( );
        if ( parseDepList != NULL ) {
            std::vector<RepShellParser::Rule_nameContext *> parseDeps = parseDepList->rule_name( );
            for ( RepShellParser::Rule_nameContext *parseDep : parseDeps ) {
                deps->insert( parseDep->IDENTIFIER( )->getText( ) );
            }
        }
    }
    return 0;
}

int main( int argc, char *argv[] ) {
    // pr_debug_raw( "Args: " );
    // for ( int i = 0; i < argc; i++ ) {
    //     pr_debug_raw( "%s ", argv[ i ] );
    // }
    // pr_debug_raw( "\n" );

    // if ( false ) {
    //     char proc_str[ 64 ];
    //     char cmdLine[ PATH_MAX ];
    //     FILE *proc_file;
    //     pid_t parent_pid = getppid( );
    //     pr_debug( "Parent pid:%d", parent_pid );

    //     snprintf( proc_str, PATH_MAX, "/proc/%i/cmdline", parent_pid );
    //     proc_file = fopen( proc_str, "r" );
    //     fgets( cmdLine, PATH_MAX, proc_file );
    //     fclose( proc_file );
    //     pr_debug( "Parent cmdline:%s", cmdLine );

    //     // This can be used to re-exec make.
    //     sprintf( proc_str, "/proc/%i/exe", parent_pid );
    // }

    bool pendingDashTask = false;
    bool foundArgEndMarker = false;
    const char *task = NULL;
    int i;
    for ( i = 1; i < argc; i++ ) {
        const char *arg = argv[ i ];
        // pr_debug( "Arg:%d %s", i, arg );
        if ( strncmp( "--", arg, 3 ) == 0 ) {
            foundArgEndMarker = true;
            break;
        } else if ( pendingDashTask ) {
            task = arg;
        } else if ( strncmp( "--task", arg, 7 ) == 0 ) {
            pendingDashTask = true;
        } else {
            pr_debug( "Unexpected arg:%s", arg );
            return 1;
        }
    }
    if ( !foundArgEndMarker ) {
        pr_debug( "uage: RepShell [--task task_name] -- [shell args...]" );
        return 1;
    }
    if ( i == argc - 1 ) {
        pr_debug( "No args to shell given." );
        return 1;
    }
    int argEndMarker = i;

    if ( task == NULL ) {
        pr_debug( "Traceing Unknown" );
        task = "";
    } else {
        pr_debug( "Traceing task: %s", task );
    }

    pid_t pid = fork( );
    if ( pid == -1 ) {
        std::cout << "Fork error" << std::endl;
    }
    if ( pid == 0 ) {
        char *cmd = strdup( "/usr/bin/bash" );

        argv[ argEndMarker ] = cmd;
        runBash( argc - argEndMarker, &argv[ argEndMarker ] );
        free( cmd );
        exit( 0 );
    }
    int status;
    waitpid( pid, &status, 0 );
    ptrace( PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK );

    std::set<Rule> all_rules; // TODO parse out previous rules.
    parseExistingRules( all_rules );

    Rule new_rule( task );

    int ret = traceBash( pid, pid, new_rule );

    new_rule.deps.erase( new_rule.name ); // Don't set a rule depend on itself.

    std::set<Rule>::iterator iter = all_rules.find( new_rule );
    if ( iter != all_rules.end( ) ) {
        // Already exists in rules, add the deps we found, if any.
        const Rule &previous_rule = *iter;
        // Cast away const since the deps of a rules don't impact the hash of the item in the set.
        Rule &editable_rules = const_cast<Rule &>( previous_rule );
        editable_rules.deps.insert( new_rule.deps.begin( ), new_rule.deps.end( ) );
    } else {
        // Rule is new, add it to the set;
        all_rules.insert( new_rule );
    }

    std::ofstream rep_dep_out( ".RepDep" );
    for ( const Rule &rule : all_rules ) {
        if ( rule.deps.size( ) == 0 ) {
            continue;
        }
        if ( rule.name.empty( ) ) {

            pr_debug_raw( "Empty: " );
            for ( const auto &dep : rule.deps ) {
                pr_debug_raw( "%s ", dep.c_str( ) );
            }
            pr_debug( "" );
        } else {
            rep_dep_out << rule.name << ":";
            for ( const auto &dep : rule.deps ) {
                rep_dep_out << " " << dep;
            }
            rep_dep_out << std::endl << std::endl;
        }
    }
    rep_dep_out.close( );

    // pr_debug( "Exiting with:%d (%s)", ret, strerror( ret ) );
    return ret;
}
