#include "analysis.h"
#include "output.h"
#include "process.h"
#include "util.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

struct Args
{
    std::vector<std::string> file_types = { "cs", "hpp", "json", "rs" };
    int indent_size = 4;
    std::filesystem::path output_dir = "output";
    std::string process_name = "cs2.exe";
    int verbose = 2;
    bool no_log_file = false;
};

static void print_help( const char* exe )
{
    printf( "Usage: %s [OPTIONS]\n\n", exe );
    printf( "Options:\n" );
    printf( "  -f, --file-types <TYPES>   Comma-separated file types (default: cs,hpp,json,rs)\n" );
    printf( "  -i, --indent-size <SIZE>   Spaces per indent level (default: 4)\n" );
    printf( "  -o, --output <DIR>         Output directory (default: output)\n" );
    printf( "  -p, --process-name <NAME>  Game process name (default: cs2.exe)\n" );
    printf( "  -v, --verbose              Increase verbosity (can repeat: -vvv)\n" );
    printf( "  -n, --no-log-file          Don't create cs2-dumper.log\n" );
    printf( "  -h, --help                 Show this help\n" );
}

static std::vector<std::string> split_csv( const std::string& s )
{
    std::vector<std::string> result;
    std::string token;
    for ( char c : s )
    {
        if ( c == ',' )
        {
            if ( !token.empty( ) ) result.push_back( token );
            token.clear( );
        }
        else
        {
            token += c;
        }
    }
    if ( !token.empty( ) ) result.push_back( token );
    return result;
}

static Args parse_args( int argc, char* argv[ ] )
{
    Args args;

    for ( int i = 1; i < argc; ++i )
    {
        std::string arg = argv[ i ];

        if ( arg == "-h" || arg == "--help" )
        {
            print_help( argv[ 0 ] );
            exit( 0 );
        }
        else if ( arg == "-v" || arg == "--verbose" )
        {
            args.verbose++;
        }
        else if ( arg == "-n" || arg == "--no-log-file" )
        {
            args.no_log_file = true;
        }
        else if ( ( arg == "-f" || arg == "--file-types" ) && i + 1 < argc )
        {
            args.file_types = split_csv( argv[ ++i ] );
        }
        else if ( ( arg == "-i" || arg == "--indent-size" ) && i + 1 < argc )
        {
            args.indent_size = std::atoi( argv[ ++i ] );
        }
        else if ( ( arg == "-o" || arg == "--output" ) && i + 1 < argc )
        {
            args.output_dir = argv[ ++i ];
        }
        else if ( ( arg == "-p" || arg == "--process-name" ) && i + 1 < argc )
        {
            args.process_name = argv[ ++i ];
        }
        else
        {
            if ( arg.size( ) > 1 && arg[ 0 ] == '-' && arg[ 1 ] != '-' )
            {
                for ( size_t j = 1; j < arg.size( ); ++j )
                {
                    if ( arg[ j ] == 'v' ) args.verbose++;
                }
            }
        }
    }

    return args;
}

int main( int argc, char* argv[ ] )
{
    Args args = parse_args( argc, argv );

    switch ( args.verbose )
    {
        case 0:  g_log_level = LogLevel::Error; break;
        case 1:  g_log_level = LogLevel::Warn;  break;
        case 2:  g_log_level = LogLevel::Info;   break;
        case 3:  g_log_level = LogLevel::Debug;  break;
        default: g_log_level = LogLevel::Trace;  break;
    }

    try
    {
        Process process( args.process_name );

        auto start = std::chrono::steady_clock::now( );

        AnalysisResult result = analyze_all( process );

        Output output( args.file_types, args.indent_size, args.output_dir, result );
        output.dump_all( process );

        auto elapsed = std::chrono::steady_clock::now( ) - start;
        auto ms = std::chrono::duration_cast< std::chrono::milliseconds >( elapsed ).count( );

        LOG_INFO( "analysis completed in %lld.%02lldms", ms / 1000, ms % 1000 );

        printf( "Done! Output written to: %s\n", args.output_dir.string( ).c_str( ) );

    }
    catch ( const std::exception& e )
    {
        fprintf( stderr, "Error: %s\n", e.what( ) );

        if ( !args.no_log_file )
            flush_log( );

        return 1;
    }

    if ( !args.no_log_file )
        flush_log( );

    return 0;
}
