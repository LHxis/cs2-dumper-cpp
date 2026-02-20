#pragma once

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>

enum class LogLevel
{
    Error, Warn, Info, Debug, Trace
};

inline LogLevel g_log_level = LogLevel::Error;
inline std::vector<std::string> g_log_entries;

inline void log_msg( LogLevel level, const char* fmt, ... )
{
    if ( level > g_log_level )
        return;

    const char* prefix = "";
    switch ( level )
    {
        case LogLevel::Error: prefix = "[ERROR] "; break;
        case LogLevel::Warn:  prefix = "[WARN]  "; break;
        case LogLevel::Info:  prefix = "[INFO]  "; break;
        case LogLevel::Debug: prefix = "[DEBUG] "; break;
        case LogLevel::Trace: prefix = "[TRACE] "; break;
    }

    va_list args;
    va_start( args, fmt );

    char buf[ 4096 ];
    vsnprintf( buf, sizeof( buf ), fmt, args );

    va_end( args );

    g_log_entries.push_back( std::string( prefix ) + buf );
}

inline void flush_log( const std::string& path = "cs2-dumper.log" )
{
    if ( g_log_entries.empty( ) )
        return;

    FILE* f = fopen( path.c_str( ), "w" );
    if ( !f ) return;

    for ( const auto& line : g_log_entries )
    {
        fprintf( f, "%s\n", line.c_str( ) );
    }

    fclose( f );
}

#define LOG_ERROR(fmt, ...) log_msg(LogLevel::Error, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  log_msg(LogLevel::Warn,  fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  log_msg(LogLevel::Info,  fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) log_msg(LogLevel::Debug, fmt, ##__VA_ARGS__)
#define LOG_TRACE(fmt, ...) log_msg(LogLevel::Trace, fmt, ##__VA_ARGS__)

inline std::string slugify( const std::string& input )
{
    std::string result;
    result.reserve( input.size( ) );
    for ( char c : input )
    {
        result += std::isalnum( static_cast< unsigned char >( c ) ) ? c : '_';
    }
    return result;
}

inline std::string to_pascal_case( const std::string& input )
{
    std::string result;
    result.reserve( input.size( ) );
    bool capitalize_next = true;
    for ( char c : input )
    {
        if ( c == '_' || c == ' ' || c == '-' || c == '.' )
        {
            capitalize_next = true;
        }
        else
        {
            if ( capitalize_next )
            {
                result += static_cast< char >( std::toupper( static_cast< unsigned char >( c ) ) );
                capitalize_next = false;
            }
            else
            {
                result += c;
            }
        }
    }
    return result;
}

inline std::string to_snake_case( const std::string& input )
{
    std::string result;
    result.reserve( input.size( ) + 4 );
    bool prev_upper = false;
    bool prev_sep = true;
    for ( size_t i = 0; i < input.size( ); ++i )
    {
        char c = input[ i ];
        if ( c == '_' || c == ' ' || c == '-' || c == '.' )
        {
            if ( !result.empty( ) && result.back( ) != '_' )
                result += '_';
            prev_sep = true;
            prev_upper = false;
        }
        else if ( std::isupper( static_cast< unsigned char >( c ) ) )
        {
            if ( !prev_upper && !prev_sep && !result.empty( ) )
                result += '_';
            result += static_cast< char >( std::tolower( static_cast< unsigned char >( c ) ) );
            prev_upper = true;
            prev_sep = false;
        }
        else
        {
            result += c;
            prev_upper = false;
            prev_sep = false;
        }
    }
    return result;
}

inline std::string to_hex( uint64_t value )
{
    char buf[ 32 ];
    snprintf( buf, sizeof( buf ), "0x%llX", static_cast< unsigned long long >( value ) );
    return buf;
}

inline std::string to_hex( int64_t value )
{
    if ( value >= 0 )
    {
        char buf[ 32 ];
        snprintf( buf, sizeof( buf ), "0x%llX", static_cast< unsigned long long >( value ) );
        return buf;
    }
    else
    {
        char buf[ 32 ];
        snprintf( buf, sizeof( buf ), "%lld", static_cast< long long >( value ) );
        return buf;
    }
}

inline std::string to_hex( int32_t value )
{
    return to_hex( static_cast< int64_t >( value ) );
}

inline std::string to_hex( uint32_t value )
{
    return to_hex( static_cast< uint64_t >( value ) );
}

inline std::string get_timestamp_rfc3339( )
{
    auto now = std::chrono::system_clock::now( );
    auto time_t_now = std::chrono::system_clock::to_time_t( now );
    struct tm tm_buf;
    localtime_s( &tm_buf, &time_t_now );

    char buf[ 64 ];
    strftime( buf, sizeof( buf ), "%Y-%m-%dT%H:%M:%S%z", &tm_buf );
    return buf;
}

inline std::string get_timestamp_display( )
{
    auto now = std::chrono::system_clock::now( );
    auto time_t_now = std::chrono::system_clock::to_time_t( now );
    struct tm tm_buf;
    localtime_s( &tm_buf, &time_t_now );

    char buf[ 64 ];
    strftime( buf, sizeof( buf ), "%Y-%m-%d %H:%M:%S", &tm_buf );
    return buf;
}

class JsonBuilder
{
public:
    static std::string object_begin( )
    {
        return "{";
    }
    static std::string object_end( )
    {
        return "}";
    }
    static std::string array_begin( )
    {
        return "[";
    }
    static std::string array_end( )
    {
        return "]";
    }

    static std::string escape_string( const std::string& s )
    {
        std::string result = "\"";
        for ( char c : s )
        {
            switch ( c )
            {
                case '"':  result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default:   result += c; break;
            }
        }
        result += "\"";
        return result;
    }

    static std::string key_value_str( const std::string& key, const std::string& value )
    {
        return escape_string( key ) + ": " + escape_string( value );
    }

    static std::string key_value_num( const std::string& key, int64_t value )
    {
        return escape_string( key ) + ": " + std::to_string( value );
    }

    static std::string key_value_null( const std::string& key )
    {
        return escape_string( key ) + ": null";
    }

    // Pretty-print a JSON string by adding indentation
    static std::string prettify( const std::string& json, int indent_size = 4 )
    {
        std::string result;
        result.reserve( json.size( ) * 2 );
        int level = 0;
        bool in_string = false;
        bool escape_next = false;

        for ( size_t i = 0; i < json.size( ); ++i )
        {
            char c = json[ i ];

            if ( escape_next )
            {
                result += c;
                escape_next = false;
                continue;
            }

            if ( c == '\\' && in_string )
            {
                result += c;
                escape_next = true;
                continue;
            }

            if ( c == '"' )
            {
                in_string = !in_string;
                result += c;
                continue;
            }

            if ( in_string )
            {
                result += c;
                continue;
            }

            switch ( c )
            {
                case '{':
                case '[':
                    result += c;
                    ++level;
                    result += '\n';
                    result += std::string( level * indent_size, ' ' );
                    break;
                case '}':
                case ']':
                    --level;
                    result += '\n';
                    result += std::string( level * indent_size, ' ' );
                    result += c;
                    break;
                case ',':
                    result += c;
                    result += '\n';
                    result += std::string( level * indent_size, ' ' );
                    break;
                case ':':
                    result += ": ";
                    break;
                case ' ':
                case '\n':
                case '\r':
                case '\t':
                    break;
                default:
                    result += c;
                    break;
            }
        }

        return result;
    }
};
