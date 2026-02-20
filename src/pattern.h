#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace pattern
{

    struct Pattern
    {
        std::vector<uint8_t> bytes;
        std::vector<bool> mask;
    };

    inline Pattern parse( const char* pattern_str )
    {
        Pattern pat;
        const char* p = pattern_str;

        while ( *p )
        {
            while ( *p == ' ' ) ++p;
            if ( !*p ) break;

            if ( *p == '?' )
            {
                pat.bytes.push_back( 0 );
                pat.mask.push_back( false );
                while ( *p == '?' ) ++p;
            }
            else
            {
                unsigned int byte_val = 0;
                if ( sscanf_s( p, "%02X", &byte_val ) == 1 )
                {
                    pat.bytes.push_back( static_cast< uint8_t >( byte_val ) );
                    pat.mask.push_back( true );
                    while ( *p && *p != ' ' && *p != '?' ) ++p;
                }
                else
                {
                    ++p;
                }
            }
        }

        return pat;
    }

    inline ptrdiff_t find( const uint8_t* data, size_t data_size, const Pattern& pat )
    {
        if ( pat.bytes.empty( ) || pat.bytes.size( ) > data_size )
            return -1;

        size_t pat_size = pat.bytes.size( );
        size_t end = data_size - pat_size;

        for ( size_t i = 0; i <= end; ++i )
        {
            bool found = true;
            for ( size_t j = 0; j < pat_size; ++j )
            {
                if ( pat.mask[ j ] && data[ i + j ] != pat.bytes[ j ] )
                {
                    found = false;
                    break;
                }
            }
            if ( found )
                return static_cast< ptrdiff_t >( i );
        }

        return -1;
    }

    inline ptrdiff_t find( const uint8_t* data, size_t data_size, const char* pattern_str )
    {
        return find( data, data_size, parse( pattern_str ) );
    }

    inline uint32_t resolve_rip( const uint8_t* data, ptrdiff_t match_offset, int rel32_pos )
    {
        int32_t rel32 = 0;
        std::memcpy( &rel32, data + match_offset + rel32_pos, sizeof( int32_t ) );
        int64_t target = static_cast< int64_t >( match_offset + rel32_pos + 4 ) + rel32;
        return static_cast< uint32_t >( target );
    }

    inline uint32_t read_u32( const uint8_t* data, ptrdiff_t match_offset, int pos )
    {
        uint32_t val = 0;
        std::memcpy( &val, data + match_offset + pos, sizeof( uint32_t ) );
        return val;
    }

    inline uint8_t read_u8( const uint8_t* data, ptrdiff_t match_offset, int pos )
    {
        return data[ match_offset + pos ];
    }

} // namespace pattern

namespace address
{

    inline uintptr_t follow_call( const Process& process, uintptr_t base )
    {
        int32_t rel32 = 0;
        process.read( base + 1, rel32 );
        return static_cast< uintptr_t >(
            static_cast< int64_t >( base + 1 + sizeof( int32_t ) ) + rel32
            );
    }

    inline uintptr_t follow_jmp( const Process& process, uintptr_t base )
    {
        return follow_call( process, base );
    }

    inline uintptr_t resolve_rip( const Process& process, uintptr_t base )
    {
        int32_t rel32 = 0;
        process.read( base + 3, rel32 );
        return static_cast< uintptr_t >( static_cast< int64_t >( base + 3 + sizeof( int32_t ) ) + rel32 );
    }

} // namespace address
