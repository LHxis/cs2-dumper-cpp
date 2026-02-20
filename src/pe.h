#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <windows.h>

namespace pe
{

    inline uint32_t find_export_rva( const uint8_t* pe_data, size_t pe_size, const char* export_name )
    {
        if ( pe_size < sizeof( IMAGE_DOS_HEADER ) )
            return 0;

        auto dos_header = reinterpret_cast< const IMAGE_DOS_HEADER* >( pe_data );
        if ( dos_header->e_magic != IMAGE_DOS_SIGNATURE )
            return 0;

        if ( static_cast< size_t >( dos_header->e_lfanew ) + sizeof( IMAGE_NT_HEADERS64 ) > pe_size )
            return 0;

        auto nt_headers = reinterpret_cast< const IMAGE_NT_HEADERS64* >( pe_data + dos_header->e_lfanew );
        if ( nt_headers->Signature != IMAGE_NT_SIGNATURE )
            return 0;

        if ( nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
            return 0;

        auto& export_dir_entry = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
        if ( export_dir_entry.VirtualAddress == 0 || export_dir_entry.Size == 0 )
            return 0;

        uint32_t export_rva = export_dir_entry.VirtualAddress;

        if ( export_rva + sizeof( IMAGE_EXPORT_DIRECTORY ) > pe_size )
            return 0;

        auto export_dir = reinterpret_cast< const IMAGE_EXPORT_DIRECTORY* >( pe_data + export_rva );

        if ( export_dir->AddressOfNames + export_dir->NumberOfNames * 4 > pe_size )
            return 0;

        auto names = reinterpret_cast< const uint32_t* >( pe_data + export_dir->AddressOfNames );
        auto ordinals = reinterpret_cast< const uint16_t* >( pe_data + export_dir->AddressOfNameOrdinals );
        auto functions = reinterpret_cast< const uint32_t* >( pe_data + export_dir->AddressOfFunctions );

        for ( uint32_t i = 0; i < export_dir->NumberOfNames; ++i )
        {
            if ( names[ i ] >= pe_size )
                continue;

            const char* name = reinterpret_cast< const char* >( pe_data + names[ i ] );
            if ( std::strcmp( name, export_name ) == 0 )
            {
                uint16_t ordinal = ordinals[ i ];
                if ( ordinal < export_dir->NumberOfFunctions )
                {
                    return functions[ ordinal ];
                }
            }
        }

        return 0;
    }

    inline uint64_t get_image_base( const uint8_t* pe_data, size_t pe_size )
    {
        if ( pe_size < sizeof( IMAGE_DOS_HEADER ) )
            return 0;

        auto dos_header = reinterpret_cast< const IMAGE_DOS_HEADER* >( pe_data );
        auto nt_headers = reinterpret_cast< const IMAGE_NT_HEADERS64* >( pe_data + dos_header->e_lfanew );

        return nt_headers->OptionalHeader.ImageBase;
    }

} // namespace pe
