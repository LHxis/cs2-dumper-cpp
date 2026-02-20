#include "process.h"
#include "util.h"
#include <algorithm>
#include <stdexcept>
#include <locale>
#include <codecvt>
#include <psapi.h>

static std::string wide_to_narrow( const wchar_t* wstr )
{
    if ( !wstr || !wstr[ 0 ] ) return { };
    int len = WideCharToMultiByte( CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr );
    if ( len <= 0 ) return { };
    std::string result( len - 1, '\0' );
    WideCharToMultiByte( CP_UTF8, 0, wstr, -1, &result[ 0 ], len, nullptr, nullptr );
    return result;
}

Process::Process( const std::string& process_name )
{
    m_pid = find_process_id( process_name );

    if ( m_pid == 0 )
    {
        throw std::runtime_error( "failed to find process: " + process_name );
    }

    m_handle = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, m_pid );

    if ( !m_handle )
    {
        throw std::runtime_error( "failed to open process: " + process_name );
    }

    enumerate_modules( );

    LOG_INFO( "attached to process \"%s\" (pid: %u, modules: %zu)", process_name.c_str( ), m_pid, m_modules.size( ) );
}

Process::~Process( )
{
    if ( m_handle )
    {
        CloseHandle( m_handle );
    }
}

DWORD Process::find_process_id( const std::string& name )
{
    HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if ( snapshot == INVALID_HANDLE_VALUE )
        return 0;

    PROCESSENTRY32W entry{ };
    entry.dwSize = sizeof( entry );

    if ( Process32FirstW( snapshot, &entry ) )
    {
        do
        {
            std::string exe_name = wide_to_narrow( entry.szExeFile );
            if ( _stricmp( exe_name.c_str( ), name.c_str( ) ) == 0 )
            {
                CloseHandle( snapshot );
                return entry.th32ProcessID;
            }
        } while ( Process32NextW( snapshot, &entry ) );
    }

    CloseHandle( snapshot );
    return 0;
}

void Process::enumerate_modules( )
{
    HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid );
    if ( snapshot == INVALID_HANDLE_VALUE )
        return;

    MODULEENTRY32W entry{ };
    entry.dwSize = sizeof( entry );

    if ( Module32FirstW( snapshot, &entry ) )
    {
        do
        {
            ModuleInfo info;
            info.name = wide_to_narrow( entry.szModule );
            info.base = reinterpret_cast< uintptr_t >( entry.modBaseAddr );
            info.size = entry.modBaseSize;
            m_modules.push_back( std::move( info ) );
        } while ( Module32NextW( snapshot, &entry ) );
    }

    CloseHandle( snapshot );
}

ModuleInfo Process::module_by_name( const std::string& name ) const
{
    for ( const auto& mod : m_modules )
    {
        if ( _stricmp( mod.name.c_str( ), name.c_str( ) ) == 0 )
            return mod;
    }
    throw std::runtime_error( "module not found: " + name );
}

bool Process::read_raw( uintptr_t address, void* buffer, size_t size ) const
{
    SIZE_T bytes_read = 0;
    return ReadProcessMemory( m_handle, reinterpret_cast< LPCVOID >( address ), buffer, size, &bytes_read ) && bytes_read == size;
}

std::vector<uint8_t> Process::read_raw( uintptr_t address, size_t size ) const
{
    std::vector<uint8_t> buffer( size );
    SIZE_T bytes_read = 0;
    if ( !ReadProcessMemory( m_handle, reinterpret_cast< LPCVOID >( address ), buffer.data( ), size, &bytes_read ) )
    {
        buffer.clear( );
    }
    else
    {
        buffer.resize( bytes_read );
    }
    return buffer;
}

std::string Process::read_string( uintptr_t address, size_t max_len ) const
{
    std::vector<char> buf( max_len + 1, 0 );
    SIZE_T bytes_read = 0;
    ReadProcessMemory( m_handle, reinterpret_cast< LPCVOID >( address ), buf.data( ), max_len, &bytes_read );
    buf[ max_len ] = 0;

    size_t len = strnlen( buf.data( ), max_len );
    return std::string( buf.data( ), len );
}

uint64_t Process::read_addr64( uintptr_t address ) const
{
    uint64_t result = 0;
    read( address, result );
    return result;
}
