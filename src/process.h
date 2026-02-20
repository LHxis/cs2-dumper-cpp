#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <windows.h>
#include <tlhelp32.h>

struct ModuleInfo
{
    std::string name;
    uintptr_t base = 0;
    size_t size = 0;
};

class Process
{
public:
    explicit Process( const std::string& process_name );
    ~Process( );
    Process( const Process& ) = delete;
    Process& operator=( const Process& ) = delete;

    bool is_valid( ) const
    {
        return m_handle != nullptr;
    }

    ModuleInfo module_by_name( const std::string& name ) const;
    const std::vector<ModuleInfo>& module_list( ) const
    {
        return m_modules;
    }

    template<typename T>
    bool read( uintptr_t address, T& out ) const
    {
        SIZE_T bytes_read = 0;
        return ReadProcessMemory( m_handle, reinterpret_cast< LPCVOID >( address ), &out, sizeof( T ), &bytes_read ) && bytes_read == sizeof( T );
    }

    template<typename T>
    T read( uintptr_t address ) const
    {
        T result{ };
        read( address, result );
        return result;
    }

    bool read_raw( uintptr_t address, void* buffer, size_t size ) const;
    std::vector<uint8_t> read_raw( uintptr_t address, size_t size ) const;
    std::string read_string( uintptr_t address, size_t max_len = 256 ) const;
    uint64_t read_addr64( uintptr_t address ) const;

private:
    HANDLE m_handle = nullptr;
    DWORD m_pid = 0;
    std::vector<ModuleInfo> m_modules;
    static DWORD find_process_id( const std::string& name );
    void enumerate_modules( );
};
