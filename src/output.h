#pragma once

#include "analysis.h"

#include <filesystem>
#include <string>
#include <vector>

class Process;

class Formatter
{
public:
    Formatter( std::string& out, int indent_size ) : m_out( out ), m_indent_size( indent_size ), m_indent_level( 0 )
    {
    }

    void write( const std::string& text );
    void writeln( const std::string& text );
    void writeln( );

    template<typename F>
    void block( const std::string& heading, bool semicolon, F&& body )
    {
        writeln( heading + " {" );
        m_indent_level++;
        body( *this );
        m_indent_level--;
        writeln( semicolon ? "};" : "}" );
    }

private:
    std::string& m_out;
    int m_indent_size;
    int m_indent_level;
    void push_indent( );
};

class Output
{
public:
    Output( const std::vector<std::string>& file_types, int indent_size, const std::filesystem::path& out_dir, const AnalysisResult& result );
    void dump_all( Process& process ) const;
private:
    std::vector<std::string> m_file_types;
    int m_indent_size;
    std::filesystem::path m_out_dir;
    const AnalysisResult& m_result;
    std::string m_timestamp_display;
    std::string m_timestamp_rfc3339;

    void dump_buttons( ) const;
    void dump_interfaces( ) const;
    void dump_offsets( ) const;
    void dump_schemas( ) const;
    void dump_info( Process& process ) const;

    void write_banner( Formatter& fmt ) const;
    void write_to_file( const std::string& file_name, const std::string& ext, const std::string& content ) const;
};

namespace writers
{

    std::string buttons_cs( const ButtonMap& buttons, int indent_size );
    std::string buttons_hpp( const ButtonMap& buttons, int indent_size );
    std::string buttons_json( const ButtonMap& buttons, int indent_size );
    std::string buttons_rs( const ButtonMap& buttons, int indent_size );

    std::string interfaces_cs( const InterfaceMap& ifaces, int indent_size );
    std::string interfaces_hpp( const InterfaceMap& ifaces, int indent_size );
    std::string interfaces_json( const InterfaceMap& ifaces, int indent_size );
    std::string interfaces_rs( const InterfaceMap& ifaces, int indent_size );

    std::string offsets_cs( const OffsetMap& offsets, int indent_size );
    std::string offsets_hpp( const OffsetMap& offsets, int indent_size );
    std::string offsets_json( const OffsetMap& offsets, int indent_size );
    std::string offsets_rs( const OffsetMap& offsets, int indent_size );

    std::string schemas_cs( const SchemaMap& schemas, int indent_size );
    std::string schemas_hpp( const SchemaMap& schemas, int indent_size );
    std::string schemas_json( const SchemaMap& schemas, int indent_size );
    std::string schemas_rs( const SchemaMap& schemas, int indent_size );

} // namespace writers
