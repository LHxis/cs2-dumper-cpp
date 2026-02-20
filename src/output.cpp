#include "output.h"
#include "process.h"
#include "util.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <set>
#include <sstream>
#include <stdexcept>

namespace fs = std::filesystem;

void Formatter::push_indent( )
{
    if ( m_indent_level > 0 )
    {
        m_out.append( m_indent_level * m_indent_size, ' ' );
    }
}

void Formatter::write( const std::string& text )
{
    for ( size_t i = 0; i < text.size( ); ++i )
    {
        if ( !m_out.empty( ) && m_out.back( ) == '\n' && text[ i ] != '\n' )
        {
            push_indent( );
        }
        m_out += text[ i ];
    }
}

void Formatter::writeln( const std::string& text )
{
    write( text );
    m_out += '\n';
}

void Formatter::writeln( )
{
    m_out += '\n';
}

Output::Output( const std::vector<std::string>& file_types, int indent_size, const fs::path& out_dir, const AnalysisResult& result )
    : m_file_types( file_types )
    , m_indent_size( indent_size )
    , m_out_dir( out_dir )
    , m_result( result )
    , m_timestamp_display( get_timestamp_display( ) )
    , m_timestamp_rfc3339( get_timestamp_rfc3339( ) )
{
    fs::create_directories( m_out_dir );
}

void Output::dump_all( Process& process ) const
{
    dump_buttons( );
    dump_interfaces( );
    dump_offsets( );
    dump_schemas( );
    dump_info( process );
}

void Output::dump_buttons( ) const
{
    for ( const auto& ext : m_file_types )
    {
        std::string content;
        if ( ext != "json" )
        {
            std::string banner;
            Formatter fmt( banner, m_indent_size );
            write_banner( fmt );
            content = banner;
        }

        if ( ext == "cs" ) content += writers::buttons_cs( m_result.buttons, m_indent_size );
        else if ( ext == "hpp" ) content += writers::buttons_hpp( m_result.buttons, m_indent_size );
        else if ( ext == "json" ) content += writers::buttons_json( m_result.buttons, m_indent_size );
        else if ( ext == "rs" ) content += writers::buttons_rs( m_result.buttons, m_indent_size );

        write_to_file( "buttons", ext, content );
    }
}

void Output::dump_interfaces( ) const
{
    for ( const auto& ext : m_file_types )
    {
        std::string content;
        if ( ext != "json" )
        {
            std::string banner;
            Formatter fmt( banner, m_indent_size );
            write_banner( fmt );
            content = banner;
        }

        if ( ext == "cs" )        content += writers::interfaces_cs( m_result.interfaces, m_indent_size );
        else if ( ext == "hpp" )  content += writers::interfaces_hpp( m_result.interfaces, m_indent_size );
        else if ( ext == "json" ) content += writers::interfaces_json( m_result.interfaces, m_indent_size );
        else if ( ext == "rs" )   content += writers::interfaces_rs( m_result.interfaces, m_indent_size );

        write_to_file( "interfaces", ext, content );
    }
}

void Output::dump_offsets( ) const
{
    for ( const auto& ext : m_file_types )
    {
        std::string content;
        if ( ext != "json" )
        {
            std::string banner;
            Formatter fmt( banner, m_indent_size );
            write_banner( fmt );
            content = banner;
        }

        if ( ext == "cs" )        content += writers::offsets_cs( m_result.offsets, m_indent_size );
        else if ( ext == "hpp" )  content += writers::offsets_hpp( m_result.offsets, m_indent_size );
        else if ( ext == "json" ) content += writers::offsets_json( m_result.offsets, m_indent_size );
        else if ( ext == "rs" )   content += writers::offsets_rs( m_result.offsets, m_indent_size );

        write_to_file( "offsets", ext, content );
    }
}

void Output::dump_schemas( ) const
{
    for ( const auto& [module_name, pair] : m_result.schemas )
    {
        SchemaMap single_map;
        single_map[ module_name ] = pair;

        for ( const auto& ext : m_file_types )
        {
            std::string content;
            if ( ext != "json" )
            {
                std::string banner;
                Formatter fmt( banner, m_indent_size );
                write_banner( fmt );
                content = banner;
            }

            if ( ext == "cs" )        content += writers::schemas_cs( single_map, m_indent_size );
            else if ( ext == "hpp" )  content += writers::schemas_hpp( single_map, m_indent_size );
            else if ( ext == "json" ) content += writers::schemas_json( single_map, m_indent_size );
            else if ( ext == "rs" )   content += writers::schemas_rs( single_map, m_indent_size );

            write_to_file( slugify( module_name ), ext, content );
        }
    }
}

void Output::dump_info( Process& process ) const
{
    uint32_t build_number = 0;

    for ( const auto& [module_name, offsets] : m_result.offsets )
    {
        auto it = offsets.find( "dwBuildNumber" );
        if ( it == offsets.end( ) ) continue;

        try
        {
            auto module = process.module_by_name( module_name );
            process.read( static_cast< uintptr_t >( module.base + it->second ), build_number );
            if ( build_number != 0 ) break;
        }
        catch ( ... )
        {
        }
    }

    std::string json = "{\n";
    json += "    \"timestamp\": \"" + m_timestamp_rfc3339 + "\",\n";
    json += "    \"build_number\": " + std::to_string( build_number ) + "\n";
    json += "}";

    write_to_file( "info", "json", json );
}

void Output::write_banner( Formatter& fmt ) const
{
    fmt.writeln( "// Generated using https://github.com/a2x/cs2-dumper" );
    fmt.writeln( "// " + m_timestamp_display );
    fmt.writeln( );
}

void Output::write_to_file( const std::string& file_name, const std::string& ext,
    const std::string& content ) const
{
    auto path = m_out_dir / ( file_name + "." + ext );
    std::ofstream file( path, std::ios::binary );
    if ( file )
    {
        file << content;
    }
}

namespace writers
{

    std::string buttons_cs( const ButtonMap& buttons, int indent_size )
    {
        std::string out;
        Formatter fmt( out, indent_size );

        fmt.block( "namespace CS2Dumper", false, [ & ] ( Formatter& fmt )
        {
            fmt.writeln( "// Module: client.dll" );
            fmt.block( "public static class Buttons", false, [ & ] ( Formatter& fmt )
            {
                for ( const auto& [name, value] : buttons )
                {
                    fmt.writeln( "public const nint " + name + " = " + to_hex( value ) + ";" );
                }
            } );
        } );

        return out;
    }

    std::string buttons_hpp( const ButtonMap& buttons, int indent_size )
    {
        std::string out;
        Formatter fmt( out, indent_size );

        fmt.writeln( "#pragma once" );
        fmt.writeln( );
        fmt.writeln( "#include <cstddef>" );
        fmt.writeln( "#include <cstdint>" );
        fmt.writeln( );

        fmt.block( "namespace cs2_dumper", false, [ & ] ( Formatter& fmt )
        {
            fmt.writeln( "// Module: client.dll" );
            fmt.block( "namespace buttons", false, [ & ] ( Formatter& fmt )
            {
                for ( const auto& [name, value] : buttons )
                {
                    fmt.writeln( "constexpr std::ptrdiff_t " + name + " = " + to_hex( value ) + ";" );
                }
            } );
        } );

        return out;
    }

    std::string buttons_json( const ButtonMap& buttons, int indent_size )
    {
        std::string json = "{\"client.dll\":{";
        bool first = true;
        for ( const auto& [name, value] : buttons )
        {
            if ( !first ) json += ",";
            json += JsonBuilder::escape_string( name ) + ":" + std::to_string( value );
            first = false;
        }
        json += "}}";
        return JsonBuilder::prettify( json, indent_size );
    }

    std::string buttons_rs( const ButtonMap& buttons, int indent_size )
    {
        std::string out;
        Formatter fmt( out, indent_size );

        fmt.writeln( "#![allow(non_upper_case_globals, unused)]" );
        fmt.writeln( );

        fmt.block( "pub mod cs2_dumper", false, [ & ] ( Formatter& fmt )
        {
            fmt.writeln( "// Module: client.dll" );
            fmt.block( "pub mod buttons", false, [ & ] ( Formatter& fmt )
            {
                for ( const auto& [name, value] : buttons )
                {
                    std::string rname = name;
                    if ( rname == "use" ) rname = "r#use";
                    fmt.writeln( "pub const " + rname + ": usize = " + to_hex( value ) + ";" );
                }
            } );
        } );

        return out;
    }


    std::string interfaces_cs( const InterfaceMap& ifaces, int indent_size )
    {
        std::string out;
        Formatter fmt( out, indent_size );

        fmt.block( "namespace CS2Dumper.Interfaces", false, [ & ] ( Formatter& fmt )
        {
            for ( const auto& [module_name, entries] : ifaces )
            {
                fmt.writeln( "// Module: " + module_name );
                fmt.block( "public static class " + to_pascal_case( slugify( module_name ) ), false,
                    [ & ] ( Formatter& fmt )
                {
                    for ( const auto& [name, value] : entries )
                    {
                        if ( value > static_cast< uint64_t >( INT32_MAX ) )
                        {
                            fmt.writeln( "public static readonly nint " + name +
                                " = unchecked((nint)" + to_hex( value ) + ");" );
                        }
                        else
                        {
                            fmt.writeln( "public const nint " + name + " = " + to_hex( value ) + ";" );
                        }
                    }
                } );
            }
        } );

        return out;
    }

    std::string interfaces_hpp( const InterfaceMap& ifaces, int indent_size )
    {
        std::string out;
        Formatter fmt( out, indent_size );

        fmt.writeln( "#pragma once" );
        fmt.writeln( );
        fmt.writeln( "#include <cstddef>" );
        fmt.writeln( "#include <cstdint>" );
        fmt.writeln( );

        fmt.block( "namespace cs2_dumper", false, [ & ] ( Formatter& fmt )
        {
            fmt.block( "namespace interfaces", false, [ & ] ( Formatter& fmt )
            {
                for ( const auto& [module_name, entries] : ifaces )
                {
                    fmt.writeln( "// Module: " + module_name );
                    fmt.block( "namespace " + to_snake_case( slugify( module_name ) ), false,
                        [ & ] ( Formatter& fmt )
                    {
                        for ( const auto& [name, value] : entries )
                        {
                            fmt.writeln( "constexpr std::ptrdiff_t " + name + " = " + to_hex( value ) + ";" );
                        }
                    } );
                }
            } );
        } );

        return out;
    }

    std::string interfaces_json( const InterfaceMap& ifaces, int indent_size )
    {
        std::string json = "{";
        bool first_mod = true;
        for ( const auto& [module_name, entries] : ifaces )
        {
            if ( !first_mod ) json += ",";
            json += JsonBuilder::escape_string( module_name ) + ":{";
            bool first = true;
            for ( const auto& [name, value] : entries )
            {
                if ( !first ) json += ",";
                json += JsonBuilder::escape_string( name ) + ":" + std::to_string( value );
                first = false;
            }
            json += "}";
            first_mod = false;
        }
        json += "}";
        return JsonBuilder::prettify( json, indent_size );
    }

    std::string interfaces_rs( const InterfaceMap& ifaces, int indent_size )
    {
        std::string out;
        Formatter fmt( out, indent_size );

        fmt.writeln( "#![allow(non_upper_case_globals, unused)]" );
        fmt.writeln( );

        fmt.block( "pub mod cs2_dumper", false, [ & ] ( Formatter& fmt )
        {
            fmt.block( "pub mod interfaces", false, [ & ] ( Formatter& fmt )
            {
                for ( const auto& [module_name, entries] : ifaces )
                {
                    fmt.writeln( "// Module: " + module_name );
                    fmt.block( "pub mod " + to_snake_case( slugify( module_name ) ), false,
                        [ & ] ( Formatter& fmt )
                    {
                        for ( const auto& [name, value] : entries )
                        {
                            fmt.writeln( "pub const " + name + ": usize = " + to_hex( value ) + ";" );
                        }
                    } );
                }
            } );
        } );

        return out;
    }


    std::string offsets_cs( const OffsetMap& offsets, int indent_size )
    {
        std::string out;
        Formatter fmt( out, indent_size );

        fmt.block( "namespace CS2Dumper.Offsets", false, [ & ] ( Formatter& fmt )
        {
            for ( const auto& [module_name, entries] : offsets )
            {
                fmt.writeln( "// Module: " + module_name );
                fmt.block( "public static class " + to_pascal_case( slugify( module_name ) ), false,
                    [ & ] ( Formatter& fmt )
                {
                    for ( const auto& [name, value] : entries )
                    {
                        fmt.writeln( "public const nint " + name + " = " + to_hex( value ) + ";" );
                    }
                } );
            }
        } );

        return out;
    }

    std::string offsets_hpp( const OffsetMap& offsets, int indent_size )
    {
        std::string out;
        Formatter fmt( out, indent_size );

        fmt.writeln( "#pragma once" );
        fmt.writeln( );
        fmt.writeln( "#include <cstddef>" );
        fmt.writeln( "#include <cstdint>" );
        fmt.writeln( );

        fmt.block( "namespace cs2_dumper", false, [ & ] ( Formatter& fmt )
        {
            fmt.block( "namespace offsets", false, [ & ] ( Formatter& fmt )
            {
                for ( const auto& [module_name, entries] : offsets )
                {
                    fmt.writeln( "// Module: " + module_name );
                    fmt.block( "namespace " + to_snake_case( slugify( module_name ) ), false,
                        [ & ] ( Formatter& fmt )
                    {
                        for ( const auto& [name, value] : entries )
                        {
                            fmt.writeln( "constexpr std::ptrdiff_t " + name + " = " + to_hex( value ) + ";" );
                        }
                    } );
                }
            } );
        } );

        return out;
    }

    std::string offsets_json( const OffsetMap& offsets, int indent_size )
    {
        std::string json = "{";
        bool first_mod = true;
        for ( const auto& [module_name, entries] : offsets )
        {
            if ( !first_mod ) json += ",";
            json += JsonBuilder::escape_string( module_name ) + ":{";
            bool first = true;
            for ( const auto& [name, value] : entries )
            {
                if ( !first ) json += ",";
                json += JsonBuilder::escape_string( name ) + ":" + std::to_string( value );
                first = false;
            }
            json += "}";
            first_mod = false;
        }
        json += "}";
        return JsonBuilder::prettify( json, indent_size );
    }

    std::string offsets_rs( const OffsetMap& offsets, int indent_size )
    {
        std::string out;
        Formatter fmt( out, indent_size );

        fmt.writeln( "#![allow(non_upper_case_globals, unused)]" );
        fmt.writeln( );

        fmt.block( "pub mod cs2_dumper", false, [ & ] ( Formatter& fmt )
        {
            fmt.block( "pub mod offsets", false, [ & ] ( Formatter& fmt )
            {
                for ( const auto& [module_name, entries] : offsets )
                {
                    fmt.writeln( "// Module: " + module_name );
                    fmt.block( "pub mod " + to_snake_case( slugify( module_name ) ), false,
                        [ & ] ( Formatter& fmt )
                    {
                        for ( const auto& [name, value] : entries )
                        {
                            fmt.writeln( "pub const " + name + ": usize = " + to_hex( value ) + ";" );
                        }
                    } );
                }
            } );
        } );

        return out;
    }


    static void write_metadata( Formatter& fmt, const std::vector<ClassMetadata>& metadata )
    {
        if ( metadata.empty( ) ) return;

        fmt.writeln( "//" );
        fmt.writeln( "// Metadata:" );

        for ( const auto& m : metadata )
        {
            switch ( m.type )
            {
                case ClassMetadata::NetworkChangeCallback:
                    fmt.writeln( "// NetworkChangeCallback: " + m.name );
                    break;
                case ClassMetadata::NetworkVarNames:
                    fmt.writeln( "// NetworkVarNames: " + m.name + " (" + m.type_name + ")" );
                    break;
                case ClassMetadata::Unknown:
                    fmt.writeln( "// " + m.name );
                    break;
            }
        }
    }


    std::string schemas_cs( const SchemaMap& schemas, int indent_size )
    {
        std::string out;
        Formatter fmt( out, indent_size );

        fmt.block( "namespace CS2Dumper.Schemas", false, [ & ] ( Formatter& fmt )
        {
            for ( const auto& [module_name, pair] : schemas )
            {
                const auto& [classes, enums] = pair;

                fmt.writeln( "// Module: " + module_name );
                fmt.writeln( "// Class count: " + std::to_string( classes.size( ) ) );
                fmt.writeln( "// Enum count: " + std::to_string( enums.size( ) ) );

                fmt.block( "public static class " + to_pascal_case( slugify( module_name ) ), false,
                    [ & ] ( Formatter& fmt )
                {
                    for ( const auto& e : enums )
                    {
                        const char* type_name = nullptr;
                        switch ( e.alignment )
                        {
                            case 1: type_name = "byte"; break;
                            case 2: type_name = "ushort"; break;
                            case 4: type_name = "uint"; break;
                            case 8: type_name = "ulong"; break;
                            default: continue;
                        }

                        fmt.writeln( "// Alignment: " + std::to_string( e.alignment ) );
                        fmt.writeln( "// Member count: " + std::to_string( e.size ) );

                        fmt.block( "public enum " + slugify( e.name ) + " : " + type_name, false,
                            [ & ] ( Formatter& fmt )
                        {
                            std::string members;
                            for ( size_t i = 0; i < e.members.size( ); ++i )
                            {
                                if ( i > 0 ) members += ",\n";
                                const auto& m = e.members[ i ];
                                std::string formatted;
                                if ( m.value >= 0 && m.value <= INT32_MAX )
                                {
                                    formatted = to_hex( static_cast< uint64_t >( m.value ) );
                                }
                                else
                                {
                                    formatted = "unchecked((" + std::string( type_name ) + ")" +
                                        std::to_string( m.value ) + ")";
                                }
                                members += m.name + " = " + formatted;
                            }
                            fmt.writeln( members );
                        } );
                    }

                    for ( const auto& c : classes )
                    {
                        std::string parent = c.parent_name.has_value( )
                            ? slugify( c.parent_name.value( ) )
                            : "None";

                        fmt.writeln( "// Parent: " + parent );
                        fmt.writeln( "// Field count: " + std::to_string( c.fields.size( ) ) );
                        write_metadata( fmt, c.metadata );

                        fmt.block( "public static class " + slugify( c.name ), false,
                            [ & ] ( Formatter& fmt )
                        {
                            for ( const auto& f : c.fields )
                            {
                                fmt.writeln( "public const nint " + f.name + " = " +
                                    to_hex( f.offset ) + "; // " + f.type_name );
                            }
                        } );
                    }
                } );
            }
        } );

        return out;
    }

    std::string schemas_hpp( const SchemaMap& schemas, int indent_size )
    {
        std::string out;
        Formatter fmt( out, indent_size );

        fmt.writeln( "#pragma once" );
        fmt.writeln( );
        fmt.writeln( "#include <cstddef>" );
        fmt.writeln( "#include <cstdint>" );
        fmt.writeln( );

        fmt.block( "namespace cs2_dumper", false, [ & ] ( Formatter& fmt )
        {
            fmt.block( "namespace schemas", false, [ & ] ( Formatter& fmt )
            {
                for ( const auto& [module_name, pair] : schemas )
                {
                    const auto& [classes, enums] = pair;

                    fmt.writeln( "// Module: " + module_name );
                    fmt.writeln( "// Class count: " + std::to_string( classes.size( ) ) );
                    fmt.writeln( "// Enum count: " + std::to_string( enums.size( ) ) );

                    fmt.block( "namespace " + to_snake_case( slugify( module_name ) ), false,
                        [ & ] ( Formatter& fmt )
                    {
                        for ( const auto& e : enums )
                        {
                            const char* type_name = nullptr;
                            switch ( e.alignment )
                            {
                                case 1: type_name = "uint8_t"; break;
                                case 2: type_name = "uint16_t"; break;
                                case 4: type_name = "uint32_t"; break;
                                case 8: type_name = "uint64_t"; break;
                                default: continue;
                            }

                            fmt.writeln( "// Alignment: " + std::to_string( e.alignment ) );
                            fmt.writeln( "// Member count: " + std::to_string( e.size ) );

                            fmt.block( "enum class " + slugify( e.name ) + " : " + type_name, true,
                                [ & ] ( Formatter& fmt )
                            {
                                std::string members;
                                for ( size_t i = 0; i < e.members.size( ); ++i )
                                {
                                    if ( i > 0 ) members += ",\n";
                                    const auto& m = e.members[ i ];
                                    std::string formatted;
                                    if ( m.value >= 0 && m.value <= INT32_MAX )
                                    {
                                        formatted = to_hex( static_cast< uint64_t >( m.value ) );
                                    }
                                    else
                                    {
                                        uint64_t max_val = 0;
                                        if ( strcmp( type_name, "uint8_t" ) == 0 ) max_val = 0xFF;
                                        else if ( strcmp( type_name, "uint16_t" ) == 0 ) max_val = 0xFFFF;
                                        else if ( strcmp( type_name, "uint32_t" ) == 0 ) max_val = 0xFFFFFFFF;
                                        else max_val = 0xFFFFFFFFFFFFFFFF;
                                        formatted = to_hex( max_val );
                                    }
                                    members += m.name + " = " + formatted;
                                }
                                fmt.writeln( members );
                            } );
                        }

                        for ( const auto& c : classes )
                        {
                            std::string parent = c.parent_name.has_value( )
                                ? slugify( c.parent_name.value( ) )
                                : "None";

                            fmt.writeln( "// Parent: " + parent );
                            fmt.writeln( "// Field count: " + std::to_string( c.fields.size( ) ) );
                            write_metadata( fmt, c.metadata );

                            fmt.block( "namespace " + slugify( c.name ), false,
                                [ & ] ( Formatter& fmt )
                            {
                                for ( const auto& f : c.fields )
                                {
                                    fmt.writeln( "constexpr std::ptrdiff_t " + f.name + " = " +
                                        to_hex( f.offset ) + "; // " + f.type_name );
                                }
                            } );
                        }
                    } );
                }
            } );
        } );

        return out;
    }

    std::string schemas_json( const SchemaMap& schemas, int indent_size )
    {
        std::string json = "{";
        bool first_mod = true;

        for ( const auto& [module_name, pair] : schemas )
        {
            const auto& [classes, enums] = pair;
            if ( !first_mod ) json += ",";

            json += JsonBuilder::escape_string( module_name ) + ":{";

            json += "\"classes\":{";
            bool first_class = true;
            for ( const auto& c : classes )
            {
                if ( !first_class ) json += ",";

                json += JsonBuilder::escape_string( slugify( c.name ) ) + ":{";

                if ( c.parent_name.has_value( ) )
                {
                    json += "\"parent\":" + JsonBuilder::escape_string( c.parent_name.value( ) ) + ",";
                }
                else
                {
                    json += "\"parent\":null,";
                }

                json += "\"fields\":{";
                bool first_field = true;
                for ( const auto& f : c.fields )
                {
                    if ( !first_field ) json += ",";
                    json += JsonBuilder::escape_string( f.name ) + ":" + std::to_string( f.offset );
                    first_field = false;
                }
                json += "},";

                json += "\"metadata\":[";
                bool first_meta = true;
                for ( const auto& m : c.metadata )
                {
                    if ( !first_meta ) json += ",";
                    json += "{";
                    switch ( m.type )
                    {
                        case ClassMetadata::NetworkChangeCallback:
                            json += "\"type\":\"NetworkChangeCallback\",";
                            json += "\"name\":" + JsonBuilder::escape_string( m.name );
                            break;
                        case ClassMetadata::NetworkVarNames:
                            json += "\"type\":\"NetworkVarNames\",";
                            json += "\"name\":" + JsonBuilder::escape_string( m.name ) + ",";
                            json += "\"type_name\":" + JsonBuilder::escape_string( m.type_name );
                            break;
                        case ClassMetadata::Unknown:
                            json += "\"type\":\"Unknown\",";
                            json += "\"name\":" + JsonBuilder::escape_string( m.name );
                            break;
                    }
                    json += "}";
                    first_meta = false;
                }
                json += "]";

                json += "}";
                first_class = false;
            }
            json += "},";

            json += "\"enums\":{";
            bool first_enum = true;
            for ( const auto& e : enums )
            {
                if ( !first_enum ) json += ",";

                const char* type_str = "unknown";
                switch ( e.alignment )
                {
                    case 1: type_str = "uint8"; break;
                    case 2: type_str = "uint16"; break;
                    case 4: type_str = "uint32"; break;
                    case 8: type_str = "uint64"; break;
                }

                json += JsonBuilder::escape_string( slugify( e.name ) ) + ":{";
                json += "\"alignment\":" + std::to_string( e.alignment ) + ",";
                json += "\"type\":" + JsonBuilder::escape_string( type_str ) + ",";

                json += "\"members\":{";
                bool first_member = true;
                for ( const auto& m : e.members )
                {
                    if ( !first_member ) json += ",";
                    json += JsonBuilder::escape_string( m.name ) + ":" + std::to_string( m.value );
                    first_member = false;
                }
                json += "}";

                json += "}";
                first_enum = false;
            }
            json += "}";

            json += "}";
            first_mod = false;
        }
        json += "}";

        return JsonBuilder::prettify( json, indent_size );
    }

    std::string schemas_rs( const SchemaMap& schemas, int indent_size )
    {
        std::string out;
        Formatter fmt( out, indent_size );

        fmt.writeln( "#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, unused)]" );
        fmt.writeln( );

        fmt.block( "pub mod cs2_dumper", false, [ & ] ( Formatter& fmt )
        {
            fmt.block( "pub mod schemas", false, [ & ] ( Formatter& fmt )
            {
                for ( const auto& [module_name, pair] : schemas )
                {
                    const auto& [classes, enums] = pair;

                    fmt.writeln( "// Module: " + module_name );
                    fmt.writeln( "// Class count: " + std::to_string( classes.size( ) ) );
                    fmt.writeln( "// Enum count: " + std::to_string( enums.size( ) ) );

                    fmt.block( "pub mod " + to_snake_case( slugify( module_name ) ), false,
                        [ & ] ( Formatter& fmt )
                    {
                        for ( const auto& e : enums )
                        {
                            const char* type_name = nullptr;
                            switch ( e.alignment )
                            {
                                case 1: type_name = "u8"; break;
                                case 2: type_name = "u16"; break;
                                case 4: type_name = "u32"; break;
                                case 8: type_name = "u64"; break;
                                default: continue;
                            }

                            fmt.writeln( "// Alignment: " + std::to_string( e.alignment ) );
                            fmt.writeln( "// Member count: " + std::to_string( e.size ) );

                            fmt.writeln( "#[repr(" + std::string( type_name ) + ")]" );
                            fmt.block( "pub enum " + slugify( e.name ), false,
                                [ & ] ( Formatter& fmt )
                            {
                                std::set<int64_t> used_values;
                                std::string members;
                                bool first = true;
                                for ( const auto& m : e.members )
                                {
                                    if ( !used_values.insert( m.value ).second )
                                        continue;

                                    if ( !first ) members += ",\n";

                                    std::string formatted;
                                    if ( m.value == -1 )
                                    {
                                        formatted = std::string( type_name ) + "::MAX";
                                    }
                                    else
                                    {
                                        formatted = to_hex( static_cast< uint64_t >( m.value ) );
                                    }

                                    members += m.name + " = " + formatted;
                                    first = false;
                                }
                                fmt.writeln( members );
                            } );
                        }

                        for ( const auto& c : classes )
                        {
                            std::string parent = c.parent_name.has_value( )
                                ? slugify( c.parent_name.value( ) )
                                : "None";

                            fmt.writeln( "// Parent: " + parent );
                            fmt.writeln( "// Field count: " + std::to_string( c.fields.size( ) ) );
                            write_metadata( fmt, c.metadata );

                            fmt.block( "pub mod " + slugify( c.name ), false,
                                [ & ] ( Formatter& fmt )
                            {
                                for ( const auto& f : c.fields )
                                {
                                    fmt.writeln( "pub const " + f.name + ": usize = " +
                                        to_hex( f.offset ) + "; // " + f.type_name );
                                }
                            } );
                        }
                    } );
                }
            } );
        } );

        return out;
    }

} // namespace writers
