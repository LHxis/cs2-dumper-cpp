#include "analysis.h"
#include "process.h"
#include "pattern.h"
#include "pe.h"
#include "source2.h"
#include "util.h"

#include <algorithm>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>

AnalysisResult analyze_all( Process& process )
{
    AnalysisResult result;

    try
    {
        result.buttons = analyze_buttons( process );
        LOG_INFO( "found %zu buttons", result.buttons.size( ) );
    }
    catch ( const std::exception& e )
    {
        LOG_ERROR( "failed to read buttons: %s", e.what( ) );
    }

    try
    {
        result.interfaces = analyze_interfaces( process );
        size_t total = 0;
        for ( auto& [_, ifaces] : result.interfaces ) total += ifaces.size( );
        LOG_INFO( "found %zu interfaces across %zu modules", total, result.interfaces.size( ) );
    }
    catch ( const std::exception& e )
    {
        LOG_ERROR( "failed to read interfaces: %s", e.what( ) );
    }

    try
    {
        result.offsets = analyze_offsets( process );
        size_t total = 0;
        for ( auto& [_, offs] : result.offsets ) total += offs.size( );
        LOG_INFO( "found %zu offsets across %zu modules", total, result.offsets.size( ) );
    }
    catch ( const std::exception& e )
    {
        LOG_ERROR( "failed to read offsets: %s", e.what( ) );
    }

    try
    {
        result.schemas = analyze_schemas( process );
        size_t class_count = 0, enum_count = 0;
        for ( auto& [_, pair] : result.schemas )
        {
            class_count += pair.first.size( );
            enum_count += pair.second.size( );
        }
        LOG_INFO( "found %zu classes and %zu enums across %zu modules",
            class_count, enum_count, result.schemas.size( ) );
    }
    catch ( const std::exception& e )
    {
        LOG_ERROR( "failed to read schemas: %s", e.what( ) );
    }

    return result;
}

ButtonMap analyze_buttons( Process& process )
{
    auto module = process.module_by_name( "client.dll" );
    auto buf = process.read_raw( module.base, module.size );

    if ( buf.empty( ) )
        throw std::runtime_error( "failed to read client.dll" );

    auto pat = pattern::parse( "48 8B 15 ?? ?? ?? ?? 48 85 D2 74 ?? 48 8B 02 48 85 C0" );
    auto match = pattern::find( buf.data( ), buf.size( ), pat );

    if ( match < 0 )
        throw std::runtime_error( "outdated button list pattern" );

    uint32_t list_ptr_rva = pattern::resolve_rip( buf.data( ), match, 3 );

    uint64_t list_head = process.read_addr64( module.base + list_ptr_rva );

    ButtonMap result;
    uint64_t button_ptr = list_head;

    while ( button_ptr != 0 )
    {
        KeyButton button{ };
        if ( !process.read( static_cast< uintptr_t >( button_ptr ), button ) )
            break;

        std::string name = process.read_string( static_cast< uintptr_t >( button.name ), 32 );

        uint64_t state_addr = button_ptr + offsetof( KeyButton, state );

        if ( state_addr >= module.base )
        {
            uint64_t state_rva = state_addr - module.base;

            LOG_DEBUG( "found \"%s\" at 0x%llX (%s + 0x%llX)", name.c_str( ), state_addr, module.name.c_str( ), state_rva );

            result[ name ] = state_rva;
        }

        button_ptr = button.next;
    }

    return result;
}

InterfaceMap analyze_interfaces( Process& process )
{
    InterfaceMap result;

    for ( const auto& module : process.module_list( ) )
    {
        auto buf = process.read_raw( module.base, module.size );
        if ( buf.empty( ) )
            continue;

        uint32_t ci_rva = pe::find_export_rva( buf.data( ), buf.size( ), "CreateInterface" );
        if ( ci_rva == 0 )
            continue;

        uintptr_t list_ptr = address::resolve_rip( process, module.base + ci_rva );

        uint64_t list_head = process.read_addr64( list_ptr );

        if ( list_head == 0 )
            continue;

        std::map<std::string, uint64_t> ifaces;
        uint64_t reg_ptr = list_head;

        while ( reg_ptr != 0 )
        {
            InterfaceReg reg{ };
            if ( !process.read( static_cast< uintptr_t >( reg_ptr ), reg ) )
                break;

            std::string name = process.read_string( static_cast< uintptr_t >( reg.name ), 128 );
            if ( name.empty( ) )
            {
                reg_ptr = reg.next;
                continue;
            }

            uintptr_t instance_addr = address::resolve_rip( process, static_cast< uintptr_t >( reg.create_fn ) );

            if ( instance_addr >= module.base )
            {
                uint64_t instance_rva = instance_addr - module.base;

                LOG_DEBUG( "found \"%s\" at 0x%llX (%s + 0x%llX)",
                    name.c_str( ), ( unsigned long long )instance_addr,
                    module.name.c_str( ), ( unsigned long long )instance_rva );

                ifaces[ name ] = instance_rva;
            }

            reg_ptr = reg.next;
        }

        if ( !ifaces.empty( ) )
        {
            result[ module.name ] = std::move( ifaces );
        }
    }

    return result;
}

enum class CaptureType
{
    RipRel,
    RawU32,
    RawU8,
};

struct OffsetPattern
{
    const char* name;
    const char* pattern_str;
    int capture_offset;
    CaptureType capture_type;
    int extra_offset;
};

struct DerivedOffsetPattern
{
    const char* base_name;
    const char* derived_name;
    const char* pattern_str;
    int capture_offset;
    CaptureType capture_type;
};

static const OffsetPattern client_patterns[ ] = {
    { "dwCSGOInput",
    "48 89 05 ?? ?? ?? ?? 0F 57 C0 0F 11 05", 3, CaptureType::RipRel, 0 },
    { "dwEntityList",
    "48 89 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? CC", 3, CaptureType::RipRel, 0 },
    { "dwGameEntitySystem",
    "48 8B 1D ?? ?? ?? ?? 48 89 1D ?? ?? ?? ?? 4C 63 B3", 3, CaptureType::RipRel, 0 },
    { "dwGameEntitySystem_highestEntityIndex",
    "FF 81 ?? ?? ?? ?? 48 85 D2", 2, CaptureType::RawU32, 0 },
    { "dwGameRules",
    "48 89 1D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 84 C0", 3, CaptureType::RipRel, 0 },
    { "dwGlobalVars",
    "48 89 15 ?? ?? ?? ?? 48 89 42", 3, CaptureType::RipRel, 0 },
    { "dwGlowManager",
    "48 8B 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 8B 41", 3, CaptureType::RipRel, 0 },
    { "dwLocalPlayerController",
    "48 8B 05 ?? ?? ?? ?? 41 89 BE", 3, CaptureType::RipRel, 0 },
    { "dwPlantedC4",
    "48 8B 15 ?? ?? ?? ?? 41 FF C0 48 8D 4C 24 ?? 44 89 05", 3, CaptureType::RipRel, 0 },
    { "dwPrediction",
    "48 8D 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 40 53 56 41 54", 3, CaptureType::RipRel, 0 },
    { "dwSensitivity",
    "48 8D 0D ?? ?? ?? ?? 66 0F 6E CD", 3, CaptureType::RipRel, 8 },
    { "dwSensitivity_sensitivity",
    "48 8D 7E ?? 48 0F BA E0 ?? 72 ?? 85 D2 49 0F 4F FF", 3, CaptureType::RawU8, 0 },
    { "dwViewMatrix",
    "48 8D 0D ?? ?? ?? ?? 48 C1 E0 06", 3, CaptureType::RipRel, 0 },
    { "dwViewRender",
    "48 89 05 ?? ?? ?? ?? 48 8B C8 48 85 C0", 3, CaptureType::RipRel, 0 },
    { "dwWeaponC4",
    "48 8B 15 ?? ?? ?? ?? 48 8B 5C 24 ?? FF C0 89 05 ?? ?? ?? ?? 48 8B C6 48 89 34 EA 80 BE", 3, CaptureType::RipRel, 0 },
};

static const DerivedOffsetPattern client_derived[ ] = {
    { "dwCSGOInput", "dwViewAngles",
    "F2 42 0F 10 84 28 ?? ?? ?? ??", 6, CaptureType::RawU32 },
    { "dwPrediction", "dwLocalPlayerPawn",
    "4C 39 B6 ?? ?? ?? ?? 74 ?? 44 88 BE", 3, CaptureType::RawU32 },
};

static const OffsetPattern engine2_patterns[ ] = {
    { "dwBuildNumber",
    "89 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 0D", 2, CaptureType::RipRel, 0 },
    { "dwNetworkGameClient",
    "48 89 3D ?? ?? ?? ?? FF 87", 3, CaptureType::RipRel, 0 },
    { "dwNetworkGameClient_clientTickCount",
    "8B 81 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC CC 8B 81 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC CC 83 B9", 2, CaptureType::RawU32, 0 },
    { "dwNetworkGameClient_deltaTick",
    "4C 8D B7 ?? ?? ?? ?? 4C 89 7C 24", 3, CaptureType::RawU32, 0 },
    { "dwNetworkGameClient_isBackgroundMap",
    "0F B6 81 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 0F B6 81 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 40 53", 3, CaptureType::RawU32, 0 },
    { "dwNetworkGameClient_localPlayer",
    "42 8B 94 D3 ?? ?? ?? ?? 5B 49 FF E3 32 C0 5B C3 CC CC CC CC CC CC CC CC 40 53", 4, CaptureType::RawU32, 0 },
    { "dwNetworkGameClient_maxClients",
    "8B 81 ?? ?? ?? ?? C3 ?? ?? ?? ?? ?? ?? ?? ?? ?? 8B 81 ?? ?? ?? ?? C3 ?? ?? ?? ?? ?? ?? ?? ?? ?? 8B 81", 2, CaptureType::RawU32, 0 },
    { "dwNetworkGameClient_serverTickCount",
    "8B 81 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC CC 83 B9", 2, CaptureType::RawU32, 0 },
    { "dwNetworkGameClient_signOnState",
    "44 8B 81 ?? ?? ?? ?? 48 8D 0D", 3, CaptureType::RawU32, 0 },
    { "dwWindowHeight",
    "8B 05 ?? ?? ?? ?? 89 03", 2, CaptureType::RipRel, 0 },
    { "dwWindowWidth",
    "8B 05 ?? ?? ?? ?? 89 07", 2, CaptureType::RipRel, 0 },
};

static const OffsetPattern input_system_patterns[ ] = {
    { "dwInputSystem",
    "48 89 05 ?? ?? ?? ?? 33 C0", 3, CaptureType::RipRel, 0 },
};

static const OffsetPattern matchmaking_patterns[ ] = {
    { "dwGameTypes",
    "48 8D 0D ?? ?? ?? ?? FF 90", 3, CaptureType::RipRel, 0 },
};

static const OffsetPattern soundsystem_patterns[ ] = {
    { "dwSoundSystem",
    "48 8D 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 48 89 15", 3, CaptureType::RipRel, 0 },
    { "dwSoundSystem_engineViewData",
    "0F 11 47 ?? 0F 10 4E ?? 0F 11 8F", 3, CaptureType::RawU8, 0 },
};

static std::map<std::string, uint32_t> scan_patterns( const uint8_t* data, size_t data_size, const OffsetPattern* patterns, size_t pattern_count, const char* module_debug_name, uint64_t image_base )
{
    std::map<std::string, uint32_t> map;

    for ( size_t i = 0; i < pattern_count; ++i )
    {
        const auto& p = patterns[ i ];
        auto pat = pattern::parse( p.pattern_str );
        auto match = pattern::find( data, data_size, pat );

        if ( match < 0 )
        {
            LOG_ERROR( "outdated pattern: %s", p.name );
            continue;
        }

        uint32_t rva = 0;
        switch ( p.capture_type )
        {
            case CaptureType::RipRel:
                rva = pattern::resolve_rip( data, match, p.capture_offset ) + p.extra_offset;
                break;
            case CaptureType::RawU32:
                rva = pattern::read_u32( data, match, p.capture_offset ) + p.extra_offset;
                break;
            case CaptureType::RawU8:
                rva = pattern::read_u8( data, match, p.capture_offset ) + p.extra_offset;
                break;
        }

        map[ p.name ] = rva;

        LOG_DEBUG( "found \"%s\" at 0x%llX (%s + 0x%X)",
            p.name,
            static_cast< unsigned long long >( rva ) + image_base,
            module_debug_name, rva );
    }

    return map;
}

OffsetMap analyze_offsets( Process& process )
{
    OffsetMap result;

    struct ModulePatterns
    {
        const char* module_name;
        const OffsetPattern* patterns;
        size_t count;
        const DerivedOffsetPattern* derived;
        size_t derived_count;
    };

    ModulePatterns modules[ ] = {
        { "client.dll", client_patterns, std::size( client_patterns ),
        client_derived, std::size( client_derived ) },
        { "engine2.dll", engine2_patterns, std::size( engine2_patterns ),
        nullptr, 0 },
        { "inputsystem.dll", input_system_patterns, std::size( input_system_patterns ),
        nullptr, 0 },
        { "matchmaking.dll", matchmaking_patterns, std::size( matchmaking_patterns ),
        nullptr, 0 },
        { "soundsystem.dll", soundsystem_patterns, std::size( soundsystem_patterns ),
        nullptr, 0 },
    };

    for ( const auto& mod : modules )
    {
        auto module = process.module_by_name( mod.module_name );
        auto buf = process.read_raw( module.base, module.size );

        if ( buf.empty( ) )
        {
            LOG_ERROR( "failed to read module: %s", mod.module_name );
            continue;
        }

        uint64_t image_base = pe::get_image_base( buf.data( ), buf.size( ) );
        auto map = scan_patterns( buf.data( ), buf.size( ),
            mod.patterns, mod.count,
            mod.module_name, image_base );

        if ( mod.derived )
        {
            for ( size_t i = 0; i < mod.derived_count; ++i )
            {
                const auto& d = mod.derived[ i ];
                auto base_it = map.find( d.base_name );
                if ( base_it == map.end( ) )
                    continue;

                auto pat = pattern::parse( d.pattern_str );
                auto match = pattern::find( buf.data( ), buf.size( ), pat );
                if ( match < 0 )
                {
                    LOG_ERROR( "outdated derived pattern: %s", d.derived_name );
                    continue;
                }

                uint32_t val = 0;
                switch ( d.capture_type )
                {
                    case CaptureType::RipRel:
                        val = pattern::resolve_rip( buf.data( ), match, d.capture_offset );
                        break;
                    case CaptureType::RawU32:
                        val = pattern::read_u32( buf.data( ), match, d.capture_offset );
                        break;
                    case CaptureType::RawU8:
                        val = pattern::read_u8( buf.data( ), match, d.capture_offset );
                        break;
                }

                map[ d.derived_name ] = base_it->second + val;

                LOG_DEBUG( "found \"%s\" at (%s + 0x%X)",
                    d.derived_name, mod.module_name,
                    base_it->second + val );
            }
        }

        result[ mod.module_name ] = std::move( map );
    }

    return result;
}

static std::string str_replace_all( const std::string& str, const std::string& from, const std::string& to )
{
    std::string result = str;
    size_t pos = 0;
    while ( ( pos = result.find( from, pos ) ) != std::string::npos )
    {
        result.replace( pos, from.length( ), to );
        pos += to.length( );
    }
    return result;
}

static bool read_class_binding( Process& process, uint64_t binding_addr, Class& out_class )
{
    SchemaClassInfoData binding{ };
    if ( !process.read( static_cast< uintptr_t >( binding_addr ), binding ) )
        return false;

    std::string module_name = process.read_string( static_cast< uintptr_t >( binding.module_name ), 128 );
    if ( module_name.empty( ) ) return false;
    module_name += ".dll";

    std::string name = process.read_string( static_cast< uintptr_t >( binding.name ), 128 );
    if ( name.empty( ) ) return false;

    std::optional<std::string> parent_name;
    if ( binding.base_classes != 0 )
    {
        SchemaBaseClassInfoData base_class_info{ };
        if ( process.read( static_cast< uintptr_t >( binding.base_classes ), base_class_info ) )
        {
            if ( base_class_info.class_ptr != 0 )
            {
                SchemaBaseClass parent{ };
                if ( process.read( static_cast< uintptr_t >( base_class_info.class_ptr ), parent ) )
                {
                    std::string pname = process.read_string( static_cast< uintptr_t >( parent.name ), 128 );
                    if ( !pname.empty( ) )
                    {
                        parent_name = pname;
                    }
                }
            }
        }
    }

    std::vector<ClassField> fields;
    if ( binding.fields != 0 && binding.field_count > 0 )
    {
        for ( int i = 0; i < binding.field_count; ++i )
        {
            uint64_t field_addr = binding.fields + static_cast< uint64_t >( i ) * sizeof( SchemaClassFieldData );
            SchemaClassFieldData field{ };
            if ( !process.read( static_cast< uintptr_t >( field_addr ), field ) )
                continue;

            if ( field.type_ptr == 0 )
                continue;

            std::string field_name = process.read_string( static_cast< uintptr_t >( field.name ), 128 );

            SchemaType schema_type{ };
            process.read( static_cast< uintptr_t >( field.type_ptr ), schema_type );
            std::string type_name = process.read_string( static_cast< uintptr_t >( schema_type.name ), 128 );
            type_name = str_replace_all( type_name, " ", "" );

            fields.push_back( { field_name, type_name, field.offset } );
        }
    }

    std::vector<ClassMetadata> metadata;
    if ( binding.static_metadata != 0 && binding.static_metadata_count > 0 )
    {
        for ( int i = 0; i < binding.static_metadata_count; ++i )
        {
            uint64_t meta_addr = binding.static_metadata + static_cast< uint64_t >( i ) * sizeof( SchemaMetadataEntryData );
            SchemaMetadataEntryData meta{ };
            if ( !process.read( static_cast< uintptr_t >( meta_addr ), meta ) )
                continue;

            if ( meta.network_value == 0 )
                continue;

            std::string meta_name = process.read_string( static_cast< uintptr_t >( meta.name ), 128 );

            SchemaNetworkValue net_val{ };
            process.read( static_cast< uintptr_t >( meta.network_value ), net_val );

            ClassMetadata cm;
            if ( meta_name == "MNetworkChangeCallback" )
            {
                cm.type = ClassMetadata::NetworkChangeCallback;
                cm.name = process.read_string( static_cast< uintptr_t >( net_val.name_ptr ), 128 );
            }
            else if ( meta_name == "MNetworkVarNames" )
            {
                cm.type = ClassMetadata::NetworkVarNames;
                cm.name = process.read_string( static_cast< uintptr_t >( net_val.var_value.name ), 128 );
                cm.type_name = process.read_string( static_cast< uintptr_t >( net_val.var_value.type_name ), 128 );
                cm.type_name = str_replace_all( cm.type_name, " ", "" );
            }
            else
            {
                cm.type = ClassMetadata::Unknown;
                cm.name = meta_name;
            }

            metadata.push_back( std::move( cm ) );
        }
    }

    out_class.name = std::move( name );
    out_class.module_name = std::move( module_name );
    out_class.parent_name = std::move( parent_name );
    out_class.metadata = std::move( metadata );
    out_class.fields = std::move( fields );

    return true;
}

static bool read_enum_binding( Process& process, uint64_t binding_addr, Enum& out_enum )
{
    SchemaEnumInfoData binding{ };
    if ( !process.read( static_cast< uintptr_t >( binding_addr ), binding ) )
        return false;

    std::string name = process.read_string( static_cast< uintptr_t >( binding.name ), 128 );
    if ( name.empty( ) ) return false;

    std::vector<EnumMember> members;
    if ( binding.enumerators != 0 && binding.enumerator_count > 0 )
    {
        for ( int i = 0; i < binding.enumerator_count; ++i )
        {
            uint64_t enum_addr = binding.enumerators + static_cast< uint64_t >( i ) * sizeof( SchemaEnumeratorInfoData );
            SchemaEnumeratorInfoData enumerator{ };
            if ( !process.read( static_cast< uintptr_t >( enum_addr ), enumerator ) )
                continue;

            std::string member_name = process.read_string( static_cast< uintptr_t >( enumerator.name ), 128 );
            members.push_back( { member_name, static_cast< int64_t >( enumerator.value ) } );
        }
    }

    out_enum.name = std::move( name );
    out_enum.alignment = binding.alignment;
    out_enum.size = binding.enumerator_count;
    out_enum.members = std::move( members );

    return true;
}

SchemaMap analyze_schemas( Process& process )
{
    auto module = process.module_by_name( "schemasystem.dll" );
    auto buf = process.read_raw( module.base, module.size );

    if ( buf.empty( ) )
        throw std::runtime_error( "failed to read schemasystem.dll" );

    auto pat = pattern::parse( "4C 8D 35 ?? ?? ?? ?? 0F 28 45" );
    auto match = pattern::find( buf.data( ), buf.size( ), pat );

    if ( match < 0 )
        throw std::runtime_error( "outdated schema system pattern" );

    uint32_t schema_system_rva = pattern::resolve_rip( buf.data( ), match, 3 );

    int32_t registration_count = 0;
    process.read( static_cast< uintptr_t >( module.base + schema_system_rva + SchemaSystemOff::RegistrationCnt ),
        registration_count );

    if ( registration_count == 0 )
        throw std::runtime_error( "no schema registrations" );

    uintptr_t type_scopes_addr = module.base + schema_system_rva + SchemaSystemOff::TypeScopes;

    int32_t scope_count = 0;
    process.read( type_scopes_addr + UtlVectorOff::Count, scope_count );

    uint64_t scope_data_ptr = 0;
    process.read( type_scopes_addr + UtlVectorOff::Data, scope_data_ptr );

    SchemaMap schema_map;

    for ( int32_t i = 0; i < scope_count; ++i )
    {
        uint64_t type_scope_ptr = 0;
        process.read( static_cast< uintptr_t >( scope_data_ptr + i * sizeof( uint64_t ) ), type_scope_ptr );

        if ( type_scope_ptr == 0 )
            continue;

        char scope_name_buf[ 256 ] = { };
        process.read_raw( static_cast< uintptr_t >( type_scope_ptr + TypeScopeOff::Name ),
            scope_name_buf, sizeof( scope_name_buf ) );
        std::string module_name( scope_name_buf );

        if ( module_name.empty( ) )
            continue;

        uint64_t class_hash_addr = type_scope_ptr + TypeScopeOff::ClassBindings;
        auto class_ptrs = utl_ts_hash_elements( process, class_hash_addr );

        std::vector<Class> classes;
        for ( auto ptr : class_ptrs )
        {
            Class cls;
            if ( read_class_binding( process, ptr, cls ) )
            {
                classes.push_back( std::move( cls ) );
            }
        }

        uint64_t enum_hash_addr = type_scope_ptr + TypeScopeOff::EnumBindings;
        auto enum_ptrs = utl_ts_hash_elements( process, enum_hash_addr );

        std::vector<Enum> enums;
        for ( auto ptr : enum_ptrs )
        {
            Enum e;
            if ( read_enum_binding( process, ptr, e ) )
            {
                enums.push_back( std::move( e ) );
            }
        }

        if ( classes.empty( ) && enums.empty( ) )
            continue;

        LOG_DEBUG( "module \"%s\" contains %zu class(es) and %zu enum(s)",
            module_name.c_str( ), classes.size( ), enums.size( ) );

        schema_map[ module_name ] = { std::move( classes ), std::move( enums ) };
    }

    return schema_map;
}
