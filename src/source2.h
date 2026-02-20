#pragma once

#include <cstdint>
#include <cstring>
#include <set>
#include <vector>

class Process;

#pragma pack(push, 1)

struct KeyButton
{
    uint8_t pad_0[ 0x8 ];
    uint64_t name;
    uint8_t pad_1[ 0x20 ];
    uint32_t state;
    uint8_t pad_2[ 0x54 ];
    uint64_t next;
};
static_assert( sizeof( KeyButton ) == 0x90, "KeyButton layout mismatch" );

struct InterfaceReg
{
    uint64_t create_fn;
    uint64_t name;
    uint64_t next;
};
static_assert( sizeof( InterfaceReg ) == 0x18, "InterfaceReg layout mismatch" );

struct SchemaClassFieldData
{
    uint64_t name;
    uint64_t type_ptr;
    int32_t offset;
    int32_t metadata_count;
    uint64_t metadata;
};
static_assert( sizeof( SchemaClassFieldData ) == 0x20, "SchemaClassFieldData layout mismatch" );

struct SchemaMetadataEntryData
{
    uint64_t name;
    uint64_t network_value;
};
static_assert( sizeof( SchemaMetadataEntryData ) == 0x10, "SchemaMetadataEntryData layout mismatch" );

struct SchemaVarName
{
    uint64_t name;
    uint64_t type_name;
};
static_assert( sizeof( SchemaVarName ) == 0x10, "SchemaVarName layout mismatch" );

struct SchemaNetworkValue
{
    union
    {
        uint64_t name_ptr;
        int32_t int_value;
        float float_value;
        uint64_t ptr_value;
        SchemaVarName var_value;
        char name_value[ 32 ];
    };
};

struct SchemaBaseClass
{
    uint8_t pad_0[ 0x10 ];
    uint64_t name;
};
static_assert( sizeof( SchemaBaseClass ) == 0x18, "SchemaBaseClass layout mismatch" );

struct SchemaBaseClassInfoData
{
    uint8_t pad_0[ 0x18 ];
    uint64_t class_ptr;
};
static_assert( sizeof( SchemaBaseClassInfoData ) == 0x20, "SchemaBaseClassInfoData layout mismatch" );

struct SchemaType
{
    uint8_t  pad_0[ 0x8 ];
    uint64_t name;
    uint64_t type_scope;
    uint8_t  type_category;
    uint8_t  atomic_category;
    uint8_t  pad_1[ 0x6 ];
};

struct SchemaClassInfoData
{
    uint64_t base;
    uint64_t name;
    uint64_t module_name;
    int32_t  size;
    int16_t  field_count;
    int16_t  static_metadata_count;
    uint8_t  pad_0[ 0x2 ];
    uint8_t  alignment;
    uint8_t  has_base_class;
    int16_t  total_class_size;
    int16_t  derived_class_size;
    uint64_t fields;
    uint8_t  pad_1[ 0x8 ];
    uint64_t base_classes;
    uint64_t static_metadata;
    uint8_t  pad_2[ 0x8 ];
    uint64_t type_scope;
    uint64_t type_ptr;
    uint8_t  pad_3[ 0x10 ];
};
static_assert( sizeof( SchemaClassInfoData ) == 0x70, "SchemaClassInfoData layout mismatch" );

struct SchemaEnumeratorInfoData
{
    uint64_t name;
    uint64_t value;
    int32_t  metadata_count;
    uint8_t  pad_0[ 0x4 ];
    uint64_t metadata;
};
static_assert( sizeof( SchemaEnumeratorInfoData ) == 0x20, "SchemaEnumeratorInfoData layout mismatch" );

struct SchemaEnumInfoData
{
    uint64_t base;
    uint64_t name;
    uint64_t module_name;
    uint8_t size;
    uint8_t alignment;
    uint8_t flags;
    uint8_t pad_0;
    uint16_t enumerator_count;
    uint16_t static_metadata_count;
    uint64_t enumerators;
    uint64_t static_metadata;
    uint64_t type_scope;
    int64_t min_enumerator_value;
    int64_t max_enumerator_value;
};
static_assert( sizeof( SchemaEnumInfoData ) == 0x48, "SchemaEnumInfoData layout mismatch" );

#pragma pack(pop)

namespace SchemaSystemOff
{
    constexpr size_t TypeScopes = 0x0190;
    constexpr size_t RegistrationCnt = 0x0280;
}

namespace UtlVectorOff
{
    constexpr size_t Count = 0x0000;
    constexpr size_t Data = 0x0008;
}

namespace TypeScopeOff
{
    constexpr size_t Name = 0x0008;
    constexpr size_t ClassBindings = 0x0560;
    constexpr size_t EnumBindings = 0x1DD0;
}

namespace UtlTsHashOff
{
    constexpr size_t BlocksAllocated = 0x000C;
    constexpr size_t PeakAllocated = 0x0010;
    constexpr size_t FreeBlocksNext = 0x0020;
    constexpr size_t Buckets = 0x0060;
    constexpr size_t BucketCount = 256;
    constexpr size_t BucketSize = 0x18;
    constexpr size_t TotalSize = 0x1870;
}

namespace UtlTsHashBucketOff
{
    constexpr size_t FirstUncommitted = 0x0010;
}

namespace UtlTsHashFixedDataOff
{
    constexpr size_t Key = 0x0000;
    constexpr size_t Next = 0x0008;
    constexpr size_t Data = 0x0010;
}

namespace UtlTsHashAllocatedBlobOff
{
    constexpr size_t Next = 0x0000;
    constexpr size_t Data = 0x0010;
}

inline std::vector<uint64_t> utl_ts_hash_elements( const Process& process, uint64_t hash_addr )
{
    int32_t blocks_allocated = 0;
    int32_t peak_allocated = 0;
    process.read( static_cast< uintptr_t >( hash_addr + UtlTsHashOff::BlocksAllocated ), blocks_allocated );
    process.read( static_cast< uintptr_t >( hash_addr + UtlTsHashOff::PeakAllocated ), peak_allocated );

    std::vector<uint64_t> result;
    result.reserve( static_cast< size_t >( blocks_allocated + peak_allocated ) );

    for ( size_t i = 0; i < UtlTsHashOff::BucketCount; ++i )
    {
        uint64_t bucket_addr = hash_addr + UtlTsHashOff::Buckets + i * UtlTsHashOff::BucketSize;
        uint64_t node_ptr = 0;
        process.read( static_cast< uintptr_t >( bucket_addr + UtlTsHashBucketOff::FirstUncommitted ), node_ptr );

        while ( node_ptr != 0 )
        {
            uint64_t data_ptr = 0;
            process.read( static_cast< uintptr_t >( node_ptr + UtlTsHashFixedDataOff::Data ), data_ptr );

            if ( data_ptr != 0 )
            {
                result.push_back( data_ptr );
            }

            if ( static_cast< int >( result.size( ) ) >= blocks_allocated )
                break;

            uint64_t next = 0;
            process.read( static_cast< uintptr_t >( node_ptr + UtlTsHashFixedDataOff::Next ), next );
            node_ptr = next;
        }
    }

    uint64_t blob_ptr = 0;
    process.read( static_cast< uintptr_t >( hash_addr + UtlTsHashOff::FreeBlocksNext ), blob_ptr );

    size_t free_count = 0;
    while ( blob_ptr != 0 && free_count < static_cast< size_t >( peak_allocated ) )
    {
        uint64_t data_ptr = 0;
        process.read( static_cast< uintptr_t >( blob_ptr + UtlTsHashAllocatedBlobOff::Data ), data_ptr );

        if ( data_ptr != 0 )
        {
            result.push_back( data_ptr );
        }

        ++free_count;

        uint64_t next = 0;
        process.read( static_cast< uintptr_t >( blob_ptr + UtlTsHashAllocatedBlobOff::Next ), next );
        blob_ptr = next;
    }

    std::set<uint64_t> seen;
    std::vector<uint64_t> unique;
    unique.reserve( result.size( ) );
    for ( auto ptr : result )
    {
        if ( seen.insert( ptr ).second )
        {
            unique.push_back( ptr );
        }
    }

    return unique;
}
