#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

class Process;

using ButtonMap = std::map<std::string, uint64_t>;
using InterfaceMap = std::map<std::string, std::map<std::string, uint64_t>>;
using OffsetMap = std::map<std::string, std::map<std::string, uint32_t>>;

struct ClassMetadata
{
    enum Type
    {
        Unknown, NetworkChangeCallback, NetworkVarNames
    };
    Type type = Unknown;
    std::string name;
    std::string type_name;
};

struct ClassField
{
    std::string name;
    std::string type_name;
    int32_t offset = 0;
};

struct Class
{
    std::string name;
    std::string module_name;
    std::optional<std::string> parent_name;
    std::vector<ClassMetadata> metadata;
    std::vector<ClassField> fields;
};

struct EnumMember
{
    std::string name;
    int64_t value = 0;
};

struct Enum
{
    std::string name;
    uint8_t alignment = 0;
    uint16_t size = 0;
    std::vector<EnumMember> members;
};

using SchemaMap = std::map<std::string, std::pair<std::vector<Class>, std::vector<Enum>>>;

struct AnalysisResult
{
    ButtonMap buttons;
    InterfaceMap interfaces;
    OffsetMap offsets;
    SchemaMap schemas;
};

AnalysisResult analyze_all( Process& process );
ButtonMap analyze_buttons( Process& process );
InterfaceMap analyze_interfaces( Process& process );
OffsetMap analyze_offsets( Process& process );
SchemaMap analyze_schemas( Process& process );
