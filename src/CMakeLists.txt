cmake_minimum_required(VERSION 3.16)
project(cs2-dumper LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Only builds on Windows (uses Windows API for process memory reading)
if(NOT WIN32)
    message(FATAL_ERROR "This project only supports Windows")
endif()

add_executable(cs2-dumper
    main.cpp
    process.cpp
    analysis.cpp
    output.cpp
)

target_include_directories(cs2-dumper PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Link Windows libraries
target_link_libraries(cs2-dumper PRIVATE
    psapi
)

# Release optimizations
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(cs2-dumper PRIVATE /O2)
    set_target_properties(cs2-dumper PROPERTIES
        LINK_FLAGS "/LTCG"
    )
endif()

# MSVC-specific settings
if(MSVC)
    target_compile_options(cs2-dumper PRIVATE /W3 /utf-8)
    # Disable specific warnings for intentional code patterns
    target_compile_definitions(cs2-dumper PRIVATE
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )
endif()

# MinGW / GCC settings
if(MINGW)
    target_compile_options(cs2-dumper PRIVATE -Wall -Wextra)
    target_link_libraries(cs2-dumper PRIVATE psapi)
endif()
