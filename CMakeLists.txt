cmake_minimum_required(VERSION 3.10)

project(fastmem)

add_executable(fastmem
    fastmem/exception_registry.hpp
    fastmem/noitree.hpp
    fastmem/vmem.hpp
    fastmem/main.cpp
)

target_compile_features(fastmem PUBLIC cxx_std_20)

if (WIN32)
    target_sources(fastmem PRIVATE
        fastmem/win32_apis.hpp
        fastmem/exception_registry_windows.cpp
        fastmem/vmem_windows.cpp
    )
elseif (UNIX)
endif ()
