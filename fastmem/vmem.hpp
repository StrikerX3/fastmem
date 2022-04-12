#pragma once

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
    #include <Windows.h>

    #include <vector>
#endif

#include "exception_registry.hpp"

#include <cstdint>

namespace os::vmem {

enum class Access { None, Read, Write, ReadWrite };

struct View {
    void *const ptr = nullptr;
    size_t size = 0;
};

// A chunk of allocated memory to be mapped to a VirtualMemory area.
// The chunk can be mapped multiple times in different locations, such as when mirroring RAM or ROM.
class BackedMemory {
public:
    BackedMemory(size_t size, Access access);
    ~BackedMemory();

    size_t Size() const {
        return m_size;
    }

    Access AccessFlags() const {
        return m_access;
    }

#ifdef _WIN32
    HANDLE Section() const {
        return m_hSection;
    }
#endif

private:
    const size_t m_size;
    const Access m_access;
#ifdef _WIN32
    HANDLE m_hSection = nullptr;
#endif
};

// A chunk of virtual memory onto which BackedMemory instances can be mapped.
class VirtualMemory {
public:
    VirtualMemory(size_t size);
    ~VirtualMemory();

    void *Ptr() const {
        return m_mem;
    }
    size_t Size() const {
        return m_size;
    }

    View Map(const BackedMemory &mem, size_t baseAddress);
    bool Unmap(View view);

    void AddUnmappedAccessHandlers(size_t startAddress, size_t endAddress, void *context,
                                   os::excpt::ReadHandlerFn readFn, os::excpt::WriteHandlerFn writeFn);
    void RemoveUnmappedAccessHandlers(size_t startAddress, size_t endAddress);

private:
#ifdef _WIN32
    void *m_mem = nullptr;
    size_t m_size = 0;

    struct Region {
        void *ptr = nullptr;
        size_t size = 0;
        bool mapped = false;
    };
    std::vector<Region> m_regions;

    Region *SplitRegion(void *ptr, size_t size);
    bool MergeRegion(void *ptr, size_t size);
#endif
};

} // namespace os::vmem
