#pragma once

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
        #define NOMINMAX
    #endif
    #include <Windows.h>

    #include <vector>
#endif

#include "exception_registry.hpp"

#include <cstdint>
#include <span>

namespace os::vmem {

enum class Access { None, Read, Write, ReadWrite };

struct View {
    void *const ptr = nullptr;
    size_t size = 0;
};

// A chunk of allocated memory to be mapped to a AddressSpace area.
// The chunk can be mapped multiple times in different locations, such as when mirroring RAM or ROM.
class MemoryBlock {
public:
    MemoryBlock(size_t size, Access access = Access::ReadWrite);
    ~MemoryBlock();

    void *Ptr() const {
        return m_ptr;
    }

    size_t Size() const {
        return m_size;
    }

    std::span<uint8_t> Data() const {
        return std::span<uint8_t>{static_cast<uint8_t *>(m_ptr), m_size};
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
    void *m_ptr = nullptr;
    const size_t m_size;
    const Access m_access;
#ifdef _WIN32
    HANDLE m_hSection = nullptr;
#endif
};

// A chunk of virtual memory onto which MemoryBlock instances can be mapped.
class AddressSpace {
public:
    AddressSpace(size_t size);
    ~AddressSpace();

    void *Ptr() const {
        return m_mem;
    }
    size_t Size() const {
        return m_size;
    }

    View Map(const MemoryBlock &mem, size_t baseAddress);
    View Map(const MemoryBlock &mem, size_t baseAddress, size_t offset, size_t size);
    bool Unmap(View view);

    void AddUnmappedAccessHandlers(size_t startAddress, size_t endAddress, void *context,
                                   os::excpt::ReadHandlerFn readFn, os::excpt::WriteHandlerFn writeFn);
    void RemoveUnmappedAccessHandlers(size_t startAddress, size_t endAddress);

private:
#ifdef _WIN32
    void *m_mem = nullptr;
    size_t m_size = 0;
    size_t m_pageMask = 0;

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

// A contiguous chunk of virtual memory that can have individual pages committed or decommitted on demand.
class VirtualMemory {
public:
    VirtualMemory(size_t size);
    ~VirtualMemory();

    // Retrieves the size of this virtual memory block.
    size_t Size() const {
        return m_size;
    }

    // Retrieves the page size.
    size_t PageSize() const {
        return m_pageSize;
    }

    // Returns a pointer to the virtual memory block.
    void *Ptr() const {
        return m_mem;
    }

    // Commits all pages that comprise the specified region.
    // offset and length must be page-aligned.
    // Returns a pointer to the committed memory region.
    void *Commit(size_t offset, size_t length, Access access);

    // Decommits all pages that comprise the specified region
    // offset and length must be page-aligned.
    // Returns true if the region was decommitted.
    bool Decommit(size_t offset, size_t length);

    // Determines if the page at the specified offset is committed.
    // offset does not need to be page-aligned. Instead, the function determines if the page that contains the address
    // is committed.
    bool IsCommitted(size_t offset);

private:
    void *m_mem = nullptr;
    size_t m_size = 0;
    size_t m_pageSize = 0;
    size_t m_pageMask = 0;
};

} // namespace os::vmem
