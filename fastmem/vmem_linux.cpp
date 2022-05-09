#include "vmem.hpp"

#include <algorithm>
#include <bit>

#include <sys/mman.h>
#include <unistd.h>

namespace os::vmem {

constexpr static int ProtectFlags(Access access) {
    switch (access) {
    case Access::None: return PROT_NONE;
    case Access::Read: return PROT_READ;
    case Access::Write: return PROT_WRITE;
    case Access::ReadWrite: return PROT_READ | PROT_WRITE;
    default: return PROT_NONE; // TODO: assert / unreachable
    }
}

MemoryBlock::MemoryBlock(size_t size, Access access)
    : m_size(size)
    , m_access(access) {
    m_fd = memfd_create("vmem", 0);
    if (m_fd == -1) {
        // TODO: error: failed to create file descriptor
        return;
    }
    if (ftruncate(m_fd, size) != 0) {
        // TODO: error: failed to allocate memory for file descriptor
        m_fd = -1;
        return;
    }
    m_ptr = mmap(nullptr, size, ProtectFlags(access), MAP_SHARED, m_fd, 0);
    if (m_ptr == nullptr) {
        // TODO: error: failed to map file descriptor memory
        close(m_fd);
        m_fd = -1;
    }
}

MemoryBlock::~MemoryBlock() {
    if (m_ptr != nullptr) {
        munmap(m_ptr, m_size);
    }
    if (m_fd != -1) {
        close(m_fd);
    }
}

AddressSpace::AddressSpace(size_t size) {
    m_mem = mmap(nullptr, size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (m_mem == nullptr) {
        // TODO: error: could not allocate virtual memory
        return;
    }
    m_size = size;
    m_pageMask = sysconf(_SC_PAGESIZE) - 1;
}

AddressSpace::~AddressSpace() {
    if (m_mem != nullptr) {
        munmap(m_mem, m_size);
    }
}

View AddressSpace::Map(const MemoryBlock &mem, size_t baseAddress, size_t offset, size_t size) {
    // Sanity check: ensure virtual memory was allocated successfully
    if (m_mem == nullptr) {
        // TODO: error: virtual memory not allocated
        return {};
    }

    // Adjust offset to the previous multiple of the page size
    offset &= ~m_pageMask;

    // Limit size to the MemoryBlock size
    size = std::min(size, mem.Size() - offset);

    // Adjust size to the next multiple of the page size
    size = (size + m_pageMask) & ~m_pageMask;

    void *ptr = &reinterpret_cast<char *>(m_mem)[baseAddress];
    ptr = mmap(ptr, size, ProtectFlags(mem.AccessFlags()), MAP_SHARED | MAP_FIXED, mem.FileDescriptor(), offset);
    if (ptr == nullptr) {
        // TODO: error: could not map view
        return {};
    }
    return {ptr, size};
}

bool AddressSpace::Unmap(View view) {
    // Sanity check: ensure the view was actually mapped to this address space
    if (view.ptr < m_mem || reinterpret_cast<char *>(view.ptr) + view.size > reinterpret_cast<char *>(m_mem) + m_size) {
        return false;
    }

    return mmap(view.ptr, view.size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != nullptr;
}

VirtualMemory::VirtualMemory(size_t size) {
    m_mem = mmap(nullptr, size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (m_mem == nullptr) {
        // TODO: error: could not allocate virtual memory
        return;
    }
    m_size = size;

    m_pageSize = sysconf(_SC_PAGESIZE);
    m_pageMask = m_pageSize - 1;
    m_pageShift = std::countr_zero(m_pageSize);
    m_allocatedPages.resize(m_size / m_pageSize);
}

VirtualMemory::~VirtualMemory() {
    munmap(m_mem, m_size);
}

void *VirtualMemory::Commit(size_t offset, size_t length, Access access) {
    // Require offset and length to be page-aligned
    if ((offset & m_pageMask) || (length & m_pageMask)) {
        // TODO: error: offset/length is not page-aligned
        return nullptr;
    }

    // Bounds check
    if (offset + length > m_size) {
        // TODO: error: offset + length out of range
        return nullptr;
    }

    void *ptr = &reinterpret_cast<char *>(m_mem)[offset];
    if (mprotect(ptr, length, ProtectFlags(access)) == 0) {
        for (size_t i = 0; i < (length >> m_pageShift); i++) {
            m_allocatedPages[i + (offset >> m_pageShift)] = true;
        }
        return ptr;
    } else {
        return nullptr;
    }
}

bool VirtualMemory::Decommit(size_t offset, size_t length) {
    // Require offset and length to be page-aligned
    if ((offset & m_pageMask) || (length & m_pageMask)) {
        // TODO: error: offset/length is not page-aligned
        return false;
    }

    // Bounds check
    if (offset + length > m_size) {
        // TODO: error: offset + length out of range
        return false;
    }

    void *ptr = &reinterpret_cast<char *>(m_mem)[offset];
    if (mmap(ptr, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0)) {
        for (size_t i = 0; i < (length >> m_pageShift); i++) {
            m_allocatedPages[i + (offset >> m_pageShift)] = false;
        }
        return true;
    } else {
        return false;
    }
}

bool VirtualMemory::IsCommitted(size_t offset) {
    return m_allocatedPages[offset >> m_pageShift];
}

} // namespace os::vmem
