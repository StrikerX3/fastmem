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
    if (mprotect(ptr, length, PROT_NONE) == 0) {
        for (size_t i = 0; i < (length >> m_pageShift); i++) {
            m_allocatedPages[i + (offset >> m_pageShift)] = false;
        }
        madvise(ptr, length, MADV_DONTNEED);
        return true;
    } else {
        return false;
    }
}

bool VirtualMemory::IsCommitted(size_t offset) {
    return m_allocatedPages[offset >> m_pageShift];
}

} // namespace os::vmem
