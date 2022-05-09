#include "vmem.hpp"

#include <algorithm>

#include "win32_apis.hpp"

namespace os::vmem {

constexpr static DWORD ProtectFlags(Access access) {
    switch (access) {
    case Access::None: return PAGE_NOACCESS;
    case Access::Read: return PAGE_READONLY;
    case Access::Write: return PAGE_READWRITE;
    case Access::ReadWrite: return PAGE_READWRITE;
    default: return PAGE_NOACCESS; // TODO: assert / unreachable
    }
}

MemoryBlock::MemoryBlock(size_t size, Access access)
    : m_size(size)
    , m_access(access) {
    m_hSection = CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, ProtectFlags(access), (DWORD)(size >> 32),
                                   (DWORD)(size & 0xffffffff), nullptr);
    if (m_hSection == nullptr) {
        // TODO: error: could not allocate pagefile-backed memory section
        return;
    }
    m_ptr = MapViewOfFile(m_hSection, FILE_MAP_ALL_ACCESS, 0, 0, size);
}

MemoryBlock::~MemoryBlock() {
    if (m_ptr != nullptr) {
        UnmapViewOfFile(m_ptr);
    }
    if (m_hSection != nullptr) {
        CloseHandle(m_hSection);
    }
}

AddressSpace::AddressSpace(size_t size) {
    if (win32::VirtualAlloc2 == nullptr || win32::MapViewOfFile3 == nullptr || win32::UnmapViewOfFileEx == nullptr) {
        // TODO: error: missing API
        // TODO: implement fallback
        return;
    }

    m_mem =
        win32::VirtualAlloc2(nullptr, nullptr, size, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS, nullptr, 0);
    if (m_mem == nullptr) {
        // TODO: error: could not allocate virtual memory
        return;
    }
    m_size = size;

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    m_pageMask = sysInfo.dwPageSize - 1;

    m_regions.push_back({m_mem, size, false});
}

AddressSpace::~AddressSpace() {
    if (m_mem != nullptr) {
        // Unmap mapped regions
        bool anyMapped = false;
        for (auto &region : m_regions) {
            if (region.mapped) {
                if (!win32::UnmapViewOfFileEx(region.ptr, MEM_PRESERVE_PLACEHOLDER)) {
                    // TODO: error: could not unmap region
                }
                anyMapped = true;
            }
        }

        // Coalesce entire region
        if (anyMapped) {
            if (!VirtualFree(m_mem, m_size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS)) {
                // TODO: error: failed to coalesce placeholders
            }
        }

        if (!VirtualFree(m_mem, 0, MEM_RELEASE)) {
            // TODO: error: could not free virtual memory
        }
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

    auto *region = SplitRegion(static_cast<char *>(m_mem) + baseAddress, size);
    if (region == nullptr) {
        // TODO: error: cannot split region
        return {};
    }

    void *ptr = win32::MapViewOfFile3(mem.Section(), nullptr, region->ptr, offset, size, MEM_REPLACE_PLACEHOLDER,
                                      ProtectFlags(mem.AccessFlags()), nullptr, 0);
    if (ptr == nullptr) {
        // Undo split
        MergeRegion(static_cast<char *>(m_mem) + baseAddress, size);

        // TODO: error: could not map view
        return {};
    }

    region->mapped = true;
    MEMORY_BASIC_INFORMATION info;
    if (VirtualQuery(ptr, &info, sizeof(info))) {
        size = info.RegionSize;
    }
    return {ptr, size};
}

bool AddressSpace::Unmap(View view) {
    // Sanity check: ensure virtual memory was allocated successfully
    if (m_mem == nullptr) {
        // TODO: error: virtual memory not allocated
        return false;
    }

    // Sanity check: ensure view actually belongs to this address space
    if (view.ptr < m_mem || static_cast<uint8_t *>(view.ptr) + view.size > static_cast<uint8_t *>(m_mem) + m_size) {
        // TODO: error: view out of range
        return false;
    }

    if (!win32::UnmapViewOfFileEx(view.ptr, MEM_PRESERVE_PLACEHOLDER)) {
        // TODO: error: could not unmap view
        return false;
    }

    if (!MergeRegion(view.ptr, view.size)) {
        // TODO: error: failed to merge regions
        return false;
    }

    return true;
}

AddressSpace::Region *AddressSpace::SplitRegion(void *ptr, size_t size) {
    // Find region that contains the requested split
    auto cur = std::upper_bound(m_regions.begin(), m_regions.end(), ptr,
                                [](void *ptr, const Region &rhs) { return ptr < rhs.ptr; });
    if (cur == m_regions.begin()) {
        // TODO: error: ptr is outside our allocated region
        return nullptr;
    }
    --cur;

    // Check that the region is not mapped
    if (cur->mapped) {
        // TODO: error: region is already mapped
        return nullptr;
    }

    // Check if the requested split fits in the region
    if (size > cur->size) {
        // TODO: error: not enough space to map region
        return nullptr;
    }

    // Region to be mapped exactly matches the unallocated region
    if (ptr == cur->ptr && size == cur->size) {
        return &*cur;
    }

    // Split the region
    if (!VirtualFree(ptr, size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)) {
        // TODO: error: could not split memory region
        return nullptr;
    }

    auto index = cur - m_regions.begin();

    // Region to be mapped sits at the start of the unallocated region -> split into two parts
    // Current region is resized to the requested size
    // A new region is added above it with the remaining size
    // | current          |
    // | ptr   size |
    // --------------------
    // | current    | new |
    if (ptr == cur->ptr) {
        auto newSize = cur->size - size;
        cur->size = size;
        m_regions.insert(cur + 1, Region{.ptr = static_cast<char *>(cur->ptr) + size, .size = newSize});
        return &m_regions[index];
    }

    // Region to be mapped sits at the end of the unallocated region -> split into two parts
    // A new region is added below it with the requested size
    // Current region is resized to the remaining size
    // | current          |
    //       | ptr   size |
    // --------------------
    // | cur | new        |
    if (static_cast<char *>(ptr) + size == static_cast<char *>(cur->ptr) + cur->size) {
        cur->size -= size;
        return &*m_regions.insert(cur + 1, Region{.ptr = ptr, .size = size});
    }

    // Region to be mapped sits in the middle of the unallocated region -> split into three parts
    // Shrink current region to the space just before the pointer
    // Add two new regions: one for the requested region, one for the remainder
    // | current                 |
    //       | ptr   size |
    // ---------------------------
    // | cur | new        | new  |
    auto curSize = cur->size;
    cur->size = static_cast<char *>(ptr) - static_cast<char *>(cur->ptr);
    m_regions.insert(cur + 1, Region{.ptr = static_cast<char *>(ptr) + size, .size = curSize - size - cur->size});
    return &*m_regions.insert(m_regions.begin() + index + 1, Region{.ptr = ptr, .size = size});
}

void AddressSpace::AddUnmappedAccessHandlers(size_t startAddress, size_t endAddress, void *context,
                                             os::excpt::ReadHandlerFn readFn, os::excpt::WriteHandlerFn writeFn) {
    if (startAddress > m_size || endAddress > m_size) {
        return;
    }
    os::excpt::MemoryAccessExceptionHandlerRegistry::Register(reinterpret_cast<uintptr_t>(m_mem), startAddress,
                                                              endAddress, context, readFn, writeFn);
}

void AddressSpace::RemoveUnmappedAccessHandlers(size_t startAddress, size_t endAddress) {
    if (startAddress > m_size || endAddress > m_size) {
        return;
    }
    os::excpt::MemoryAccessExceptionHandlerRegistry::Unregister(reinterpret_cast<uintptr_t>(m_mem), startAddress,
                                                                endAddress);
}

bool AddressSpace::MergeRegion(void *ptr, size_t size) {
    // Find region that contains the region to be merged.
    // This should match exactly one of the existing regions.
    auto cur = std::lower_bound(m_regions.begin(), m_regions.end(), ptr,
                                [](const Region &lhs, void *ptr) { return lhs.ptr < ptr; });
    if (cur == m_regions.end() || cur->ptr != ptr || cur->size != size) {
        // TODO: error: invalid region
        return false;
    }
    cur->mapped = false;

    // Check potential regions to be merged above and below the current region
    const bool canMergeLower = cur != m_regions.begin() && !std::prev(cur)->mapped;
    const bool canMergeUpper = std::next(cur) != m_regions.end() && !std::next(cur)->mapped;
    if (canMergeLower && canMergeUpper) {
        // Merge three regions into one
        // | lower | cur | upper |
        // -----------------------
        // | lower               |
        auto lower = std::prev(cur);
        auto upper = std::next(cur);
        lower->size += cur->size + upper->size;
        if (!VirtualFree(lower->ptr, lower->size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS)) {
            // TODO: error: failed to coalesce placeholders while merging regions
            return false;
        }
        m_regions.erase(cur, std::next(upper));
    } else if (canMergeLower) {
        // Merge two regions into one
        // | lower | cur |
        // ---------------
        // | lower       |
        auto lower = std::prev(cur);
        lower->size += cur->size;
        if (!VirtualFree(lower->ptr, lower->size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS)) {
            // TODO: error: failed to coalesce placeholders while merging regions
            return false;
        }
        m_regions.erase(cur);
    } else if (canMergeUpper) {
        // Merge two regions into one
        // | cur | upper |
        // ---------------
        // | current     |
        auto upper = std::next(cur);
        cur->size += upper->size;
        if (!VirtualFree(cur->ptr, cur->size, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS)) {
            // TODO: error: failed to coalesce placeholders while merging regions
            return false;
        }
        m_regions.erase(upper);
    }

    return true;
}

VirtualMemory::VirtualMemory(size_t size) {
    m_mem = VirtualAlloc(nullptr, size, MEM_RESERVE, PAGE_NOACCESS);
    if (m_mem == nullptr) {
        // TODO: error: could not allocate virtual memory
        return;
    }
    m_size = size;

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    m_pageSize = sysInfo.dwPageSize;
    m_pageMask = sysInfo.dwPageSize - 1;
}

VirtualMemory::~VirtualMemory() {
    VirtualFree(m_mem, 0, MEM_RELEASE);
}

void *VirtualMemory::Commit(size_t offset, size_t length, Access access) {
    // Require offset and length to be page-aligned
    if ((offset & m_pageMask) || (length & m_pageMask)) {
        // TODO: error: offset/length is not page-aligned
        return nullptr;
    }

    return VirtualAlloc(&reinterpret_cast<char *>(m_mem)[offset], length, MEM_COMMIT, ProtectFlags(access));
}

bool VirtualMemory::Decommit(size_t offset, size_t length) {
    // Require offset and length to be page-aligned
    if ((offset & m_pageMask) || (length & m_pageMask)) {
        // TODO: error: offset/length is not page-aligned
        return false;
    }

    return VirtualFree(&reinterpret_cast<char *>(m_mem)[offset], length, MEM_DECOMMIT);
}

bool VirtualMemory::IsCommitted(size_t offset) {
    MEMORY_BASIC_INFORMATION info;
    if (VirtualQuery(&reinterpret_cast<char *>(m_mem)[offset], &info, sizeof(info)) == 0) {
        return false;
    }
    return info.State == MEM_COMMIT;
}

} // namespace os::vmem
