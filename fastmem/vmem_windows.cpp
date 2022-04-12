#include "vmem.hpp"

#include "win32_apis.hpp"

#include <algorithm>

namespace vmem {

constexpr static DWORD ProtectFlags(Access access) {
    switch (access) {
    case Access::None: return PAGE_NOACCESS;
    case Access::Read: return PAGE_READONLY;
    case Access::Write: return PAGE_READWRITE;
    case Access::ReadWrite: return PAGE_READWRITE;
    default: return PAGE_NOACCESS; // TODO: assert / unreachable
    }
}

BackedMemory::BackedMemory(size_t size, Access access)
    : m_size(size)
    , m_access(access) {
    m_hSection = CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, ProtectFlags(access), (DWORD)(size >> 32),
                                   (DWORD)(size & 0xffffffff), nullptr);
    if (m_hSection == nullptr) {
        // TODO: error: could not allocate pagefile-backed memory section
        return;
    }
}

BackedMemory::~BackedMemory() {
    if (m_hSection != nullptr) {
        CloseHandle(m_hSection);
    }
}

VirtualMemory::VirtualMemory(size_t size) {
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

    m_regions.push_back({m_mem, size, false});
}

VirtualMemory::~VirtualMemory() {
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

View VirtualMemory::Map(const BackedMemory &mem, size_t baseAddress) {
    // Sanity check: ensure virtual memory was allocated successfully
    if (m_mem == nullptr) {
        // TODO: error: virtual memory not allocated
        return {};
    }

    auto size = mem.Size();
    auto *region = SplitRegion(static_cast<char *>(m_mem) + baseAddress, size);
    if (region == nullptr) {
        // TODO: error: cannot split region
        return {};
    }

    void *ptr = win32::MapViewOfFile3(mem.Section(), nullptr, region->ptr, 0, size, MEM_REPLACE_PLACEHOLDER,
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

bool VirtualMemory::Unmap(View view) {
    // Sanity check: ensure virtual memory was allocated successfully
    if (m_mem == nullptr) {
        // TODO: error: virtual memory not allocated
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

VirtualMemory::Region *VirtualMemory::SplitRegion(void *ptr, size_t size) {
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

bool VirtualMemory::MergeRegion(void *ptr, size_t size) {
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

} // namespace vmem
