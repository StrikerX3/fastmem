#include "vmem.hpp"

#include "noitree.hpp"

#include <array>
#include <bit>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>

template <typename IndexType, size_t indexBits>
class DynamicBitset {
public:
    DynamicBitset() {
        os::excpt::MemoryAccessExceptionHandlerRegistry::Register(
            (uintptr_t)m_vmem.Ptr(), 0, m_vmem.Size(), this,
            [](void *context, uintptr_t address, size_t size, void *value) {
                auto &bitset = *static_cast<DynamicBitset *>(context);
                bitset.HandleRead(address, size, value);
            },
            [](void *context, uintptr_t address, size_t size, const void *value) {
                auto &bitset = *static_cast<DynamicBitset *>(context);
                bitset.HandleWrite(address, size, value);
            });
    }

    void Reset() {
        m_vmem.Decommit(0, m_vmem.Size());
    }

    void Set(IndexType index) {
        const auto entryOffset = EntryOffset(index);
        const auto bitOffset = BitOffset(index);
        m_entries[entryOffset] |= Bit(bitOffset);
    }

    void Clear(IndexType index) {
        const auto entryOffset = EntryOffset(index);
        const auto bitOffset = BitOffset(index);
        m_entries[entryOffset] &= ~Bit(bitOffset);
    }

    void SetValue(IndexType index, bool value) {
        const auto entryOffset = EntryOffset(index);
        const auto bitOffset = BitOffset(index);
        if (value) {
            m_entries[entryOffset] |= Bit(bitOffset);
        } else {
            m_entries[entryOffset] &= ~Bit(bitOffset);
        }
    }

    bool Flip(IndexType index) {
        const auto entryOffset = EntryOffset(index);
        const auto bitOffset = BitOffset(index);
        m_entries[entryOffset] ^= Bit(bitOffset);
        return m_entries[entryOffset] & Bit(bitOffset);
    }

    bool Test(IndexType index) const {
        const auto entryOffset = EntryOffset(index);
        const auto bitOffset = BitOffset(index);
        return m_entries[entryOffset] & Bit(bitOffset);
    }

    /*std::optional<IndexType> LowerBound(IndexType startIndex) const {
        // TODO: skip uncommitted pages
        const auto startEntryOffset = EntryOffset(startIndex);
        const auto startBitOffset = BitOffset(startIndex);
        for (size_t entryOffset = startEntryOffset; entryOffset < kNumEntries; entryOffset++) {
            size_t baseBit = 0;
            auto val = m_entries[entryOffset];
            while (val != 0) {
                auto firstBit = std::countr_zero(val);
                if (baseBit + firstBit >= startBitOffset) {
                    return baseBit + firstBit + entryOffset * kEntryBits;
                }
                baseBit += firstBit + 1;
                val >>= firstBit + 1;
            }
        }
        return std::nullopt;
    }*/

private:
    using EntryType = uint64_t;
    static constexpr size_t kEntryBits = 8 * sizeof(EntryType);
    static constexpr EntryType kBit = static_cast<EntryType>(1);
    static constexpr size_t kNumEntries = (kBit << indexBits) / sizeof(EntryType);

    os::vmem::VirtualMemory m_vmem{kNumEntries};
    EntryType *m_entries = static_cast<EntryType *>(m_vmem.Ptr());

    size_t EntryOffset(IndexType index) const {
        return (index / kEntryBits);
    }

    size_t BitOffset(IndexType index) const {
        return index % kEntryBits;
    }

    EntryType Bit(size_t bitOffset) const {
        return kBit << bitOffset;
    }

    void HandleRead(uintptr_t address, size_t size, void *value) {
        m_vmem.Commit(address, size, os::vmem::Access::ReadWrite);
        std::fill_n((char *)value, size, 0);
    }

    void HandleWrite(uintptr_t address, size_t size, const void *value) {
        if (m_vmem.Commit(address, size, os::vmem::Access::ReadWrite)) {
            std::copy_n((const char *)value, size, (char *)m_vmem.Ptr() + address);
        }
    }
};

void testDynamicBitset() {
    DynamicBitset<uint32_t, 32> set;
    auto b = [](bool value) { return value ? '+' : '-'; };
    set.Set(0);
    set.Clear(0x1003);
    set.Flip(0x10000C);
    printf("%c%c%c%c\n", b(set.Test(0)), b(set.Test(0x1003)), b(set.Test(0x10000C)), b(set.Test(0x10000018)));
}

void testVirtualMemory() {
    os::vmem::VirtualMemory mem{0x3000};
    printf("Virtual memory allocated: %zu bytes at %p\n", mem.Size(), mem.Ptr());
    os::excpt::MemoryAccessExceptionHandlerRegistry::Register(
        (uintptr_t)mem.Ptr(), 0, mem.Size(), nullptr,
        [](void *context, uintptr_t address, size_t size, void *value) {
            printf("Attempted to read %zu bytes from 0x%p\n", size, (void *)address);
        },
        [](void *context, uintptr_t address, size_t size, const void *value) {
            printf("Attempted to write %zu bytes to 0x%p\n", size, (void *)address);
        });
    // | 0x0000 | 0x1000 | 0x2000 |
    // | xxxxxx | xxxxxx | xxxxxx |

    auto *u8Ptr = reinterpret_cast<volatile char *>(mem.Ptr());
    u8Ptr[0] = 1; // SIGSEGV / access violation

    auto commit = [&](size_t address, size_t size, os::vmem::Access access) {
        void *ptr = mem.Commit(address, size, access);
        printf("Committed 0x%zx..0x%zx: %p\n", address, address + size - 1, ptr);
    };

    auto testWrite = [&](size_t address, uint8_t value) {
        u8Ptr[address] = value;
        printf("Wrote value at 0x%zx: %" PRIu8 "\n", address, u8Ptr[address]);
    };

    auto printValue = [&](size_t address) { printf("Value at 0x%zx: %" PRIu8 "\n", address, u8Ptr[address]); };

    commit(0x0000, 0x1000, os::vmem::Access::ReadWrite);
    testWrite(0x0000, 1);
    testWrite(0x0FFF, 2);
    // | 0x0000 | 0x1000 | 0x2000 |
    // | 1    2 | xxxxxx | xxxxxx |

    commit(0x1000, 0x2000, os::vmem::Access::ReadWrite);
    testWrite(0x1000, 3);
    testWrite(0x1FFF, 4);
    testWrite(0x2000, 5);
    testWrite(0x2FFF, 6);
    // | 0x0000 | 0x1000 | 0x2000 |
    // | 1    2 | 3    4 | 5    6 |

    commit(0x2000, 0x2000, os::vmem::Access::ReadWrite); // should fail
    // | 0x0000 | 0x1000 | 0x2000 |
    // | 1    2 | 3    4 | 5    6 |

    if (mem.Decommit(0x0000, 0x2000)) {
        printf("Decommitted 0x0000..0x1FFF\n");
    }
    // | 0x0000 | 0x1000 | 0x2000 |
    // | xxxxxx | xxxxxx | 5    6 |

    printf("0x0000 committed? %s\n", mem.IsCommitted(0x0000) ? "yes" : "no"); // no
    printf("0x1000 committed? %s\n", mem.IsCommitted(0x1000) ? "yes" : "no"); // no
    printf("0x2000 committed? %s\n", mem.IsCommitted(0x2000) ? "yes" : "no"); // yes

    commit(0x1000, 0x2000, os::vmem::Access::ReadWrite);
    printValue(0x1000); // should be zero
    printValue(0x1FFF); // should be zero
    // | 0x0000 | 0x1000 | 0x2000 |
    // | xxxxxx |        | 5    6 |
    testWrite(0x1000, 7);
    testWrite(0x1FFF, 8);
    // | 0x0000 | 0x1000 | 0x2000 |
    // | xxxxxx | 7    8 | 5    6 |

    printf("0x0000 committed? %s\n", mem.IsCommitted(0x0000) ? "yes" : "no"); // no
    printf("0x1000 committed? %s\n", mem.IsCommitted(0x1000) ? "yes" : "no"); // yes
    printf("0x2000 committed? %s\n", mem.IsCommitted(0x2000) ? "yes" : "no"); // yes
}

void testAddressSpace() {
    constexpr size_t memSize = 0x1000;
    os::vmem::AddressSpace mem{memSize * 3};
    printf("Virtual memory allocated: %zu bytes at %p\n", mem.Size(), mem.Ptr());

    // TODO: make a more realistic demo
    // - two os::vmem::AddressSpace instances (read, write)
    // - os::vmem::MemoryBlock instances for:
    //   - zero page (for open bus reads)
    //   - discard page (for writes to read-only areas)
    //   - RAM
    //   - ROM
    // - mappings:
    //   region     base     read   write
    //   ROM        0x0000   ROM    discard
    //   RAM        0x1000   RAM    RAM
    //   MMIO       0x2000   -      -
    //   open bus   0x3000   zero   discard
    // TODO: implement exception handling system for MMIO and other special cases
    // TODO: efficient mirroring
    // TODO: fast map/unmap on Windows (for NDS VRAM and TCM)

    auto u8mem = reinterpret_cast<uint8_t *>(mem.Ptr());

    os::vmem::MemoryBlock ram{0x2000, os::vmem::Access::ReadWrite};
    printf("RAM allocated: %zu bytes\n", ram.Size());

    auto view1 = mem.Map(ram, 0x0000, 0x1000, 0x1000);
    if (view1.ptr) {
        printf("RAM mapped to 0x0000 -> %p\n", view1.ptr);
    }

    auto view2 = mem.Map(ram, 0x1000, 0x1000, 0x1000);
    if (view2.ptr) {
        printf("RAM mirror mapped to 0x1000 -> %p\n", view2.ptr);
    }

    volatile uint8_t *mmio = &u8mem[0x2000];
    printf("MMIO at 0x2000 -> %p\n", mmio);

    mem.AddUnmappedAccessHandlers(
        0x2000, 0x2FFF, nullptr,
        [](void *context, uintptr_t address, size_t size, void *value) {
            printf("Read size=%zu, addr=%zx\n", size, address);
            switch (size) {
            case 1: *reinterpret_cast<uint8_t *>(value) = 0x80; break;
            case 2: *reinterpret_cast<uint16_t *>(value) = 0x8000; break;
            case 4: *reinterpret_cast<uint32_t *>(value) = 0x80000000; break;
            case 8: *reinterpret_cast<uint64_t *>(value) = 0x8000000000000000; break;
            }
        },
        [](void *context, uintptr_t address, size_t size, const void *value) {
            printf("Write size=%zu, addr=%zx, value=", size, address);
            switch (size) {
            case 1: printf("%" PRIu8 "\n", *reinterpret_cast<const uint8_t *>(value)); break;
            case 2: printf("%" PRIu16 "\n", *reinterpret_cast<const uint16_t *>(value)); break;
            case 4: printf("%" PRIu32 "\n", *reinterpret_cast<const uint32_t *>(value)); break;
            case 8: printf("%" PRIu64 "\n", *reinterpret_cast<const uint64_t *>(value)); break;
            }
        });
    printf("Added unmapped access handlers to MMIO region\n");

    auto *u8buf = static_cast<uint8_t *>(mem.Ptr());
    auto *u8view1 = static_cast<uint8_t *>(view1.ptr);
    auto *u8view2 = static_cast<uint8_t *>(view2.ptr);

    auto printMem = [&] {
        auto *ramPtr = static_cast<uint8_t *>(ram.Ptr());
        printf("  Address space - main    %02X %02X %02X %02X\n", u8buf[0], u8buf[1], u8buf[2], u8buf[3]);
        printf("  Address space - mirror  %02X %02X %02X %02X\n", u8buf[memSize + 0], u8buf[memSize + 1],
               u8buf[memSize + 2], u8buf[memSize + 3]);
        printf("  Mapped view - main      %02X %02X %02X %02X\n", u8view1[0], u8view1[1], u8view1[2], u8view1[3]);
        printf("  Mapped view - mirror    %02X %02X %02X %02X\n", u8view2[0], u8view2[1], u8view2[2], u8view2[3]);
        printf("  RAM block               %02X %02X %02X %02X\n", ramPtr[0x1000], ramPtr[0x1001], ramPtr[0x1002],
               ramPtr[0x1003]);
    };

    std::fill_n(u8buf, memSize, (uint8_t)0);
    u8buf[0] = 15;
    u8buf[1] = 33;
    u8buf[2] = 64;
    printf("Memory contents after direct manipulation to main region:\n");
    printMem();
    printf("\n");
    u8buf[memSize + 0] = 22;
    u8buf[memSize + 1] = 41;
    u8buf[memSize + 2] = 78;
    printf("Memory contents after direct manipulation to mirror region:\n");
    printMem();
    printf("\n");
    u8view1[1] = 73;
    u8view1[2] = 41;
    u8view1[3] = 1;
    printf("Memory contents after manipulation through main view:\n");
    printMem();
    printf("\n");
    u8view2[0] = 99;
    u8view2[1] = 88;
    u8view2[3] = 77;
    printf("Memory contents after manipulation through mirror view:\n");
    printMem();

    // Try accessing MMIO
    printf("\nMMIO tests:\n");
    uint8_t u8val = 1;
    uint16_t u16val = 1;
    uint32_t u32val = 1;
    uint64_t u64val = 1;
    int8_t s8val = -1;
    int16_t s16val = -1;
    int32_t s32val = -1;
    int64_t s64val = -1;
    mmio[0] = 21;
    *reinterpret_cast<volatile uint16_t *>(&mmio[2]) = 4321;
    *reinterpret_cast<volatile uint32_t *>(&mmio[4]) = 87654321;
    *reinterpret_cast<volatile uint64_t *>(&mmio[6]) = 54321;
    *reinterpret_cast<volatile uint64_t *>(&mmio[8]) = 6543210987654321;
    *reinterpret_cast<volatile uint64_t *>(&mmio[10]) = u8val;
    *reinterpret_cast<volatile uint64_t *>(&mmio[10]) = u16val;
    *reinterpret_cast<volatile uint64_t *>(&mmio[10]) = u32val;
    *reinterpret_cast<volatile uint64_t *>(&mmio[10]) = u64val;
    *reinterpret_cast<volatile int64_t *>(&mmio[10]) = s8val;
    *reinterpret_cast<volatile int64_t *>(&mmio[10]) = s16val;
    *reinterpret_cast<volatile int64_t *>(&mmio[10]) = s32val;
    *reinterpret_cast<volatile int64_t *>(&mmio[10]) = s64val;
    uint8_t mmioVal8 = mmio[1];
    uint16_t mmioVal16 = *reinterpret_cast<volatile uint16_t *>(&mmio[3]);
    uint32_t mmioVal32 = *reinterpret_cast<volatile uint32_t *>(&mmio[5]);
    uint64_t mmioVal64 = *reinterpret_cast<volatile uint64_t *>(&mmio[7]);
    uint64_t mmioVal8zx = mmio[1];
    uint64_t mmioVal16zx = *reinterpret_cast<volatile uint16_t *>(&mmio[3]);
    uint64_t mmioVal32zx = *reinterpret_cast<volatile uint32_t *>(&mmio[5]);
    uint64_t mmioVal64zx = *reinterpret_cast<volatile uint64_t *>(&mmio[7]);
    int64_t mmioVal8sx = *reinterpret_cast<volatile int8_t *>(&mmio[1]);
    int64_t mmioVal16sx = *reinterpret_cast<volatile int16_t *>(&mmio[3]);
    int64_t mmioVal32sx = *reinterpret_cast<volatile int32_t *>(&mmio[5]);
    int64_t mmioVal64sx = *reinterpret_cast<volatile int64_t *>(&mmio[7]);
    printf("MMIO reads:\n");
    printf("  %" PRIu8 " %" PRIu16 " %" PRIu32 " %" PRIu64 "\n", mmioVal8, mmioVal16, mmioVal32, mmioVal64);
    printf("  %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n", mmioVal8zx, mmioVal16zx, mmioVal32zx, mmioVal64zx);
    printf("  %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64 "\n", mmioVal8sx, mmioVal16sx, mmioVal32sx, mmioVal64sx);
    // Expected outputs:
    //   128 32768 2147483648 9223372036854775808
    //   128 32768 2147483648 9223372036854775808
    //   -128 -32768 -2147483648 -9223372036854775808

    if (mem.Unmap(view1)) {
        printf("RAM unmapped from 0x0000\n");
    }
    if (mem.Unmap(view2)) {
        printf("RAM unmapped from 0x1000\n");
    }
}

int main() {
    testDynamicBitset();
    printf("---------------------------------------\n");
    testVirtualMemory();
    printf("---------------------------------------\n");
    testAddressSpace();

    return EXIT_SUCCESS;
}
