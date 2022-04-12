#include "win32_dispatch.hpp"

#include "vmem.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

//#pragma comment(lib, "mincore")

uint8_t *mmio = nullptr;
uint8_t mmioOut = 0;

int main() {
    constexpr size_t memSize = 0x1000;
    vmem::VirtualMemory mem{memSize * 3};
    printf("Virtual memory allocated: %zu bytes at %p\n", mem.Size(), mem.Ptr());

    vmem::BackedMemory ram{0x1000, vmem::Access::ReadWrite};
    printf("RAM allocated: %zu bytes\n", ram.Size());

    auto view1 = mem.Map(ram, 0x0000);
    if (view1.ptr) {
        printf("RAM mapped to 0x0000 -> %p\n", view1.ptr);
    }

    auto view2 = mem.Map(ram, 0x1000);
    if (view1.ptr) {
        printf("RAM mirror mapped to 0x1000 -> %p\n", view2.ptr);
    }

    PVOID vecHandler = AddVectoredExceptionHandler(~0, [](_EXCEPTION_POINTERS *ExceptionInfo) -> LONG {
        printf("In vectored exception handler\n");
        if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
            auto type = ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
            if (type == 8) {
                // Data execution prevention; we don't handle those
                return EXCEPTION_CONTINUE_SEARCH;
            }

            // TODO: create global registry of address ranges -> contexts+handlers
            // - O(1) search is mandatory
            // TODO: disassemble opcode at ExceptionInfo->ExceptionRecord->ExceptionAddress
            // - figure out the value written for writes
            // - skip instruction

            auto addr = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
            auto offset = addr - (ULONG_PTR)mmio;
            switch (type) {
            case 0: // Read access violation
                printf("Attempted to read from %llx\n", addr);
                if (offset < memSize) {
                    // TODO: should disassemble instruction here
                    // 8A 40 01    (Debug)
                    // 0F B6 50 01 (Release)
                    printf("  MMIO read from offset %llx\n", offset);
                    ExceptionInfo->ContextRecord->Rax = offset ^ 0xAA;
                    if (*(uint8_t *)ExceptionInfo->ContextRecord->Rip == 0x0F) {
                        ExceptionInfo->ContextRecord->Rip += 4;
                    } else {
                        ExceptionInfo->ContextRecord->Rip += 3;
                    }
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                break;
            case 1: // Write access violation
                printf("Attempted to write to %llx\n", addr);
                if (offset < memSize) {
                    // TODO: should disassemble instruction here
                    // C6 00 05
                    auto excptAddr = (uint8_t *)ExceptionInfo->ExceptionRecord->ExceptionAddress;
                    auto offset = addr - (ULONG_PTR)mmio;
                    auto value = excptAddr[2];
                    printf("  MMIO write to offset %llx = %x\n", offset, value);
                    if (offset == 0) {
                        mmioOut = value;
                    }
                    ExceptionInfo->ContextRecord->Rip += 3;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                break;
            }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    });
    printf("Added vectored exception handler; pointer = %p\n", vecHandler);

    uint8_t *u8buf = static_cast<uint8_t *>(mem.Ptr());
    uint8_t *u8view1 = static_cast<uint8_t *>(view1.ptr);
    uint8_t *u8view2 = static_cast<uint8_t *>(view2.ptr);

    auto printMem = [&] {
        printf("(direct - main)    %02X %02X %02X %02X\n", u8buf[0], u8buf[1], u8buf[2], u8buf[3]);
        printf("(direct - mirror)  %02X %02X %02X %02X\n", u8buf[memSize + 0], u8buf[memSize + 1], u8buf[memSize + 2],
               u8buf[memSize + 3]);
        printf("(view - main)      %02X %02X %02X %02X\n", u8view1[0], u8view1[1], u8view1[2], u8view1[3]);
        printf("(view - mirror)    %02X %02X %02X %02X\n", u8view2[0], u8view2[1], u8view2[2], u8view2[3]);
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
    mmio[0] = 5;
    printf("After MMIO access: %x\n", mmioOut);
    mmioOut = mmio[1];
    printf("MMIO value read: %x\n", mmioOut);

    /*if (mem.Unmap(view1)) {
        printf("RAM unmapped from 0x0000\n");
    }
    if (mem.Unmap(view2)) {
        printf("RAM unmapped from 0x1000\n");
    }*/
}

int main2() {

    HANDLE section = nullptr;
    void *buf = nullptr;
    void *view1 = nullptr;
    void *view2 = nullptr;
    uint8_t *u8buf = nullptr;
    uint8_t *u8view1 = nullptr;
    uint8_t *u8view2 = nullptr;
    PVOID vecHandler = nullptr;
    // PVOID cntHandler = nullptr;
    const std::wstring secName = L"fastmem-test." + std::to_wstring(GetCurrentProcessId());
    constexpr size_t memSize = 0x1000;

    if (win32::VirtualAlloc2 == nullptr || win32::MapViewOfFile3 == nullptr || win32::UnmapViewOfFileEx == nullptr) {
        printf("Failed to load virtual memory management functions\n");
        return EXIT_FAILURE;
    }

    auto printMem = [&] {
        printf("(direct - main)    %02X %02X %02X %02X\n", u8buf[0], u8buf[1], u8buf[2], u8buf[3]);
        printf("(direct - mirror)  %02X %02X %02X %02X\n", u8buf[memSize + 0], u8buf[memSize + 1], u8buf[memSize + 2],
               u8buf[memSize + 3]);
        printf("(view - main)      %02X %02X %02X %02X\n", u8view1[0], u8view1[1], u8view1[2], u8view1[3]);
        printf("(view - mirror)    %02X %02X %02X %02X\n", u8view2[0], u8view2[1], u8view2[2], u8view2[3]);
    };

    SYSTEM_INFO Info;
    GetSystemInfo(&Info);
    // size_t secSize = (memSize + Info.dwAllocationGranularity - 1) & ~(Info.dwAllocationGranularity - 1);
    size_t secSize = memSize;
    printf("Allocation granularity: %lx\n", Info.dwAllocationGranularity);
    printf("Memory block size: %zx\n", memSize);
    printf("Virtual memory size: %zx\n", memSize * 3);
    printf("File mapping section size: %zx\n", secSize);

    // Create pagefile-backed section for the main memory buffer
    section = CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, (DWORD)(secSize >> 32),
                                (DWORD)(secSize & 0xffffffff), secName.c_str());
    if (section == nullptr) {
        printf("init: CreateFileMapping failed, error %#lx\n", GetLastError());
        goto Exit;
    }
    printf("init: Created section %S -> %p\n", secName.c_str(), section);

    // Allocate full memory region
    // 0x0000..0x0FFF   main memory
    // 0x1000..0x1FFF   main memory mirror
    // 0x2000..0x2FFF   memory-mapped I/O
    buf = win32::VirtualAlloc2(nullptr, nullptr, memSize * 3, MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS,
                               nullptr, 0);
    if (buf == nullptr) {
        printf("init: VirtualAlloc2 failed, error %#lx\n", GetLastError());
        goto Exit;
    }
    u8buf = (uint8_t *)buf;
    printf("Allocated virtual memory at %p\n", buf);

    // Release first main memory region, but preseve placeholder
    if (!VirtualFree(buf, memSize, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)) {
        printf("init: VirtualFree for 1st region failed, error %#lx\n", GetLastError());
        goto Exit;
    }

    // Map section into the first region
    view1 =
        win32::MapViewOfFile3(section, nullptr, buf, 0, memSize, MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, nullptr, 0);
    if (view1 == nullptr) {
        printf("init: MapViewOfFile3 for 1st region failed, error %#lx\n", GetLastError());
        goto Exit;
    }
    u8view1 = (uint8_t *)view1;
    printf("Main memory view at %p\n", view1);

    // Release second main memory region, but preseve placeholder
    if (!VirtualFree((void *)((ULONG_PTR)buf + memSize), memSize, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)) {
        printf("init: VirtualFree for 2nd region failed, error %#lx\n", GetLastError());
        goto Exit;
    }

    // Map section into the second region
    view2 = win32::MapViewOfFile3(section, nullptr, (void *)((ULONG_PTR)buf + memSize), 0, memSize,
                                  MEM_REPLACE_PLACEHOLDER, PAGE_READWRITE, nullptr, 0);
    if (view2 == nullptr) {
        printf("init: MapViewOfFile3 for 2nd region failed, error %#lx\n", GetLastError());
        goto Exit;
    }
    u8view2 = (uint8_t *)view2;
    printf("Main memory mirror view at %p\n", view2);

    // Get MMIO region pointer
    mmio = (uint8_t *)((ULONG_PTR)buf + memSize * 2);
    printf("MMIO view at %p\n", mmio);

    printf("Buffers mapped!\n");

    // Setup exception handler
    vecHandler = AddVectoredExceptionHandler(~0, [](_EXCEPTION_POINTERS *ExceptionInfo) -> LONG {
        printf("In vectored exception handler\n");
        if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
            auto type = ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
            if (type == 8) {
                // Data execution prevention; we don't handle those
                return EXCEPTION_CONTINUE_SEARCH;
            }

            // TODO: create global registry of address ranges -> contexts+handlers
            // - O(1) search is mandatory
            // TODO: disassemble opcode at ExceptionInfo->ExceptionRecord->ExceptionAddress
            // - figure out the value written for writes
            // - skip instruction

            auto addr = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
            auto offset = addr - (ULONG_PTR)mmio;
            switch (type) {
            case 0: // Read access violation
                printf("Attempted to read from %llx\n", addr);
                if (offset < memSize) {
                    // TODO: should disassemble instruction here
                    // 8A 40 01    (Debug)
                    // 0F B6 50 01 (Release)
                    printf("  MMIO read from offset %llx\n", offset);
                    ExceptionInfo->ContextRecord->Rax = offset ^ 0xAA;
                    if (*(uint8_t *)ExceptionInfo->ContextRecord->Rip == 0x0F) {
                        ExceptionInfo->ContextRecord->Rip += 4;
                    } else {
                        ExceptionInfo->ContextRecord->Rip += 3;
                    }
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                break;
            case 1: // Write access violation
                printf("Attempted to write to %llx\n", addr);
                if (offset < memSize) {
                    // TODO: should disassemble instruction here
                    // C6 00 05
                    auto excptAddr = (uint8_t *)ExceptionInfo->ExceptionRecord->ExceptionAddress;
                    auto offset = addr - (ULONG_PTR)mmio;
                    auto value = excptAddr[2];
                    printf("  MMIO write to offset %llx = %x\n", offset, value);
                    if (offset == 0) {
                        mmioOut = value;
                    }
                    ExceptionInfo->ContextRecord->Rip += 3;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                break;
            }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    });
    printf("Added vectored exception handler; pointer = %p\n", vecHandler);

    // Setup continuation handler
    /*cntHandler = AddVectoredContinueHandler(~0, [](_EXCEPTION_POINTERS *ExceptionInfo) -> LONG {
        auto type = ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
        if (type == 0 || type == 1) {
            printf("Recovered from memory access violation exception\n");
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    });
    printf("Added vectored continue handler; pointer = %p\n", cntHandler);*/

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
    mmio[0] = 5;
    printf("After MMIO access: %x\n", mmioOut);
    mmioOut = mmio[1];
    printf("MMIO value read: %x\n", mmioOut);

    // Try an actual out-of-bounds access
    // mmio[memSize] = 5;

    // view1 = nullptr;
    // view2 = nullptr;

Exit:
    /*if (mmio != nullptr) {
        if (!VirtualFree(mmio, 0, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS)) {
            printf("exit: VirtualFree for mmio region failed, error %#lx\n", GetLastError());
        }
    }*/
    if (view2 != nullptr) {
        if (!win32::UnmapViewOfFileEx(view2, MEM_PRESERVE_PLACEHOLDER)) {
            printf("exit: UnmapViewOfFileEx for 2nd region failed, error %#lx\n", GetLastError());
        }
        if (!VirtualFree(view2, memSize * 2, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS)) {
            printf("exit: VirtualFree for 2nd region failed, error %#lx\n", GetLastError());
        }
    }
    if (view1 != nullptr) {
        if (!win32::UnmapViewOfFileEx(view1, MEM_PRESERVE_PLACEHOLDER)) {
            printf("exit: UnmapViewOfFileEx for 1st region failed, error %#lx\n", GetLastError());
        }
        if (!VirtualFree(view1, memSize * 3, MEM_RELEASE | MEM_COALESCE_PLACEHOLDERS)) {
            printf("exit: VirtualFree for 1st region failed, error %#lx\n", GetLastError());
        }
    }
    if (buf != nullptr) {
        if (!VirtualFree(buf, 0, MEM_RELEASE)) {
            printf("exit: VirtualFree for buffer failed, error %#lx\n", GetLastError());
        }
    }
    if (section != nullptr) {
        if (!CloseHandle(section)) {
            printf("exit: CloseHandle failed, error %#lx\n", GetLastError());
        }
    }
    return 0;
}
