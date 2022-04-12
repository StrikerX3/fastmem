#include "vmem.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

uint8_t *mmio = nullptr;
uint8_t mmioOut = 0;

int main() {
    constexpr size_t memSize = 0x1000;
    vmem::VirtualMemory mem{memSize * 3};
    printf("Virtual memory allocated: %zu bytes at %p\n", mem.Size(), mem.Ptr());

    // TODO: make a more realistic demo
    // - two vmem::VirtualMemory instances (read, write)
    // - vmem::BackedMemory instances for:
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

    vmem::BackedMemory ram{0x1000, vmem::Access::ReadWrite};
    printf("RAM allocated: %zu bytes\n", ram.Size());

    auto view1 = mem.Map(ram, 0x0000);
    if (view1.ptr) {
        printf("RAM mapped to 0x0000 -> %p\n", view1.ptr);
    }

    auto view2 = mem.Map(ram, 0x1000);
    if (view2.ptr) {
        printf("RAM mirror mapped to 0x1000 -> %p\n", view2.ptr);
    }

    PVOID vecHandler = AddVectoredExceptionHandler(1, [](_EXCEPTION_POINTERS *ExceptionInfo) -> LONG {
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
