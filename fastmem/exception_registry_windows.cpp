#include "exception_registry.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

namespace x86 {

union ModRM {
    uint8_t u8;
    struct {
        uint8_t rm : 3;
        uint8_t reg : 3;
        uint8_t mod : 2;
    };

    ModRM()
        : u8(0) {}

    ModRM(uint8_t u8)
        : u8(u8) {}
};

union SIB {
    uint8_t u8;
    struct {
        uint8_t base : 3;
        uint8_t index : 3;
        uint8_t scale : 2;
    };

    SIB()
        : u8(0) {}

    SIB(uint8_t u8)
        : u8(u8) {}
};

struct Register {
    uint32_t index; // RAX, RBX, RCX, ..., R15

    void Apply(PCONTEXT context, uint64_t value) {
        // TODO: should handle zero/sign extensions and smaller sizes
        switch (index) {
        case 0: context->Rax = value; break;
        case 1: context->Rcx = value; break;
        case 2: context->Rdx = value; break;
        case 3: context->Rbx = value; break;
        case 4: context->Rsp = value; break;
        case 5: context->Rbp = value; break;
        case 6: context->Rsi = value; break;
        case 7: context->Rdi = value; break;
        case 8: context->R8 = value; break;
        case 9: context->R9 = value; break;
        case 10: context->R10 = value; break;
        case 11: context->R11 = value; break;
        case 12: context->R12 = value; break;
        case 13: context->R13 = value; break;
        case 14: context->R14 = value; break;
        case 15: context->R15 = value; break;
        default: // TODO: unreachable
            break;
        }
    }
};

const uint8_t *Decode(const uint8_t *code, size_t &size, uint64_t &value, Register &outReg) {
    // read:
    //   (Rel) 0F B6 96 01 20 00 00  movzx edx,byte ptr [rsi+2001h]
    //   (Dbg) 0F B6 50 01           movzx edx,byte ptr [rax+1]
    // write:
    //   (Rel) C6 86 00 20 00 00 05  mov byte ptr [rsi+2000h],5
    //   (Dbg) C6 00 05              mov byte ptr [rax],5

    const uint8_t *codeStart = code;
    size = 0;
    value = 0;
    outReg.index = 0;

    // Handle prefixes:
    // 0x66 -> address size override
    // 0x67 -> operand size override
    // 0x4* -> REX prefix
    bool addressSizeOverride = false;
    bool operandSizeOverride = false;
    bool rex = false;
    bool rexW = false;
    bool rexR = false;
    bool rexX = false;
    bool rexB = false;

    bool handlingPrefixes = true;
    do {
        switch (*code) {
        case 0x66: addressSizeOverride = true; break;
        case 0x67: operandSizeOverride = true; break;
        default:
            if ((*code & 0xF0) == 0x40) {
                rex = true;
                rexW = (*code >> 3) & 1;
                rexR = (*code >> 2) & 1;
                rexX = (*code >> 1) & 1;
                rexB = (*code >> 0) & 1;
            } else {
                handlingPrefixes = false;
                break;
            }
        }
    } while (handlingPrefixes);

    auto readSIB = [&] {
        SIB sib = *++code;
        printf("SIB = %02X -> base %X  index %X  scale %X\n", sib.u8, sib.base, sib.index, sib.scale);
        return sib;
    };

    auto readModRM = [&] {
        ModRM modRM = *++code;
        printf("modRM = %02X -> r/m %X  reg %X  mod %X\n", modRM.u8, modRM.rm, modRM.reg, modRM.mod);
        if (modRM.mod == 0b11) {
            // shouldn't happen (not a memory access)
            return modRM; // TODO: flag unsupported instruction
        }
        if (modRM.rm == 0b100) {
            readSIB();
        }
        switch (modRM.mod) {
        case 0b00: break;            // [reg]
        case 0b01: code += 1; break; // [reg+byte]
        case 0b10: code += 4; break; // [reg+dword]
        }
        return modRM;
    };

    switch (*code) {
    case 0x0F: // two-byte opcodes
        switch (*++code) {
        case 0xB6: { // movzx r16, r/m8
            auto modRM = readModRM();
            size = 1;
            // TODO: handle AH/CH/DH/BH (without REX prefix)
            outReg.index = modRM.reg + rexR * 8;
            break;
        }
        }
        break;
    case 0xC6: // mov r/m8, imm8
        readModRM();
        size = 1;
        value = *++code; // immediate byte
        break;
    }
    ++code;

    printf("Instruction:");
    for (const uint8_t *i = codeStart; i < code; i++) {
        printf(" %02X", *i);
    }
    printf("\n");
    return code;
}

} // namespace x86

namespace os::excpt {

struct MemoryAccessExceptionHandlerRegistry::Impl {
    Impl() {
        vehPtr = AddVectoredExceptionHandler(1, [](_EXCEPTION_POINTERS *ExceptionInfo) -> LONG {
            if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
                auto type = ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
                if (type == 8) {
                    // Data execution prevention; we don't handle those
                    return EXCEPTION_CONTINUE_SEARCH;
                }

                // TODO: disassemble opcode at ExceptionInfo->ExceptionRecord->ExceptionAddress
                // - figure out the value written for writes
                // - skip instruction

                auto addr = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
                auto &handlerRegistry = s_handlers;
                if (handlerRegistry.Contains(addr)) {
                    const uint8_t *code = reinterpret_cast<const uint8_t *>(ExceptionInfo->ContextRecord->Rip);
                    size_t size;
                    uint64_t value;
                    x86::Register outReg;
                    code = x86::Decode(code, size, value, outReg);
                    if (type == 0) {
                        handlerRegistry.At(addr).InvokeRead(addr, size, &value);
                        outReg.Apply(ExceptionInfo->ContextRecord, value);
                    } else if (type == 1) {
                        handlerRegistry.At(addr).InvokeWrite(addr, size, &value);
                    }
                    ExceptionInfo->ContextRecord->Rip = reinterpret_cast<DWORD64>(code);
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            return EXCEPTION_CONTINUE_SEARCH;
        });
    }

    ~Impl() {
        RemoveVectoredExceptionHandler(vehPtr);
    }

    PVOID vehPtr;
};

MemoryAccessExceptionHandlerRegistry::MemoryAccessExceptionHandlerRegistry()
    : m_impl(std::make_unique<Impl>()) {}

void MemoryAccessExceptionHandlerRegistry::Register(uintptr_t baseAddress, uintptr_t startAddress, uintptr_t endAddress,
                                                    void *context, ReadHandlerFn readFn, WriteHandlerFn writeFn) {
    s_handlers.Insert(baseAddress + startAddress, baseAddress + endAddress,
                      Entry{
                          .baseAddress = baseAddress,
                          .context = context,
                          .readHandler = readFn,
                          .writeHandler = writeFn,
                      });
}

void MemoryAccessExceptionHandlerRegistry::Unregister(uintptr_t baseAddress, uintptr_t startAddress,
                                                      uintptr_t endAddress) {
    s_handlers.Remove(baseAddress + startAddress, baseAddress + endAddress);
}

MemoryAccessExceptionHandlerRegistry MemoryAccessExceptionHandlerRegistry::s_instance;
util::NonOverlappingIntervalTree<uintptr_t, MemoryAccessExceptionHandlerRegistry::Entry>
    MemoryAccessExceptionHandlerRegistry::s_handlers;

} // namespace os::excpt
