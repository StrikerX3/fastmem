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

enum class Register { RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 };

uint64_t ReadReg(PCONTEXT context, Register reg) {
    // TODO: should handle zero/sign extensions and smaller sizes
    switch (reg) {
    case Register::RAX: return context->Rax;
    case Register::RCX: return context->Rcx;
    case Register::RDX: return context->Rdx;
    case Register::RBX: return context->Rbx;
    case Register::RSP: return context->Rsp;
    case Register::RBP: return context->Rbp;
    case Register::RSI: return context->Rsi;
    case Register::RDI: return context->Rdi;
    case Register::R8: return context->R8;
    case Register::R9: return context->R9;
    case Register::R10: return context->R10;
    case Register::R11: return context->R11;
    case Register::R12: return context->R12;
    case Register::R13: return context->R13;
    case Register::R14: return context->R14;
    case Register::R15: return context->R15;
    default: // TODO: unreachable
        return 0;
    }
}

void WriteReg(PCONTEXT context, Register reg, uint64_t value) {
    // TODO: should handle zero/sign extensions and smaller sizes
    switch (reg) {
    case Register::RAX: context->Rax = value; break;
    case Register::RCX: context->Rcx = value; break;
    case Register::RDX: context->Rdx = value; break;
    case Register::RBX: context->Rbx = value; break;
    case Register::RSP: context->Rsp = value; break;
    case Register::RBP: context->Rbp = value; break;
    case Register::RSI: context->Rsi = value; break;
    case Register::RDI: context->Rdi = value; break;
    case Register::R8: context->R8 = value; break;
    case Register::R9: context->R9 = value; break;
    case Register::R10: context->R10 = value; break;
    case Register::R11: context->R11 = value; break;
    case Register::R12: context->R12 = value; break;
    case Register::R13: context->R13 = value; break;
    case Register::R14: context->R14 = value; break;
    case Register::R15: context->R15 = value; break;
    default: // TODO: unreachable
        break;
    }
}

const uint8_t *Decode(const uint8_t *code, size_t &size, uint64_t &value, Register &outReg, PCONTEXT context) {
    // write:
    //      C6 86 00 20 00 00 15              mov byte ptr [rsi+2000h],15h
    //   66 C7 86 02 20 00 00 E1 10           mov word ptr [rsi+2002h],10E1h
    //   48 C7 86 08 20 00 00 31 D4 00 00     mov qword ptr [rsi+2008h],0D431h
    //   48 89 86 08 20 00 00                 mov qword ptr [rsi+2008h],rax
    //      C6 00 15                          mov byte ptr [rax],15h
    //   66 C7 40 02 E1 10                    mov word ptr [rax+2],10E1h
    //      C7 40 04 B1 7F 39 05              mov dword ptr [rax+4],5397FB1h
    //   48 C7 40 08 31 D4 00 00              mov qword ptr [rax+8],0D431h
    //   48 89 48 08                          mov qword ptr [rax+8],rcx
    // read:
    //      0F B6 96 01 20 00 00  movzx edx,byte ptr [rsi+2001h]
    //      8A 86 01 20 00 00     mov   al,byte ptr [rsi+2001h]
    //      0F B7 8E 03 20 00 00  movzx ecx,word ptr [rsi+2003h]
    //   44 8B 8E 05 20 00 00     mov   r9d,dword ptr [rsi+2005h]
    //   48 8B B6 09 20 00 00     mov   rsi,qword ptr [rsi+2009h]
    //      0F B6 50 01           movzx edx,byte ptr [rax+1]
    //      88 45 DF              mov   byte ptr [mmioVal8],al
    //   66 89 45 DC              mov   word ptr [mmioVal16],ax
    //      89 45 D8              mov   dword ptr [mmioVal32],eax
    //   48 89 45 D0              mov   qword ptr [mmioVal64],rax

    const uint8_t *codeStart = code;
    size = 0;
    value = 0;
    outReg = Register::RAX;

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
            }
            break;
        }
        if (handlingPrefixes) {
            ++code;
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
        case 0xB6: { // movzx r(16|32|64), r/m8
            auto modRM = readModRM();
            size = 1;
            // TODO: handle AH/CH/DH/BH (without REX prefix)
            outReg = static_cast<Register>(modRM.reg + rexR * 8);
            break;
        }
        case 0xB7: { // movzx r(16|32|64), r/m16
            auto modRM = readModRM();
            size = 2;
            // TODO: handle AH/CH/DH/BH (without REX prefix)
            outReg = static_cast<Register>(modRM.reg + rexR * 8);
            break;
        }
        }
        break;
    case 0x88: { // mov r/m8, r8
        auto modRM = readModRM();
        size = 1;
        value = ReadReg(context, static_cast<Register>(modRM.reg + rexR * 8));
        break;
    }
    case 0x89: { // mov r/m(16|32|64), r(16|32|64)
        auto modRM = readModRM();
        size = rexW ? 8 : addressSizeOverride ? 2 : 4;
        switch (size) {
        case 2: value = ReadReg(context, static_cast<Register>(modRM.reg + rexR * 8)); break;
        case 4: value = ReadReg(context, static_cast<Register>(modRM.reg + rexR * 8)); break;
        case 8: value = ReadReg(context, static_cast<Register>(modRM.reg + rexR * 8)); break;
        }
        break;
    }
    case 0x8A: { // mov r8, r/m8
        auto modRM = readModRM();
        size = 1;
        outReg = static_cast<Register>(modRM.reg + rexR * 8);
        break;
    }
    case 0x8B: { // mov r(16|32|64), r/m(16|32|64)
        auto modRM = readModRM();
        size = rexW ? 8 : addressSizeOverride ? 2 : 4;
        outReg = static_cast<Register>(modRM.reg + rexR * 8);
        break;
    }
    case 0xC6: // mov r/m8, imm8
        readModRM();
        size = 1;
        value = *++code;
        break;
    case 0xC7: // mov r/m(16|32|64), imm(16|32|64)
        readModRM();
        size = rexW ? 8 : addressSizeOverride ? 2 : 4;
        switch (size) {
        case 2: value = *reinterpret_cast<const uint16_t *>(code + 1); break;
        case 4: value = *reinterpret_cast<const uint32_t *>(code + 1); break;
        case 8: value = *reinterpret_cast<const uint32_t *>(code + 1); break;
        }
        code += rexW ? 4 : addressSizeOverride ? 2 : 4;
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
                    code = x86::Decode(code, size, value, outReg, ExceptionInfo->ContextRecord);
                    if (type == 0) {
                        handlerRegistry.At(addr).InvokeRead(addr, size, &value);
                        x86::WriteReg(ExceptionInfo->ContextRecord, outReg, value);
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