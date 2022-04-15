#include "exception_registry.hpp"

#ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #define NOMINMAX
#endif
#include <Windows.h>

#include <concepts>
#include <optional>
#include <unordered_map>

#if !defined(NDEBUG)
    #define ALWAYS_INLINE inline
#elif (defined(__GNUC__) || defined(__GNUG__) || defined(__clang__))
    #define ALWAYS_INLINE inline __attribute__((__always_inline__))
#elif defined(_MSC_VER)
    #define ALWAYS_INLINE __forceinline
#else
    #define ALWAYS_INLINE inline
#endif

// Sign-extend from a constant bit width
template <std::signed_integral T, unsigned B>
inline constexpr T SignExtend(const T x) {
    struct {
        T x : B;
    } s{x};
    return s.x;
}

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

enum class ExtensionType { None, Zero, Sign };

struct MovInstruction {
    const uint8_t *codeEnd = nullptr;
    size_t accessSize = 0;
    uint64_t immValue = 0;
    Register reg = Register::RAX;
    size_t regSize = 0;
    bool immediate = false;
    ExtensionType extensionType = ExtensionType::None;
    bool rexPrefix = false;
};

ALWAYS_INLINE DWORD64 &RegRef(PCONTEXT context, Register reg, size_t regSize, bool rex) {
    //            index -> 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15
    // r8(/r) without REX  AL   CL   DL   BL   AH   CH   DH   BH   -    -    -    -    -    -    -    -
    // r8(/r) with REX     AL   CL   DL   BL   SPL  BPL  SIL  DIL  R8B  R9B  R10B R11B R12B R13B R14B R15B
    // r16(/r)             AX   CX   DX   BX   SP   BP   SI   DI   R8W  R9W  R10W R11W R12W R13W R14W R15W
    // r32(/r)             EAX  ECX  EDX  EBX  ESP  EBP  ESI  EDI  R8D  R9D  R10D R11D R12D R13D R14D R15D
    // r64(/r)             RAX  RCX  RDX  RBX  RSP  RBP  RSI  RDI  R8   R9   R10  R11  R12  R13  R14  R15
    auto index = static_cast<size_t>(reg);
    if (regSize == 1 && !rex) {
        index &= 3;
    }
    auto *ptr = &context->Rax;
    return ptr[index];
    /*switch (reg) {
    case Register::RAX: return context->Rax;
    case Register::RCX: return context->Rcx;
    case Register::RDX: return context->Rdx;
    case Register::RBX: return context->Rbx;
    case Register::RSP: return (regSize == 1 && !rex) ? context->Rax : context->Rsp;
    case Register::RBP: return (regSize == 1 && !rex) ? context->Rcx : context->Rbp;
    case Register::RSI: return (regSize == 1 && !rex) ? context->Rdx : context->Rsi;
    case Register::RDI: return (regSize == 1 && !rex) ? context->Rbx : context->Rdi;
    case Register::R8: return context->R8;
    case Register::R9: return context->R9;
    case Register::R10: return context->R10;
    case Register::R11: return context->R11;
    case Register::R12: return context->R12;
    case Register::R13: return context->R13;
    case Register::R14: return context->R14;
    case Register::R15: return context->R15;
    default: // TODO: unreachable/invalid
        return context->Rax;
    }*/
}

ALWAYS_INLINE uint64_t ReadReg(PCONTEXT context, Register reg, size_t regSize, bool rex, ExtensionType ext) {
    if (regSize == 4 && ext == ExtensionType::None) {
        ext = ExtensionType::Zero;
    }
    auto &regRef = RegRef(context, reg, regSize, rex);
    const uint64_t mask = (~0ull >> (64 - regSize * 8));
    switch (ext) {
    case ExtensionType::None: return regRef & mask;
    case ExtensionType::Zero: return regRef & mask;
    case ExtensionType::Sign:
        switch (regSize) {
        case 1: return SignExtend<int64_t, 8>(regRef & mask);
        case 2: return SignExtend<int64_t, 16>(regRef & mask);
        case 4: return SignExtend<int64_t, 32>(regRef & mask);
        case 8: return regRef;
        default: // TODO: unreachable
            return regRef;
        }
    default: // TODO: unreachable
        return regRef;
    }
}

ALWAYS_INLINE void WriteReg(PCONTEXT context, Register reg, size_t regSize, bool rex, ExtensionType ext,
                            uint64_t value) {
    if (regSize == 4 && ext == ExtensionType::None) {
        ext = ExtensionType::Zero;
    }
    auto &regRef = RegRef(context, reg, regSize, rex);
    const uint64_t mask = (~0ull >> (64 - regSize * 8));
    switch (ext) {
    case ExtensionType::None: regRef = (regRef & ~mask) | (value & mask); break;
    case ExtensionType::Zero: regRef = value & mask; break;
    case ExtensionType::Sign:
        switch (regSize) {
        case 1: regRef = SignExtend<int64_t, 8>(value & mask); break;
        case 2: regRef = SignExtend<int64_t, 16>(value & mask); break;
        case 4: regRef = SignExtend<int64_t, 32>(value & mask); break;
        case 8: regRef = value; break;
        }
        break;
    default: // TODO: unreachable
        break;
    }
}

std::optional<MovInstruction> Decode(const uint8_t *code, PCONTEXT context) {
    // write:
    //      C6 86 00 20 00 00 15           mov    byte ptr [rsi+2000h],15h
    //   66 C7 86 02 20 00 00 E1 10        mov    word ptr [rsi+2002h],10E1h
    //   48 C7 86 08 20 00 00 31 D4 00 00  mov    qword ptr [rsi+2008h],0D431h
    //   48 89 86 08 20 00 00              mov    qword ptr [rsi+2008h],rax
    //      C6 00 15                       mov    byte ptr [rax],15h
    //   66 C7 40 02 E1 10                 mov    word ptr [rax+2],10E1h
    //      C7 40 04 B1 7F 39 05           mov    dword ptr [rax+4],5397FB1h
    //   48 C7 40 08 31 D4 00 00           mov    qword ptr [rax+8],0D431h
    //   48 89 48 08                       mov    qword ptr [rax+8],rcx
    //   4C 0F BF 6B 03                    movsx  r13,word ptr [rbx+3]
    //   48 63 73 05                       movsxd rsi,dword ptr [rbx+5]
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

    MovInstruction instr{};

    // Handle prefixes:
    // 0x66 -> address size override
    // 0x67 -> operand size override
    // 0x4* -> REX prefix
    bool addressSizeOverride = false;
    bool rexW = false;
    bool rexR = false;

    bool handlingPrefixes = true;
    do {
        switch (*code) {
        case 0x66: addressSizeOverride = true; break;
        case 0x67: break; // operand size override; affects addressing, which is irrelevant here
        default:
            if ((*code & 0xF0) == 0x40) {
                instr.rexPrefix = true;
                rexW = (*code >> 3) & 1;
                rexR = (*code >> 2) & 1;
                // These are only used with the SIB byte, which affects addressing.
                // We don't need to parse these as the computed memory address is already known.
                // rexX = (*code >> 1) & 1;
                // rexB = (*code >> 0) & 1;
            } else {
                handlingPrefixes = false;
            }
            break;
        }
        if (handlingPrefixes) {
            ++code;
        }
    } while (handlingPrefixes);

    instr.regSize = rexW ? 8 : addressSizeOverride ? 2 : 4;
    const size_t immSize = (rexW || !addressSizeOverride) ? 4 : 2;

    auto readModRM = [&] {
        ModRM modRM = *++code;
        if (modRM.mod == 0b11) [[unlikely]] {
            // shouldn't happen (not a memory access)
            return modRM; // TODO: flag unsupported instruction
        }
        if (modRM.rm == 0b100) {
            // Skip SIB byte as it only affects addressing in no relevant way
            ++code;
        }
        switch (modRM.mod) {
        case 0b00: break;            // [reg]
        case 0b01: code += 1; break; // [reg+byte]
        case 0b10: code += 4; break; // [reg+dword]
        }
        return modRM;
    };

    auto getOperand = [&](ModRM modRM) { return static_cast<Register>(modRM.reg + rexR * 8); };

    auto readImm = [&](size_t immSize) {
        uint64_t result;
        switch (immSize) {
        case 1: result = *reinterpret_cast<const uint8_t *>(code + 1); break;
        case 2: result = *reinterpret_cast<const uint16_t *>(code + 1); break;
        case 4: result = *reinterpret_cast<const uint32_t *>(code + 1); break;
        default: // TODO: unreachable
            result = 0;
        }
        code += immSize;
        return result;
    };

    switch (*code) {
    case 0x0F: // two-byte opcodes
        switch (*++code) {
        case 0xB6: { // movzx r(16|32|64), r/m8
            auto modRM = readModRM();
            instr.reg = getOperand(modRM);
            instr.accessSize = 1;
            instr.extensionType = ExtensionType::Zero;
            break;
        }
        case 0xB7: { // movzx r(16|32|64), r/m16
            auto modRM = readModRM();
            instr.reg = getOperand(modRM);
            instr.accessSize = 2;
            instr.extensionType = ExtensionType::Zero;
            break;
        }
        case 0xBE: { // movsx r(16|32|64), r/m8
            auto modRM = readModRM();
            instr.reg = getOperand(modRM);
            instr.accessSize = 1;
            instr.extensionType = ExtensionType::Sign;
            break;
        }
        case 0xBF: { // movsx r(16|32|64), r/m16
            auto modRM = readModRM();
            instr.reg = getOperand(modRM);
            instr.accessSize = 2;
            instr.extensionType = ExtensionType::Sign;
            break;
        }
        }
        break;
    case 0x63: { // movsxd r(16|32|64), r/m(16|32)
        auto modRM = readModRM();
        instr.reg = getOperand(modRM);
        instr.accessSize = addressSizeOverride ? 2 : 4;
        instr.extensionType = ExtensionType::Sign;
        break;
    }
    case 0x88: { // mov r/m8, r8
        auto modRM = readModRM();
        instr.immediate = false;
        instr.reg = getOperand(modRM);
        instr.extensionType = ExtensionType::None;
        instr.accessSize = 1;
        break;
    }
    case 0x89: { // mov r/m(16|32|64), r(16|32|64)
        auto modRM = readModRM();
        instr.immediate = false;
        instr.reg = getOperand(modRM);
        instr.extensionType = ExtensionType::None;
        instr.accessSize = instr.regSize;
        break;
    }
    case 0x8A: { // mov r8, r/m8
        auto modRM = readModRM();
        instr.reg = getOperand(modRM);
        instr.accessSize = 1;
        break;
    }
    case 0x8B: { // mov r(16|32|64), r/m(16|32|64)
        auto modRM = readModRM();
        instr.reg = getOperand(modRM);
        instr.accessSize = instr.regSize;
        break;
    }
    case 0xC6: // mov r/m8, imm8
        readModRM();
        instr.immediate = true;
        instr.immValue = readImm(1);
        instr.accessSize = 1;
        break;
    case 0xC7: // mov r/m(16|32|64), imm(16|32)
        readModRM();
        instr.immediate = true;
        instr.immValue = readImm(immSize);
        instr.accessSize = instr.regSize;
        if (instr.regSize == 8) {
            // Value is sign extended when writing to 64-bit register
            instr.immValue = SignExtend<int64_t, 32>(instr.immValue);
        }
        break;
    default: return std::nullopt; // unsupported instruction
    }
    ++code;
    instr.codeEnd = code;
    return instr;
}

} // namespace x86

namespace os::excpt {

struct MemoryAccessExceptionHandlerRegistry::Impl {
    Impl() {
        vehPtr = AddVectoredExceptionHandler(1, [](_EXCEPTION_POINTERS *ExceptionInfo) -> LONG {
            if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) [[unlikely]] {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            const auto addr = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];

            if (s_handlerCache.contains(ExceptionInfo->ContextRecord->Rip)) {
                auto &handler = s_handlerCache.at(ExceptionInfo->ContextRecord->Rip);
                handler.Invoke(ExceptionInfo->ContextRecord, addr);
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            const auto type = ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
            if (type == 8) {
                // Data execution prevention; we don't handle those
                return EXCEPTION_CONTINUE_SEARCH;
            }

            if (s_handlers.Contains(addr)) {
                const uint8_t *code = reinterpret_cast<const uint8_t *>(ExceptionInfo->ContextRecord->Rip);
                auto opt_instr = x86::Decode(code, ExceptionInfo->ContextRecord);
                if (!opt_instr) {
                    // printf("Unsupported instruction!\n");
                    __debugbreak();
                    return EXCEPTION_CONTINUE_SEARCH;
                }

                auto &instr = *opt_instr;
                /*printf("Instruction:");
                for (const uint8_t *i = code; i < instr.codeEnd; i++) {
                    printf(" %02X", *i);
                }
                printf("\n");*/

                auto entry = s_handlerCache.insert(
                    {ExceptionInfo->ContextRecord->Rip, Handler{.write = (type == 1), .instr = instr}});

                entry.first->second.Invoke(ExceptionInfo->ContextRecord, addr);
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            return EXCEPTION_CONTINUE_SEARCH;
        });
    }

    ~Impl() {
        RemoveVectoredExceptionHandler(vehPtr);
    }

    PVOID vehPtr;

    struct Handler {
        bool write;
        x86::MovInstruction instr;

        void Invoke(PCONTEXT context, uintptr_t addr) {
            uint64_t value;
            auto handler = s_handlers.At(addr);
            if (write) {
                if (instr.immediate) {
                    value = instr.immValue;
                } else {
                    value = x86::ReadReg(context, instr.reg, instr.regSize, instr.rexPrefix, instr.extensionType);
                }
                handler.InvokeWrite(addr, instr.accessSize, &value);
            } else {
                handler.InvokeRead(addr, instr.accessSize, &value);
                x86::WriteReg(context, instr.reg, instr.regSize, instr.rexPrefix, instr.extensionType, value);
            }
            context->Rip = reinterpret_cast<DWORD64>(instr.codeEnd);
        }
    };

    static std::unordered_map<uintptr_t, Handler> s_handlerCache;
};

std::unordered_map<uintptr_t, MemoryAccessExceptionHandlerRegistry::Impl::Handler>
    MemoryAccessExceptionHandlerRegistry::Impl::s_handlerCache;

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
