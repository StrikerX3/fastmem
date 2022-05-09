#include "exception_registry.hpp"

#include "x86.hpp"

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

namespace x86 {

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
                auto opt_instr = x86::Decode(code);
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
                value = x86::ExtendValue(value, instr.accessSize, instr.regSize, instr.extensionType);
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
