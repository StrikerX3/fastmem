#include "exception_registry.hpp"

#include "x86.hpp"

#include <signal.h>

#include <bits/types/siginfo_t.h>
#include <concepts>
#include <optional>
#include <unordered_map>

#if !defined(NDEBUG)
    #define ALWAYS_INLINE inline
#elif (defined(__GNUC__) || defined(__GNUG__) || defined(__clang__))
    #define ALWAYS_INLINE inline __attribute__((__always_inline__))
#else
    #define ALWAYS_INLINE inline
#endif

namespace x86 {

ALWAYS_INLINE greg_t &RegRef(ucontext_t *context, Register reg, size_t regSize, bool rex) {
    //            index -> 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15
    // r8(/r) without REX  AL   CL   DL   BL   AH   CH   DH   BH   -    -    -    -    -    -    -    -
    // r8(/r) with REX     AL   CL   DL   BL   SPL  BPL  SIL  DIL  R8B  R9B  R10B R11B R12B R13B R14B R15B
    // r16(/r)             AX   CX   DX   BX   SP   BP   SI   DI   R8W  R9W  R10W R11W R12W R13W R14W R15W
    // r32(/r)             EAX  ECX  EDX  EBX  ESP  EBP  ESI  EDI  R8D  R9D  R10D R11D R12D R13D R14D R15D
    // r64(/r)             RAX  RCX  RDX  RBX  RSP  RBP  RSI  RDI  R8   R9   R10  R11  R12  R13  R14  R15
    auto *regs = context->uc_mcontext.gregs;
    switch (reg) {
    case Register::RAX: return regs[REG_RAX];
    case Register::RCX: return regs[REG_RCX];
    case Register::RDX: return regs[REG_RDX];
    case Register::RBX: return regs[REG_RBX];
    case Register::RSP: return (regSize == 1 && !rex) ? regs[REG_RAX] : regs[REG_RSP];
    case Register::RBP: return (regSize == 1 && !rex) ? regs[REG_RCX] : regs[REG_RBP];
    case Register::RSI: return (regSize == 1 && !rex) ? regs[REG_RDX] : regs[REG_RSI];
    case Register::RDI: return (regSize == 1 && !rex) ? regs[REG_RBX] : regs[REG_RDI];
    case Register::R8: return regs[REG_R8];
    case Register::R9: return regs[REG_R9];
    case Register::R10: return regs[REG_R10];
    case Register::R11: return regs[REG_R11];
    case Register::R12: return regs[REG_R12];
    case Register::R13: return regs[REG_R13];
    case Register::R14: return regs[REG_R14];
    case Register::R15: return regs[REG_R15];
    default: // TODO: unreachable/invalid
        return regs[REG_RAX];
    }
}

ALWAYS_INLINE uint64_t ReadReg(ucontext_t *context, Register reg, size_t regSize, bool rex, ExtensionType ext) {
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

ALWAYS_INLINE void WriteReg(ucontext_t *context, size_t accessSize, Register reg, size_t regSize, bool rex,
                            ExtensionType ext, uint64_t value) {
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
        struct sigaction action;
        action.sa_sigaction = [](int sig, siginfo_t *info, void *ucontext) {
            auto invokePreviousHandler = [&] {
                if (s_oldAction.sa_handler) {
                    s_oldAction.sa_handler(sig);
                } else if (s_oldAction.sa_sigaction) {
                    s_oldAction.sa_sigaction(sig, info, ucontext);
                }
            };

            // Ignore misfires
            if (sig != SIGSEGV) {
                invokePreviousHandler();
                return;
            }

            const auto addr = reinterpret_cast<uintptr_t>(info->si_addr);
            auto *context = static_cast<ucontext_t *>(ucontext);
            const auto rip = context->uc_mcontext.gregs[REG_RIP];

            if (s_handlerCache.contains(rip)) {
                auto &handler = s_handlerCache.at(rip);
                handler.Invoke(context, addr);
                return;
            }

            if (s_handlers.Contains(addr)) {
                auto *code = reinterpret_cast<const uint8_t *>(rip);
                auto opt_instr = x86::Decode(code);
                if (!opt_instr) {
                    invokePreviousHandler();
                    return;
                }

                auto &instr = *opt_instr;

                auto entry = s_handlerCache.insert(
                    {rip, Handler{.write = (context->uc_mcontext.gregs[REG_ERR] & 0x2) != 0, .instr = instr}});

                entry.first->second.Invoke(context, addr);
                return;
            }

            invokePreviousHandler();
            return;
        };
        sigemptyset(&action.sa_mask);
        action.sa_flags = SA_SIGINFO;
        sigaction(SIGSEGV, &action, &s_oldAction);
    }

    ~Impl() {
        sigaction(SIGSEGV, &s_oldAction, nullptr);
    }

    static struct sigaction s_oldAction;

    struct Handler {
        bool write;
        x86::MovInstruction instr;

        void Invoke(ucontext_t *context, uintptr_t addr) {
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
                x86::WriteReg(context, instr.accessSize, instr.reg, instr.regSize, instr.rexPrefix, instr.extensionType,
                              value);
            }
            context->uc_mcontext.gregs[REG_RIP] = reinterpret_cast<greg_t>(instr.codeEnd);
        }
    };

    static std::unordered_map<uintptr_t, Handler> s_handlerCache;
};

struct sigaction MemoryAccessExceptionHandlerRegistry::Impl::s_oldAction;

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
