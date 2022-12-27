#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <optional>

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

std::optional<MovInstruction> Decode(const uint8_t *code) {
    // references:
    //   https://www.agner.org/optimize/
    //   https://sandpile.org/
    //   https://github.com/corkami/docs/blob/master/x86/x86.md
    //   http://www.c-jump.com/CIS77/CPU/x86/X77_0240_prefix.htm

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
    //
    // non-mov read-modify-write:
    //      48 83 08 01              or   qword ptr [rax],1
    //      48 83 A0 00 02 00 00 F7  and  qword ptr [rax+200h],0FFFFFFFFFFFFFFF7h
    //      48 33 88 00 00 02 00     xor  rcx,qword ptr [rax+20000h]  
    // non-mov read:
    //      F6 80 00 00 02 00 01     test byte ptr [rax+20000h],1
    //
    // TODO: other non-mov operations that access memory
    //   string operations (MOVS, STOS, SCAS, CMPS, etc.)

    MovInstruction instr{};

    // Handle prefixes:
    // 0x66 -> address size override
    // 0x67 -> operand size override
    // 0x4* -> REX prefix
    // TODO:
    // - REX prefix is silently dropped if it comes before other prefixes
    // - Handle additional prefixes:
    //     0x26 -> ES segment override
    //     0x2E -> CS segment override / branch not taken hint
    //     0x36 -> SS segment override
    //     0x3E -> DS segment override / branch taken hint
    //     0x64 -> FS segment override
    //     0x65 -> GS segment override
    //     0xF0 -> LOCK
    //     0xF2 -> REPNE
    //     0xF3 -> REP/REPE
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

    const size_t regSize = rexW ? 8 : addressSizeOverride ? 2 : 4;
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
            instr.regSize = regSize;
            instr.accessSize = 1;
            instr.extensionType = ExtensionType::Zero;
            break;
        }
        case 0xB7: { // movzx r(16|32|64), r/m16
            auto modRM = readModRM();
            instr.reg = getOperand(modRM);
            instr.regSize = regSize;
            instr.accessSize = 2;
            instr.extensionType = ExtensionType::Zero;
            break;
        }
        case 0xBE: { // movsx r(16|32|64), r/m8
            auto modRM = readModRM();
            instr.reg = getOperand(modRM);
            instr.regSize = regSize;
            instr.accessSize = 1;
            instr.extensionType = ExtensionType::Sign;
            break;
        }
        case 0xBF: { // movsx r(16|32|64), r/m16
            auto modRM = readModRM();
            instr.reg = getOperand(modRM);
            instr.regSize = regSize;
            instr.accessSize = 2;
            instr.extensionType = ExtensionType::Sign;
            break;
        }
        }
        break;
    case 0x63: { // movsxd r(16|32|64), r/m(16|32)
        auto modRM = readModRM();
        instr.reg = getOperand(modRM);
        instr.regSize = regSize;
        instr.accessSize = addressSizeOverride ? 2 : 4;
        instr.extensionType = ExtensionType::Sign;
        break;
    }
    case 0x88: { // mov r/m8, r8
        auto modRM = readModRM();
        instr.immediate = false;
        instr.reg = getOperand(modRM);
        instr.regSize = 1;
        instr.extensionType = ExtensionType::None;
        instr.accessSize = 1;
        break;
    }
    case 0x89: { // mov r/m(16|32|64), r(16|32|64)
        auto modRM = readModRM();
        instr.immediate = false;
        instr.reg = getOperand(modRM);
        instr.regSize = regSize;
        instr.extensionType = ExtensionType::None;
        instr.accessSize = instr.regSize;
        break;
    }
    case 0x8A: { // mov r8, r/m8
        auto modRM = readModRM();
        instr.reg = getOperand(modRM);
        instr.regSize = 1;
        instr.accessSize = 1;
        break;
    }
    case 0x8B: { // mov r(16|32|64), r/m(16|32|64)
        auto modRM = readModRM();
        instr.reg = getOperand(modRM);
        instr.regSize = regSize;
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
        instr.accessSize = regSize;
        if (regSize == 8) {
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

uint64_t ExtendValue(uint64_t value, size_t srcSize, size_t dstSize, ExtensionType ext) {
    if (srcSize == dstSize) {
        // Same sizes -- no change
        return value;
    }
    if (srcSize > dstSize) {
        // Source larger than destination -- truncate
        return value & (~0ull >> (64 - dstSize * 8));
    }
    // Source smaller than destination -- extend as appropriate
    if (ext == ExtensionType::Sign) {
        switch (srcSize) {
        case 1: return SignExtend<int64_t, 8>(value);
        case 2: return SignExtend<int64_t, 16>(value);
        case 4: return SignExtend<int64_t, 32>(value);
        case 8: return value;
        }
    }
    return value & (~0ull >> (64 - srcSize * 8));
}

} // namespace x86
