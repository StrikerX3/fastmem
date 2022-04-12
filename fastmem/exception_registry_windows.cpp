#include "exception_registry.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

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

                // TODO: create global registry of address ranges -> contexts+handlers
                // - O(1) search is mandatory
                // TODO: disassemble opcode at ExceptionInfo->ExceptionRecord->ExceptionAddress
                // - figure out the value written for writes
                // - skip instruction

                auto addr = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
                auto &handlerRegistry = s_handlers;
                if (handlerRegistry.Contains(addr)) {
                    // TODO: should disassemble instruction here
                    // read:
                    //   0F B6 96 01 20 00 00
                    // write:
                    //   C6 86 00 20 00 00 05
                    size_t size = 4; // TODO: figure out from disassembly
                    uint64_t value;
                    if (type == 0) {
                        handlerRegistry.At(addr).InvokeRead(addr, size, &value);
                        ExceptionInfo->ContextRecord->Rdx = value;
                        ExceptionInfo->ContextRecord->Rip += 7;
                    } else if (type == 1) {
                        value = 32; // TODO: figure out from disassembly
                        handlerRegistry.At(addr).InvokeWrite(addr, size, &value);
                        ExceptionInfo->ContextRecord->Rip += 7;
                    }
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
