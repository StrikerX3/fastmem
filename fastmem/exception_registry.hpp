#pragma once

#include "noitree.hpp"

#include <cstdint>
#include <memory>

namespace os::excpt {

using ReadHandlerFn = void (*)(void *context, uintptr_t address, size_t size, void *value);
using WriteHandlerFn = void (*)(void *context, uintptr_t address, size_t size, const void *value);

class MemoryAccessExceptionHandlerRegistry {
public:
    static void Register(uintptr_t baseAddress, uintptr_t startAddress, uintptr_t endAddress, void *context,
                         ReadHandlerFn readFn, WriteHandlerFn writeFn);

    static void Unregister(uintptr_t baseAddress, uintptr_t startAddress, uintptr_t endAddress);

private:
    MemoryAccessExceptionHandlerRegistry();

    struct Entry {
        uintptr_t baseAddress;
        void *context;
        ReadHandlerFn readHandler;
        WriteHandlerFn writeHandler;

        void InvokeRead(uintptr_t accessAddress, size_t size, void *value) {
            readHandler(context, accessAddress - baseAddress, size, value);
        }

        void InvokeWrite(uintptr_t accessAddress, size_t size, const void *value) {
            writeHandler(context, accessAddress - baseAddress, size, value);
        }

        bool operator==(const Entry &) const = default;
    };

    static MemoryAccessExceptionHandlerRegistry s_instance;
    static util::NonOverlappingIntervalTree<uintptr_t, Entry> s_handlers;

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace os::excpt
