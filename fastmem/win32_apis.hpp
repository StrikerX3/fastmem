#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

namespace win32 {

using PVirtualAlloc2 = PVOID(WINAPI *)(HANDLE Process, PVOID BaseAddress, SIZE_T Size, ULONG AllocationType,
                                       ULONG PageProtection, MEM_EXTENDED_PARAMETER *ExtendedParameters,
                                       ULONG ParameterCount);

using PMapViewOfFile3 = PVOID(WINAPI *)(HANDLE FileMapping, HANDLE Process, PVOID BaseAddress, ULONG64 Offset,
                                        SIZE_T ViewSize, ULONG AllocationType, ULONG PageProtection,
                                        MEM_EXTENDED_PARAMETER *ExtendedParameters, ULONG ParameterCount);

using PUnmapViewOfFileEx = BOOL(WINAPI *)(PVOID BaseAddress, ULONG UnmapFlags);

inline PVirtualAlloc2 VirtualAlloc2 = nullptr;         // Windows 10
inline PMapViewOfFile3 MapViewOfFile3 = nullptr;       // Windows 10 1803
inline PUnmapViewOfFileEx UnmapViewOfFileEx = nullptr; // Windows 8

class LibraryLoader {
    LibraryLoader() {
        hmKernelBase = LoadLibrary(TEXT("KernelBase.dll"));
        if (hmKernelBase == nullptr) {
            return;
        }

        VirtualAlloc2 = (PVirtualAlloc2)GetProcAddress(hmKernelBase, "VirtualAlloc2");
        MapViewOfFile3 = (PMapViewOfFile3)GetProcAddress(hmKernelBase, "MapViewOfFile3");
        UnmapViewOfFileEx = (PUnmapViewOfFileEx)GetProcAddress(hmKernelBase, "UnmapViewOfFileEx");
    }

    ~LibraryLoader() {
        FreeLibrary(hmKernelBase);
    }

    HMODULE hmKernelBase = nullptr;
    static LibraryLoader instance;
};
inline LibraryLoader LibraryLoader::instance;

} // namespace win32
