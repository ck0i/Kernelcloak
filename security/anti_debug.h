#pragma once
#include "../config.h"
#include "../core/types.h"
#include "../core/memory.h"
#include "../crypto/hash.h"

#if KC_ENABLE_ANTI_DEBUG

#if KC_ENABLE_IMPORT_HIDING
#include "import_hiding.h"
#endif

// type declarations needed for both paths
#if !defined(_NTDDK_) && !defined(_WDMDDK_)
extern "C" {
#ifndef _LARGE_INTEGER_DEFINED
#define _LARGE_INTEGER_DEFINED
    typedef union _LARGE_INTEGER {
        struct { unsigned long LowPart; long HighPart; };
        __int64 QuadPart;
    } LARGE_INTEGER, *PLARGE_INTEGER;
#endif

    unsigned char __stdcall MmIsAddressValid(void* VirtualAddress);
}
#endif

extern "C" {
    unsigned __int64 __rdtsc();
    unsigned char __stdcall KeGetCurrentIrql();
#if defined(_M_X64) || defined(_M_AMD64)
    unsigned __int64 __readdr(unsigned int reg);
#endif
}

#pragma intrinsic(__rdtsc)
#if defined(_M_X64) || defined(_M_AMD64)
#pragma intrinsic(__readdr)
#endif

#ifndef PASSIVE_LEVEL
#define PASSIVE_LEVEL 0
#endif

namespace kernelcloak {
namespace security {

namespace detail {

// KUSER_SHARED_DATA on x64 is mapped at this fixed address
constexpr uintptr_t kuser_shared_data_addr = 0xFFFFF78000000000ull;

// offset of KdDebuggerEnabled byte within KUSER_SHARED_DATA
constexpr uintptr_t kd_debugger_enabled_offset = 0x2D4;

// timing threshold - single-stepping costs 10k+ TSC ticks per instruction,
// a simple operation should complete in well under 5000
constexpr uint64_t rdtsc_threshold = 5000;

// ─────────────────────────────────────────────────────────────
// when import hiding is available, resolve KdDebuggerEnabled,
// KdDebuggerNotPresent, KeQueryPerformanceCounter, and
// PsIsProcessBeingDebugged dynamically. this eliminates the
// anti-debug indicator IAT entries that static analysis flags.
// ─────────────────────────────────────────────────────────────

#if KC_ENABLE_IMPORT_HIDING

KC_NOINLINE inline bool check_kd_enabled() {
    __try {
        // KdDebuggerEnabled is a data export (BOOLEAN/UCHAR) from ntoskrnl.
        // resolve_import returns the address of the exported variable.
        auto kd_addr = resolve_import(KC_HASH_CI("ntoskrnl.exe"), KC_HASH_CI("KdDebuggerEnabled"));
        if (!kd_addr || !MmIsAddressValid(kd_addr))
            return false;

        return *static_cast<volatile unsigned char*>(kd_addr) != 0;
    } __except (1) {
        return false;
    }
}

// KdDebuggerNotPresent == FALSE means debugger IS present
KC_NOINLINE inline bool check_kd_not_present() {
    __try {
        auto kd_addr = resolve_import(KC_HASH_CI("ntoskrnl.exe"), KC_HASH_CI("KdDebuggerNotPresent"));
        if (!kd_addr || !MmIsAddressValid(kd_addr))
            return false;

        return *static_cast<volatile unsigned char*>(kd_addr) == 0;
    } __except (1) {
        return false;
    }
}

// KeQueryPerformanceCounter timing variant
KC_NOINLINE inline bool check_perf_counter_timing() {
    __try {
        using ke_qpc_t = LARGE_INTEGER(__stdcall*)(LARGE_INTEGER*);
        auto ke_qpc = reinterpret_cast<ke_qpc_t>(
            resolve_import(KC_HASH_CI("ntoskrnl.exe"), KC_HASH_CI("KeQueryPerformanceCounter")));
        if (!ke_qpc)
            return false;

        LARGE_INTEGER freq;
        LARGE_INTEGER t1 = ke_qpc(&freq);

        volatile uint64_t dummy = 0;
        for (int i = 0; i < 10; ++i)
            dummy += i;

        LARGE_INTEGER t2 = ke_qpc(nullptr);
        int64_t delta = t2.QuadPart - t1.QuadPart;

        // 50us threshold
        int64_t threshold = freq.QuadPart / 20000;
        if (threshold < 50) threshold = 50;

        return delta > threshold;
    } __except (1) {
        return false;
    }
}

// resolve PsIsProcessBeingDebugged via import hiding
// IRQL: PASSIVE_LEVEL only
KC_NOINLINE inline bool check_process_debugged() {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return false;

    __try {
        auto fn = reinterpret_cast<unsigned char(__stdcall*)(void*)>(
            resolve_import(KC_HASH_CI("ntoskrnl.exe"), KC_HASH_CI("PsIsProcessBeingDebugged")));
        if (!fn)
            return false;

        auto get_proc = reinterpret_cast<void*(__stdcall*)()>(
            resolve_import(KC_HASH_CI("ntoskrnl.exe"), KC_HASH_CI("PsGetCurrentProcess")));
        if (!get_proc)
            return false;

        void* process = get_proc();
        if (!process)
            return false;

        return fn(process) != 0;
    } __except (1) {
        return false;
    }
}

KC_NOINLINE inline void take_response() {
#if KC_ANTI_DEBUG_RESPONSE == 1
    // resolve KeBugCheck dynamically to avoid IAT entry
    using ke_bugcheck_t = void(__stdcall*)(unsigned long);
    auto bugcheck = reinterpret_cast<ke_bugcheck_t>(
        resolve_import(KC_HASH_CI("ntoskrnl.exe"), KC_HASH_CI("KeBugCheck")));
    if (bugcheck)
        bugcheck(0x000000E2);
#elif KC_ANTI_DEBUG_RESPONSE == 2
    volatile uint8_t* sp = reinterpret_cast<volatile uint8_t*>(&sp);
    for (int i = 0; i < 4096; ++i)
        sp[i] = 0;
#else
    // response disabled
#endif
}

#else // KC_ENABLE_IMPORT_HIDING not available - fall back to static imports

// static path: these symbols will appear in IAT
#if !defined(_NTDDK_) && !defined(_WDMDDK_)
extern "C" {
    extern unsigned char KdDebuggerEnabled;
    extern unsigned char KdDebuggerNotPresent;
    LARGE_INTEGER __stdcall KeQueryPerformanceCounter(LARGE_INTEGER* PerformanceFrequency);
    void __stdcall KeBugCheck(unsigned long BugCheckCode);

#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
    struct _UNICODE_STRING {
        unsigned short Length;
        unsigned short MaximumLength;
        wchar_t* Buffer;
    };
    using UNICODE_STRING = _UNICODE_STRING;
    using PUNICODE_STRING = UNICODE_STRING*;
#endif

    void* __stdcall MmGetSystemRoutineAddress(UNICODE_STRING* SystemRoutineName);
}
#endif

KC_NOINLINE inline bool check_kd_enabled() {
    __try {
        return KdDebuggerEnabled != 0;
    } __except (1) {
        return false;
    }
}

KC_NOINLINE inline bool check_kd_not_present() {
    __try {
        return KdDebuggerNotPresent == 0;
    } __except (1) {
        return false;
    }
}

KC_NOINLINE inline bool check_perf_counter_timing() {
    __try {
        LARGE_INTEGER freq;
        LARGE_INTEGER t1 = KeQueryPerformanceCounter(&freq);

        volatile uint64_t dummy = 0;
        for (int i = 0; i < 10; ++i)
            dummy += i;

        LARGE_INTEGER t2 = KeQueryPerformanceCounter(nullptr);
        int64_t delta = t2.QuadPart - t1.QuadPart;

        int64_t threshold = freq.QuadPart / 20000;
        if (threshold < 50) threshold = 50;

        return delta > threshold;
    } __except (1) {
        return false;
    }
}

KC_NOINLINE inline bool check_process_debugged() {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return false;

    __try {
        wchar_t name[] = L"PsIsProcessBeingDebugged";
        UNICODE_STRING uname;
        uname.Buffer = name;
        uname.Length = sizeof(name) - sizeof(wchar_t);
        uname.MaximumLength = sizeof(name);

        auto fn = reinterpret_cast<unsigned char(__stdcall*)(void*)>(
            MmGetSystemRoutineAddress(&uname));
        if (!fn)
            return false;

        wchar_t pname[] = L"PsGetCurrentProcess";
        UNICODE_STRING upname;
        upname.Buffer = pname;
        upname.Length = sizeof(pname) - sizeof(wchar_t);
        upname.MaximumLength = sizeof(pname);

        auto get_proc = reinterpret_cast<void*(__stdcall*)()>(
            MmGetSystemRoutineAddress(&upname));
        if (!get_proc)
            return false;

        void* process = get_proc();
        if (!process)
            return false;

        return fn(process) != 0;
    } __except (1) {
        return false;
    }
}

KC_NOINLINE inline void take_response() {
#if KC_ANTI_DEBUG_RESPONSE == 1
    KeBugCheck(0x000000E2);
#elif KC_ANTI_DEBUG_RESPONSE == 2
    volatile uint8_t* sp = reinterpret_cast<volatile uint8_t*>(&sp);
    for (int i = 0; i < 4096; ++i)
        sp[i] = 0;
#else
    // response disabled
#endif
}

#endif // KC_ENABLE_IMPORT_HIDING

// shared implementations (same for both paths)

// alternate path: read from KUSER_SHARED_DATA directly (no imports needed)
KC_NOINLINE inline bool check_shared_user_data() {
    __try {
        auto* ptr = reinterpret_cast<volatile uint8_t*>(
            kuser_shared_data_addr + kd_debugger_enabled_offset);
        return *ptr != 0;
    } __except (1) {
        return false;
    }
}

// hardware breakpoint detection via DR7 stub
KC_NOINLINE inline bool check_hardware_breakpoints() {
    __try {
        // check local and global enable bits for DR0-DR3
#if defined(_M_X64) || defined(_M_AMD64)
        uint64_t dr7 = __readdr(7);
        return (dr7 & 0xFFull) != 0;
#else
        return false;
#endif
    } __except (1) {
        return false;
    }
}

// RDTSC delta timing - detects single-stepping
KC_NOINLINE inline bool check_rdtsc_timing() {
    __try {
        volatile uint64_t dummy = 0;
        uint64_t t1 = __rdtsc();

        dummy = dummy + 1;
        dummy = dummy ^ 0x55;
        dummy = dummy + 1;
        dummy = dummy ^ 0xAA;
        dummy = dummy + 1;
        dummy = dummy ^ 0xFF;
        dummy = dummy + 1;

        uint64_t t2 = __rdtsc();
        return (t2 - t1) > rdtsc_threshold;
    } __except (1) {
        return false;
    }
}

KC_FORCEINLINE bool detect_kernel_debugger() {
    return check_kd_enabled() || check_kd_not_present() || check_shared_user_data();
}

KC_NOINLINE inline bool is_debugged() {
    if (detect_kernel_debugger())
        return true;
    if (check_rdtsc_timing())
        return true;
    if (check_hardware_breakpoints())
        return true;
    if (check_process_debugged())
        return true;
    return false;
}

} // namespace detail

} // namespace security
} // namespace kernelcloak

#define KC_ANTI_DEBUG() \
    do { \
        if (::kernelcloak::security::detail::is_debugged()) { \
            ::kernelcloak::security::detail::take_response(); \
        } \
    } while (0)

#define KC_IS_DEBUGGED() \
    (::kernelcloak::security::detail::is_debugged())

#define KC_HAS_HWBP() \
    (::kernelcloak::security::detail::check_hardware_breakpoints())

#define KC_TIMING_CHECK() \
    (::kernelcloak::security::detail::check_rdtsc_timing())

#define KC_DETECT_KERNEL_DBG() \
    (::kernelcloak::security::detail::detect_kernel_debugger())

#else // KC_ENABLE_ANTI_DEBUG disabled

#define KC_ANTI_DEBUG()         do {} while (0)
#define KC_IS_DEBUGGED()        (false)
#define KC_HAS_HWBP()           (false)
#define KC_TIMING_CHECK()       (false)
#define KC_DETECT_KERNEL_DBG()  (false)

#endif // KC_ENABLE_ANTI_DEBUG

