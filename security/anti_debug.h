#pragma once
#include "../config.h"
#include "../core/types.h"
#include "../core/memory.h"
#include "../crypto/hash.h"

#if KC_ENABLE_ANTI_DEBUG

#if !defined(_NTDDK_) && !defined(_WDMDDK_)
// forward declarations - guarded to avoid redefinition across security headers
extern "C" {
    extern unsigned char* KdDebuggerEnabled;
    extern unsigned char* KdDebuggerNotPresent;

#ifndef _KC_LARGE_INTEGER_DEFINED
#define _KC_LARGE_INTEGER_DEFINED
    struct _LARGE_INTEGER {
        union {
            struct { unsigned long LowPart; long HighPart; };
            __int64 QuadPart;
        };
    };
    using LARGE_INTEGER = _LARGE_INTEGER;
#endif

    LARGE_INTEGER __stdcall KeQueryPerformanceCounter(LARGE_INTEGER* PerformanceFrequency);
    void __stdcall KeBugCheck(unsigned long BugCheckCode);

#ifndef _KC_UNICODE_STRING_DEFINED
#define _KC_UNICODE_STRING_DEFINED
    struct _UNICODE_STRING {
        unsigned short Length;
        unsigned short MaximumLength;
        wchar_t* Buffer;
    };
    using UNICODE_STRING = _UNICODE_STRING;
#endif

    void* __stdcall MmGetSystemRoutineAddress(UNICODE_STRING* SystemRoutineName);
    unsigned char __stdcall MmIsAddressValid(void* VirtualAddress);
}
#endif

extern "C" {
    unsigned __int64 __rdtsc();
}

#pragma intrinsic(__rdtsc)

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

KC_NOINLINE bool check_kd_enabled() {
    __try {
        return KdDebuggerEnabled && *KdDebuggerEnabled != 0;
    } __except (1) {
        return false;
    }
}

// KdDebuggerNotPresent == FALSE means debugger IS present
KC_NOINLINE bool check_kd_not_present() {
    __try {
        return KdDebuggerNotPresent && *KdDebuggerNotPresent == 0;
    } __except (1) {
        return false;
    }
}

// alternate path: read from KUSER_SHARED_DATA directly
KC_NOINLINE bool check_shared_user_data() {
    __try {
        auto* ptr = reinterpret_cast<volatile uint8_t*>(
            kuser_shared_data_addr + kd_debugger_enabled_offset);
        return *ptr != 0;
    } __except (1) {
        return false;
    }
}

// hardware breakpoint detection
// MSVC x64 has no inline asm and no __readdr intrinsic, so we can't directly
// read DR0-DR7. we use an allocate-and-execute approach: copy a small
// "mov rax, dr7; ret" stub into executable pool memory and call it.
// DR7 bits 0,2,4,6 (local enable) and 1,3,5,7 (global enable) indicate
// active hardware breakpoints on DR0-DR3.
KC_NOINLINE bool check_hardware_breakpoints() {
    __try {
        // 0F 21 F8 = mov rax, dr7
        // C3       = ret
        static constexpr uint8_t stub[] = { 0x0F, 0x21, 0xF8, 0xC3 };

        // allocate executable non-paged memory
        auto* code = static_cast<uint8_t*>(
            core::kc_pool_alloc(sizeof(stub)));
        if (!code)
            return false;

        core::kc_memcpy(code, stub, sizeof(stub));

        using read_dr7_fn = uint64_t(*)();
        auto fn = reinterpret_cast<read_dr7_fn>(code);

        uint64_t dr7 = fn();

        core::kc_pool_free(code);

        // check local and global enable bits for DR0-DR3
        // bits: L0(0), G0(1), L1(2), G1(3), L2(4), G2(5), L3(6), G3(7)
        return (dr7 & 0xFF) != 0;
    } __except (1) {
        return false;
    }
}

// RDTSC delta timing - detects single-stepping
KC_NOINLINE bool check_rdtsc_timing() {
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

// KeQueryPerformanceCounter timing variant
KC_NOINLINE bool check_perf_counter_timing() {
    __try {
        LARGE_INTEGER freq;
        LARGE_INTEGER t1 = KeQueryPerformanceCounter(&freq);

        volatile uint64_t dummy = 0;
        for (int i = 0; i < 10; ++i)
            dummy += i;

        LARGE_INTEGER t2 = KeQueryPerformanceCounter(nullptr);
        int64_t delta = t2.QuadPart - t1.QuadPart;

        // 50us threshold
        int64_t threshold = freq.QuadPart / 20000;
        if (threshold < 50) threshold = 50;

        return delta > threshold;
    } __except (1) {
        return false;
    }
}

// dynamically resolve PsIsProcessBeingDebugged
// IRQL: PASSIVE_LEVEL only
KC_NOINLINE bool check_process_debugged() {
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

KC_FORCEINLINE bool detect_kernel_debugger() {
    return check_kd_enabled() || check_kd_not_present() || check_shared_user_data();
}

KC_NOINLINE bool is_debugged() {
    if (detect_kernel_debugger())
        return true;
    if (check_rdtsc_timing())
        return true;
    if (check_process_debugged())
        return true;
    return false;
}

KC_NOINLINE void take_response() {
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
