#pragma once
#include "../config.h"
#include "types.h"

#pragma warning(push)
#pragma warning(disable: 4307) // integral constant overflow (intentional in hashing)

extern "C" {
    unsigned __int64 __rdtsc();

    __int64 _InterlockedExchangeAdd64(__int64 volatile*, __int64);
    __int64 _InterlockedCompareExchange64(__int64 volatile*, __int64, __int64);
    __int64 _InterlockedExchange64(__int64 volatile*, __int64);
}

#pragma intrinsic(__rdtsc)
#pragma intrinsic(_InterlockedExchangeAdd64)
#pragma intrinsic(_InterlockedCompareExchange64)
#pragma intrinsic(_InterlockedExchange64)

#if !defined(_NTDDK_) && !defined(_WDMDDK_)
// LARGE_INTEGER may already be defined by ntddk.h/wdm.h
#ifndef _LARGE_INTEGER_DEFINED
#define _LARGE_INTEGER_DEFINED
extern "C" {
    typedef union _LARGE_INTEGER {
        struct { unsigned long LowPart; long HighPart; };
        __int64 QuadPart;
    } LARGE_INTEGER, *PLARGE_INTEGER;
}
#endif

extern "C" {
    LARGE_INTEGER __stdcall KeQueryPerformanceCounter(LARGE_INTEGER* PerformanceFrequency);
    unsigned __int64 __stdcall KeQueryInterruptTime();
    void* __stdcall PsGetCurrentProcessId();
    void* __stdcall PsGetCurrentThreadId();
}
#endif

namespace kernelcloak {
namespace detail {

// compile-time seed generation from __TIME__, __COUNTER__, __LINE__
// each macro instantiation site gets different entropy
constexpr uint32_t ct_hash_char(uint32_t hash, char c) {
    return (hash ^ static_cast<uint32_t>(c)) * 0x01000193u;
}

constexpr uint32_t ct_hash_string(const char* str, uint32_t hash = 0x811c9dc5u) {
    return (*str == '\0') ? hash : ct_hash_string(str + 1, ct_hash_char(hash, *str));
}

// xorshift32 - good distribution, fast, small state
constexpr uint32_t xorshift32(uint32_t state) {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

// advance the generator N times for better diffusion from initial seed
constexpr uint32_t ct_advance(uint32_t seed, uint32_t rounds) {
    for (uint32_t i = 0; i < rounds; ++i) {
        seed = xorshift32(seed);
    }
    return seed;
}

// seed combiner - mixes __TIME__, __COUNTER__, __LINE__ into a single seed
// every call site gets unique entropy because __COUNTER__ increments per TU
// and __LINE__ differs per call site
constexpr uint32_t ct_make_seed(const char* time, uint32_t counter, uint32_t line) {
    uint32_t h = ct_hash_string(time);
    h ^= counter * 0x9e3779b9u;        // golden ratio mixing
    h = xorshift32(h);
    h ^= line * 0x517cc1b7u;           // another prime
    h = xorshift32(h);
    // ensure non-zero (xorshift needs nonzero state)
    return h ? h : 0xdeadbeef;
}

// compile-time random with parameterized generation count
// each call uses __COUNTER__ to produce a different sequence position
constexpr uint32_t ct_random_impl(uint32_t seed, uint32_t generation) {
    return ct_advance(seed, generation + 3);
}

// range clamping for compile-time
constexpr uint32_t ct_range(uint32_t val, uint32_t min_val, uint32_t max_val) {
    return min_val + (val % (max_val - min_val + 1));
}

// fallback seed generation without __TIME__ (WDK builds may undefine it)
constexpr uint32_t ct_make_seed(uint32_t counter, uint32_t line) {
    uint32_t h = 0x811c9dc5u;
    h ^= counter * 0x9e3779b9u;
    h = xorshift32(h);
    h ^= line * 0x517cc1b7u;
    h = xorshift32(h);
    return h ? h : 0xdeadbeef;
}

KC_FORCEINLINE uint64_t splitmix64(uint64_t x) noexcept {
    x += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
}

} // namespace detail

namespace core {

// compile-time PRNG - constexpr-capable wrapper around xorshift32
// used by crypto primitives for key generation at compile time
struct ct_random {
    uint32_t state;

    constexpr explicit ct_random(uint32_t seed) noexcept
        : state(seed ? seed : 0xdeadbeef) {}

    constexpr uint32_t next() noexcept {
        state = ::kernelcloak::detail::xorshift32(state);
        return state;
    }
};

// runtime PRNG state - lock-free splitmix64 backed by an interlocked counter.
// seeded from multiple hardware entropy sources, and lazily self-seeds if
// kc_random_init() wasn't called.
struct RuntimePrng {
    volatile __int64 state;

    KC_NOINLINE void seed() noexcept {
        // gather entropy from multiple uncorrelated sources
        uint64_t tsc = __rdtsc();

        LARGE_INTEGER freq;
        LARGE_INTEGER perf = KeQueryPerformanceCounter(&freq);

        uint64_t interrupt_time = KeQueryInterruptTime();

        auto pid = reinterpret_cast<uint64_t>(PsGetCurrentProcessId());
        auto tid = reinterpret_cast<uint64_t>(PsGetCurrentThreadId());

        // stack/pool KASLR entropy - address of local variable
        uint64_t stack_entropy = reinterpret_cast<uint64_t>(&tsc);

        // mix all sources into a single 64-bit seed
        uint64_t seed = tsc ^ (perf.QuadPart << 17) ^ interrupt_time;
        seed ^= (pid << 32) | tid;
        seed ^= stack_entropy;
        seed ^= static_cast<uint64_t>(freq.QuadPart) << 23;

        if (!seed) {
            seed = 0x853c49e6748fea9bull;
        }

        _InterlockedExchange64(&state, static_cast<__int64>(seed));
    }

    KC_FORCEINLINE uint64_t next64() noexcept {
        // lazy seed - avoid deterministic all-zero startup
        if (_InterlockedCompareExchange64(&state, 0, 0) == 0) {
            seed();
        }

        constexpr uint64_t inc = 0x9E3779B97F4A7C15ull;
        uint64_t x = static_cast<uint64_t>(_InterlockedExchangeAdd64(
            &state, static_cast<__int64>(inc)));
        return ::kernelcloak::detail::splitmix64(x);
    }

    KC_FORCEINLINE uint32_t next32() noexcept {
        return static_cast<uint32_t>(next64());
    }

    KC_FORCEINLINE uint32_t range(uint32_t min_val, uint32_t max_val) noexcept {
        if (min_val >= max_val) return min_val;
        return min_val + (next32() % (max_val - min_val + 1));
    }
};

// global runtime PRNG instance
// callers can call kc_random_init() once early for stronger entropy, but
// kc_random_rt() will lazily seed on first use if needed.
inline RuntimePrng& kc_global_prng() noexcept {
    // non-paged static - safe at DISPATCH_LEVEL
    static RuntimePrng instance = {};
    return instance;
}

KC_FORCEINLINE void kc_random_init() noexcept {
    kc_global_prng().seed();
}

KC_FORCEINLINE uint32_t kc_random_rt() noexcept {
    return kc_global_prng().next32();
}

KC_FORCEINLINE uint32_t kc_random_rt_range(uint32_t min_val, uint32_t max_val) noexcept {
    return kc_global_prng().range(min_val, max_val);
}

} // namespace core
} // namespace kernelcloak

// compile-time random macros
// each invocation gets unique entropy from __COUNTER__ and __LINE__
// the seed is built from __TIME__ (per-TU), __COUNTER__ (per-macro-expansion), __LINE__ (per-line)
// __TIME__ may be undefined in WDK/deterministic builds
#ifdef __TIME__
#define KC_CT_SEED_() \
    ::kernelcloak::detail::ct_make_seed(__TIME__, __COUNTER__, __LINE__)
#else
#define KC_CT_SEED_() \
    ::kernelcloak::detail::ct_make_seed(__COUNTER__, __LINE__)
#endif

// primary compile-time random value
#define KC_RANDOM_CT() \
    (::kernelcloak::detail::ct_random_impl(KC_CT_SEED_(), __COUNTER__))

// compile-time random in [min, max] range
#define KC_RAND_CT(min_val, max_val) \
    (::kernelcloak::detail::ct_range(KC_RANDOM_CT(), \
        static_cast<::kernelcloak::uint32_t>(min_val), \
        static_cast<::kernelcloak::uint32_t>(max_val)))

// runtime random
#define KC_RANDOM_RT() \
    (::kernelcloak::core::kc_random_rt())

#define KC_RAND_RT(min_val, max_val) \
    (::kernelcloak::core::kc_random_rt_range( \
        static_cast<::kernelcloak::uint32_t>(min_val), \
        static_cast<::kernelcloak::uint32_t>(max_val)))

#pragma warning(pop)
