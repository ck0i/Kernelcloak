#pragma once
#include "../config.h"
#include "../core/types.h"

#if KC_ENABLE_BOOLEAN_OBFUSCATION

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace kernelcloak {
namespace obfuscation {
namespace detail {

// opaque predicates - each is always true but not provable by the compiler
// volatile reads and intrinsics prevent MSVC /O2 from seeing through them

// rdtsc LSB | 1 is always odd
KC_NOINLINE inline bool opaque_true_0() {
    volatile unsigned __int64 tsc = __rdtsc();
    return (tsc | 1) & 1;
}

// stack address is never null
KC_NOINLINE inline bool opaque_true_1() {
    volatile int anchor = 0;
    volatile uintptr_t addr = reinterpret_cast<uintptr_t>(&anchor);
    return addr != 0;
}

// mathematical invariant: x*(x+1) is always even
KC_NOINLINE inline bool opaque_true_2() {
    volatile uint32_t x = static_cast<uint32_t>(__rdtsc());
    volatile uint32_t product = x * (x + 1);
    return (product & 1) == 0;
}

// (x | ~x) == ~0 for any x
KC_NOINLINE inline bool opaque_true_3() {
    volatile uint32_t x = static_cast<uint32_t>(__rdtsc());
    volatile uint32_t result = x | ~x;
    return result == ~static_cast<uint32_t>(0);
}

// x^x is always 0
KC_NOINLINE inline bool opaque_true_4() {
    volatile uint32_t x = static_cast<uint32_t>(__rdtsc());
    volatile uint32_t result = x ^ x;
    return result == 0;
}

// opaque false predicates - always false but not obvious

// rdtsc can't return exactly 0 in practice, but even if it could, &1 after |1 prevents it
KC_NOINLINE inline bool opaque_false_0() {
    volatile unsigned __int64 tsc = __rdtsc();
    return ((tsc | 1) & 1) == 0;
}

// stack is never at address 0
KC_NOINLINE inline bool opaque_false_1() {
    volatile int anchor = 0;
    volatile uintptr_t addr = reinterpret_cast<uintptr_t>(&anchor);
    return addr == 0;
}

// x*(x+1) is always even, so odd check is always false
KC_NOINLINE inline bool opaque_false_2() {
    volatile uint32_t x = static_cast<uint32_t>(__rdtsc());
    volatile uint32_t product = x * (x + 1);
    return (product & 1) != 0;
}

// variant selectors
template<int N>
struct opaque_true_selector;

template<> struct opaque_true_selector<0> { static KC_FORCEINLINE bool get() { return opaque_true_0(); } };
template<> struct opaque_true_selector<1> { static KC_FORCEINLINE bool get() { return opaque_true_1(); } };
template<> struct opaque_true_selector<2> { static KC_FORCEINLINE bool get() { return opaque_true_2(); } };
template<> struct opaque_true_selector<3> { static KC_FORCEINLINE bool get() { return opaque_true_3(); } };
template<> struct opaque_true_selector<4> { static KC_FORCEINLINE bool get() { return opaque_true_4(); } };

template<int N>
struct opaque_false_selector;

template<> struct opaque_false_selector<0> { static KC_FORCEINLINE bool get() { return opaque_false_0(); } };
template<> struct opaque_false_selector<1> { static KC_FORCEINLINE bool get() { return opaque_false_1(); } };
template<> struct opaque_false_selector<2> { static KC_FORCEINLINE bool get() { return opaque_false_2(); } };

// boolean wrapping - combines expression with opaque predicate
template<int Variant>
KC_FORCEINLINE bool wrap_bool(bool expr) {
    // expr AND opaque_true - result is expr but harder to analyze
    return expr & opaque_true_selector<Variant>::get();
}

} // namespace detail
} // namespace obfuscation
} // namespace kernelcloak

// each macro site gets a unique variant via __COUNTER__
#define KC_TRUE \
    (::kernelcloak::obfuscation::detail::opaque_true_selector< \
        static_cast<int>((__COUNTER__ * 0x45D9F3Bu ^ __LINE__) % 5)>::get())

#define KC_FALSE \
    (::kernelcloak::obfuscation::detail::opaque_false_selector< \
        static_cast<int>((__COUNTER__ * 0x45D9F3Bu ^ __LINE__) % 3)>::get())

#define KC_BOOL(expr) \
    (::kernelcloak::obfuscation::detail::wrap_bool< \
        static_cast<int>((__COUNTER__ * 0x45D9F3Bu ^ __LINE__) % 5)>( \
        static_cast<bool>(expr)))

#else // KC_ENABLE_BOOLEAN_OBFUSCATION disabled

#define KC_TRUE  (true)
#define KC_FALSE (false)
#define KC_BOOL(expr) (static_cast<bool>(expr))

#endif // KC_ENABLE_BOOLEAN_OBFUSCATION
