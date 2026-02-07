#pragma once
#include "../config.h"
#include "../core/types.h"
#include "boolean.h"

#if KC_ENABLE_CONTROL_FLOW

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace kernelcloak {
namespace obfuscation {
namespace detail {

// junk instruction generation that survives DCE
// volatile writes ensure the compiler can't eliminate them

KC_NOINLINE inline void junk_volatile_write() {
    volatile uint32_t sink = __rdtsc() & 0xFFu;
    (void)sink;
}

KC_NOINLINE inline void junk_nop_sled() {
    __nop();
    __nop();
    __nop();
    volatile int x = 1;
    x = x ^ x;
    (void)x;
}

KC_NOINLINE inline void junk_arithmetic() {
    volatile uint32_t a = static_cast<uint32_t>(__rdtsc());
    volatile uint32_t b = a * 0x9E3779B9u;
    volatile uint32_t c = b ^ (a >> 16);
    volatile uint32_t d = c + a;
    (void)d;
}

KC_NOINLINE inline void junk_stack_noise() {
    volatile uint8_t garbage[16];
    volatile uint32_t seed = static_cast<uint32_t>(__rdtsc());
    for (int i = 0; i < 16; ++i) {
        garbage[i] = static_cast<uint8_t>(seed >> (i & 3));
    }
    (void)garbage;
}

// larger junk flow block with fake branching
KC_NOINLINE inline void junk_flow_block() {
    volatile uint32_t state = static_cast<uint32_t>(__rdtsc());
    volatile uint32_t counter = 0;

    // fake state machine - always terminates in 1 iteration
    // but compiler can't prove it statically
    do {
        state = state * 0x45D9F3Bu + 0x1B873593u;
        counter += 1;

        volatile uint32_t temp = state ^ counter;
        if (temp & 0x80000000u) {
            state = state >> 1;
        } else {
            state = state ^ 0xDEADBEEFu;
        }
    } while (counter == 0); // always false after first iteration

    volatile uint32_t sink = state;
    (void)sink;
}

// junk selector
template<int N>
struct junk_selector;

template<> struct junk_selector<0> { static KC_FORCEINLINE void emit() { junk_volatile_write(); } };
template<> struct junk_selector<1> { static KC_FORCEINLINE void emit() { junk_nop_sled(); } };
template<> struct junk_selector<2> { static KC_FORCEINLINE void emit() { junk_arithmetic(); } };
template<> struct junk_selector<3> { static KC_FORCEINLINE void emit() { junk_stack_noise(); } };

} // namespace detail
} // namespace obfuscation
} // namespace kernelcloak

// if/else with opaque predicate injection
// condition is wrapped in KC_BOOL and ANDed with an opaque true
#define KC_IF(expr) \
    if (KC_BOOL(expr) & KC_TRUE) {

#define KC_ELSE \
    } else { \
        if (KC_FALSE) { \
            volatile ::kernelcloak::uint32_t _kc_dead = 0xDEADu; \
            (void)_kc_dead; \
        }

#define KC_ENDIF \
    }

// single junk instruction block
#define KC_JUNK() \
    do { \
        ::kernelcloak::obfuscation::detail::junk_selector< \
            static_cast<int>((__COUNTER__ * 0x45D9F3Bu ^ __LINE__) % 4)>::emit(); \
    } while (0)

// larger junk flow block
#define KC_JUNK_FLOW() \
    do { \
        ::kernelcloak::obfuscation::detail::junk_flow_block(); \
    } while (0)

#else // KC_ENABLE_CONTROL_FLOW disabled

#define KC_IF(expr) if (expr) {
#define KC_ELSE    } else {
#define KC_ENDIF   }
#define KC_JUNK()       ((void)0)
#define KC_JUNK_FLOW()  ((void)0)

#endif // KC_ENABLE_CONTROL_FLOW
