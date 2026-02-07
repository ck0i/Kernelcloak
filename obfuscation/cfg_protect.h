#pragma once
#include "../config.h"
#include "../core/types.h"
#include "boolean.h"
#include "control_flow.h"

#if KC_ENABLE_CONTROL_FLOW

namespace kernelcloak {
namespace obfuscation {
namespace detail {

// lightweight protection state - volatile to prevent optimization
struct protect_guard {
    volatile uint32_t state;

    KC_FORCEINLINE protect_guard()
        : state(static_cast<uint32_t>(__rdtsc()) | 1) {}

    KC_FORCEINLINE ~protect_guard() {
        // exit barrier - opaque check that always passes
        volatile uint32_t s = state;
        if ((s | 1) == 0) {
            // unreachable but compiler can't prove it
            __nop();
        }
        state = 0;
    }

    KC_FORCEINLINE void checkpoint() {
        volatile uint32_t s = state;
        state = s ^ 0x9E3779B9u;
    }
};

} // namespace detail
} // namespace obfuscation
} // namespace kernelcloak

// KC_PROTECT - wraps a code body in lightweight CFG protection
// injects opaque predicates at entry/exit, junk between operations
// usage: auto result = KC_PROTECT(int, { /* body that produces int */ 42; });
#define KC_PROTECT(ret_type, body) \
    [&]() -> ret_type { \
        ::kernelcloak::obfuscation::detail::protect_guard _kc_pg; \
        KC_JUNK(); \
        if (KC_FALSE) { \
            volatile ::kernelcloak::uint32_t _kc_dead = 0xBADu; \
            (void)_kc_dead; \
        } \
        _kc_pg.checkpoint(); \
        ret_type _kc_result = [&]() -> ret_type body (); \
        _kc_pg.checkpoint(); \
        KC_JUNK(); \
        return _kc_result; \
    }()

// KC_PROTECT_VOID - same as KC_PROTECT but for void return type
#define KC_PROTECT_VOID(body) \
    [&]() { \
        ::kernelcloak::obfuscation::detail::protect_guard _kc_pg; \
        KC_JUNK(); \
        if (KC_FALSE) { \
            volatile ::kernelcloak::uint32_t _kc_dead = 0xBADu; \
            (void)_kc_dead; \
        } \
        _kc_pg.checkpoint(); \
        [&]() body (); \
        _kc_pg.checkpoint(); \
        KC_JUNK(); \
    }()

#else // KC_ENABLE_CONTROL_FLOW disabled

#define KC_PROTECT(ret_type, body) \
    [&]() -> ret_type body ()

#define KC_PROTECT_VOID(body) \
    [&]() body ()

#endif // KC_ENABLE_CONTROL_FLOW
