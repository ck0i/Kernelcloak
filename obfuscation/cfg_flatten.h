#pragma once
#include "../config.h"
#include "../core/types.h"

#if KC_ENABLE_CFG_FLATTEN

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace kernelcloak {
namespace obfuscation {
namespace detail {

// compile-time FNV-1a for block label hashing (standalone to avoid hash.h dependency)
constexpr uint32_t cfg_hash(const char* str) {
    uint32_t h = 0x811c9dc5u;
    while (*str) {
        h ^= static_cast<uint32_t>(*str++);
        h *= 0x01000193u;
    }
    return h;
}

// dead block junk that uses volatile to survive DCE
KC_NOINLINE inline void cfg_dead_code() {
    volatile uint32_t x = 0xDEADC0DEu;
    volatile uint32_t y = x ^ 0xBAADF00Du;
    volatile uint32_t z = y * 0x1337u;
    (void)z;
    __nop();
}

} // namespace detail
} // namespace obfuscation
} // namespace kernelcloak

// state encryption key derived from __COUNTER__ at function definition site
// each flattened function gets a unique XOR key for state transitions

#define KC_FLAT_FUNC(ret_type, name, ...) \
    ret_type name(__VA_ARGS__) { \
        constexpr ::kernelcloak::uint32_t _kc_flat_key = \
            static_cast<::kernelcloak::uint32_t>( \
                (__COUNTER__ + 1) * 0x45D9F3Bu ^ 0xCC9E2D51u); \
        volatile ::kernelcloak::uint32_t _kc_state = \
            ::kernelcloak::obfuscation::detail::cfg_hash("__entry") ^ _kc_flat_key; \
        volatile bool _kc_running = true; \
        ret_type _kc_ret_val{}; \
        while (_kc_running) { \
            ::kernelcloak::uint32_t _kc_decoded = _kc_state ^ _kc_flat_key; \
            switch (_kc_decoded) { \
            case ::kernelcloak::obfuscation::detail::cfg_hash("__entry"):

#define KC_FLAT_BLOCK(label) \
                break; \
            case ::kernelcloak::obfuscation::detail::cfg_hash(#label):

#define KC_FLAT_GOTO(label) \
                _kc_state = ::kernelcloak::obfuscation::detail::cfg_hash(#label) ^ _kc_flat_key; \
                break;

#define KC_FLAT_IF(cond, true_label, false_label) \
                if (cond) { \
                    _kc_state = ::kernelcloak::obfuscation::detail::cfg_hash(#true_label) ^ _kc_flat_key; \
                } else { \
                    _kc_state = ::kernelcloak::obfuscation::detail::cfg_hash(#false_label) ^ _kc_flat_key; \
                } \
                break;

#define KC_FLAT_RETURN(value) \
                _kc_ret_val = (value); \
                _kc_running = false; \
                break;

// dead blocks injected before the default case
#define KC_FLAT_END() \
                break; \
            case ::kernelcloak::obfuscation::detail::cfg_hash("__dead_0"): \
                ::kernelcloak::obfuscation::detail::cfg_dead_code(); \
                _kc_state = ::kernelcloak::obfuscation::detail::cfg_hash("__dead_1") ^ _kc_flat_key; \
                break; \
            case ::kernelcloak::obfuscation::detail::cfg_hash("__dead_1"): \
                { volatile ::kernelcloak::uint32_t _d = 0xFEEDu; (void)_d; } \
                _kc_state = ::kernelcloak::obfuscation::detail::cfg_hash("__dead_2") ^ _kc_flat_key; \
                break; \
            case ::kernelcloak::obfuscation::detail::cfg_hash("__dead_2"): \
                __nop(); \
                _kc_running = false; \
                break; \
            default: \
                _kc_running = false; \
                break; \
            } \
        } \
        return _kc_ret_val; \
    }

#else // KC_ENABLE_CFG_FLATTEN disabled

// passthrough - these expand to normal function structure
// disabled mode is approximate since CFG flattening fundamentally changes structure
#define KC_FLAT_FUNC(ret_type, name, ...) \
    ret_type name(__VA_ARGS__) { \
        ret_type _kc_ret_val{};

#define KC_FLAT_BLOCK(label)
#define KC_FLAT_GOTO(label)
#define KC_FLAT_IF(cond, true_label, false_label)

#define KC_FLAT_RETURN(value) \
        return (value);

#define KC_FLAT_END() \
        return _kc_ret_val; \
    }

#endif // KC_ENABLE_CFG_FLATTEN
