#pragma once
#include "../config.h"
#include "../core/types.h"
#include "mba.h"

#if KC_ENABLE_VALUE_OBFUSCATION

namespace kernelcloak {
namespace obfuscation {
namespace detail {

// obfuscated comparison helpers
// compute difference through MBA, then test result properties
// volatile intermediates prevent MSVC from simplifying back to cmp

template<typename T>
KC_FORCEINLINE bool obf_eq(T a, T b) {
    volatile T va = a, vb = b;
    // a == b iff (a ^ b) == 0, computed through MBA
    T diff = mba_xor<T, 0>::compute(va, vb);
    volatile T vdiff = diff;
    // cast to unsigned for the or-reduction
    using U = typename kernelcloak::detail::make_unsigned<T>::type;
    volatile U udiff = static_cast<U>(vdiff);
    return udiff == static_cast<U>(0);
}

template<typename T>
KC_FORCEINLINE bool obf_ne(T a, T b) {
    volatile T va = a, vb = b;
    T diff = mba_xor<T, 1>::compute(va, vb);
    volatile T vdiff = diff;
    using U = typename kernelcloak::detail::make_unsigned<T>::type;
    volatile U udiff = static_cast<U>(vdiff);
    return udiff != static_cast<U>(0);
}

template<typename T>
KC_FORCEINLINE bool obf_lt(T a, T b) {
    volatile T va = a, vb = b;
    // a < b iff (a - b) is negative for signed, or borrow for unsigned
    T diff = mba_sub<T, 0>::compute(va, vb);
    volatile T vdiff = diff;
    // check sign bit for signed types, use subtraction borrow for unsigned
    if constexpr (kernelcloak::detail::is_signed<T>::value) {
        return vdiff < static_cast<T>(0);
    } else {
        // for unsigned: a < b iff a - b wrapped (i.e., b > a)
        // use volatile to prevent optimization
        return va < vb ? true : false;
    }
}

template<typename T>
KC_FORCEINLINE bool obf_gt(T a, T b) {
    return obf_lt(b, a);
}

template<typename T>
KC_FORCEINLINE bool obf_le(T a, T b) {
    return !obf_gt(a, b);
}

template<typename T>
KC_FORCEINLINE bool obf_ge(T a, T b) {
    return !obf_lt(a, b);
}

} // namespace detail
} // namespace obfuscation
} // namespace kernelcloak

#define KC_EQ(a, b) \
    [&]() -> bool { \
        using _kc_T = decltype((a) + (b)); \
        return ::kernelcloak::obfuscation::detail::obf_eq<_kc_T>( \
            static_cast<_kc_T>(a), static_cast<_kc_T>(b)); \
    }()

#define KC_NE(a, b) \
    [&]() -> bool { \
        using _kc_T = decltype((a) + (b)); \
        return ::kernelcloak::obfuscation::detail::obf_ne<_kc_T>( \
            static_cast<_kc_T>(a), static_cast<_kc_T>(b)); \
    }()

#define KC_LT(a, b) \
    [&]() -> bool { \
        using _kc_T = decltype((a) + (b)); \
        return ::kernelcloak::obfuscation::detail::obf_lt<_kc_T>( \
            static_cast<_kc_T>(a), static_cast<_kc_T>(b)); \
    }()

#define KC_GT(a, b) \
    [&]() -> bool { \
        using _kc_T = decltype((a) + (b)); \
        return ::kernelcloak::obfuscation::detail::obf_gt<_kc_T>( \
            static_cast<_kc_T>(a), static_cast<_kc_T>(b)); \
    }()

#define KC_LE(a, b) \
    [&]() -> bool { \
        using _kc_T = decltype((a) + (b)); \
        return ::kernelcloak::obfuscation::detail::obf_le<_kc_T>( \
            static_cast<_kc_T>(a), static_cast<_kc_T>(b)); \
    }()

#define KC_GE(a, b) \
    [&]() -> bool { \
        using _kc_T = decltype((a) + (b)); \
        return ::kernelcloak::obfuscation::detail::obf_ge<_kc_T>( \
            static_cast<_kc_T>(a), static_cast<_kc_T>(b)); \
    }()

#else // KC_ENABLE_VALUE_OBFUSCATION disabled

#define KC_EQ(a, b) ((a) == (b))
#define KC_NE(a, b) ((a) != (b))
#define KC_LT(a, b) ((a) <  (b))
#define KC_GT(a, b) ((a) >  (b))
#define KC_LE(a, b) ((a) <= (b))
#define KC_GE(a, b) ((a) >= (b))

#endif // KC_ENABLE_VALUE_OBFUSCATION
