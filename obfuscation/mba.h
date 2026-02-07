#pragma once
#include "../config.h"
#include "../core/types.h"

#if KC_ENABLE_MBA

namespace kernelcloak {
namespace obfuscation {
namespace detail {

// mixed boolean arithmetic decompositions
// each operation has multiple equivalent forms selected by compile-time Variant param

// a + b decompositions
template<typename T, int Variant>
struct mba_add;

// (a ^ b) + 2*(a & b)
template<typename T>
struct mba_add<T, 0> {
    static KC_FORCEINLINE T compute(T a, T b) {
        volatile T va = a, vb = b;
        T x = va ^ vb;
        T y = va & vb;
        return x + (y << 1);
    }
};

// (a | b) + (a & b)
template<typename T>
struct mba_add<T, 1> {
    static KC_FORCEINLINE T compute(T a, T b) {
        volatile T va = a, vb = b;
        return (va | vb) + (va & vb);
    }
};

// ((a & b) << 1) + (a ^ b) + (0 & ~0) -- noise term cancels
template<typename T>
struct mba_add<T, 2> {
    static KC_FORCEINLINE T compute(T a, T b) {
        volatile T va = a, vb = b;
        T noise = static_cast<T>(0) & ~static_cast<T>(0);
        return ((va & vb) << 1) + (va ^ vb) + noise;
    }
};

// a - b decompositions
template<typename T, int Variant>
struct mba_sub;

// a + (~b) + 1
template<typename T>
struct mba_sub<T, 0> {
    static KC_FORCEINLINE T compute(T a, T b) {
        volatile T va = a, vb = b;
        return va + (~vb) + static_cast<T>(1);
    }
};

// (a ^ (~b)) + ((~(a | b) + (a & (~b))) << 1) -- simplified to: (a ^ ~b) - ~(a|b)*2 + (a&~b)*2
// actually just: (a & ~b) - (~a & b) which is a - b
template<typename T>
struct mba_sub<T, 1> {
    static KC_FORCEINLINE T compute(T a, T b) {
        volatile T va = a, vb = b;
        return (va & ~vb) - (~va & vb);
    }
};

// (a ^ b) - ((~a & b) << 1)
template<typename T>
struct mba_sub<T, 2> {
    static KC_FORCEINLINE T compute(T a, T b) {
        volatile T va = a, vb = b;
        return (va ^ vb) - ((~va & vb) << 1);
    }
};

// a & b decompositions
template<typename T, int Variant>
struct mba_and;

// (a + b - (a ^ b)) >> 1
template<typename T>
struct mba_and<T, 0> {
    static KC_FORCEINLINE T compute(T a, T b) {
        volatile T va = a, vb = b;
        // unsigned shift for correctness
        using U = typename kernelcloak::detail::make_unsigned<T>::type;
        return static_cast<T>((static_cast<U>(va) + static_cast<U>(vb)
            - static_cast<U>(va ^ vb)) >> 1);
    }
};

// ~(~a | ~b) -- de morgan
template<typename T>
struct mba_and<T, 1> {
    static KC_FORCEINLINE T compute(T a, T b) {
        volatile T va = a, vb = b;
        return ~(~va | ~vb);
    }
};

// ((a ^ b) ^ b) & b -- simplifies to a & b since (a^b)^b == a
template<typename T>
struct mba_and<T, 2> {
    static KC_FORCEINLINE T compute(T a, T b) {
        volatile T va = a, vb = b;
        T t = (va ^ vb) ^ vb;
        return t & vb;
    }
};

// a | b decompositions
template<typename T, int Variant>
struct mba_or;

// (a ^ b) + (a & b)  -- standard MBA identity
template<typename T>
struct mba_or<T, 0> {
    static KC_FORCEINLINE T compute(T a, T b) {
        volatile T va = a, vb = b;
        return (va ^ vb) + (va & vb);
    }
};

// ~(~a & ~b) -- de morgan
template<typename T>
struct mba_or<T, 1> {
    static KC_FORCEINLINE T compute(T a, T b) {
        volatile T va = a, vb = b;
        return ~(~va & ~vb);
    }
};

// ((a ^ b) | b) -- since (a^b)|b == a|b
template<typename T>
struct mba_or<T, 2> {
    static KC_FORCEINLINE T compute(T a, T b) {
        volatile T va = a, vb = b;
        return (va ^ vb) | vb;
    }
};

// a ^ b decompositions
template<typename T, int Variant>
struct mba_xor;

// (a | b) - (a & b)
template<typename T>
struct mba_xor<T, 0> {
    static KC_FORCEINLINE T compute(T a, T b) {
        volatile T va = a, vb = b;
        return (va | vb) - (va & vb);
    }
};

// (a & ~b) | (~a & b)
template<typename T>
struct mba_xor<T, 1> {
    static KC_FORCEINLINE T compute(T a, T b) {
        volatile T va = a, vb = b;
        return (va & ~vb) | (~va & vb);
    }
};

// ~(~(a & ~b) & ~(~a & b)) -- nested de morgan
template<typename T>
struct mba_xor<T, 2> {
    static KC_FORCEINLINE T compute(T a, T b) {
        volatile T va = a, vb = b;
        return ~(~(va & ~vb) & ~(~va & vb));
    }
};

// negation: -a = ~a + 1, with MBA wrapping
template<typename T, int Variant>
struct mba_neg;

template<typename T>
struct mba_neg<T, 0> {
    static KC_FORCEINLINE T compute(T a) {
        volatile T va = a;
        return (~va) + static_cast<T>(1);
    }
};

template<typename T>
struct mba_neg<T, 1> {
    static KC_FORCEINLINE T compute(T a) {
        volatile T va = a;
        // -a = (a ^ -1) + 1 = ~a + 1, but expressed differently
        return (va ^ static_cast<T>(-1)) + static_cast<T>(1);
    }
};

template<typename T>
struct mba_neg<T, 2> {
    static KC_FORCEINLINE T compute(T a) {
        volatile T va = a;
        // -a = ~a + 1 = (~a | 0) + (1 & ~0) -- noise wrapping
        T inv = ~va;
        T noise = static_cast<T>(1) & ~static_cast<T>(0);
        return (inv | static_cast<T>(0)) + noise;
    }
};

} // namespace detail
} // namespace obfuscation
} // namespace kernelcloak

// variant selection via __COUNTER__ mod 3
#define KC_MBA_VARIANT() ((__COUNTER__ * 0x45D9F3Bu ^ __LINE__) % 3)

#define KC_MBA(x) (x)

#define KC_ADD(a, b) \
    [&]() -> decltype((a) + (b)) { \
        using _kc_T = decltype((a) + (b)); \
        constexpr int _kc_v = static_cast<int>((__COUNTER__ * 0x45D9F3Bu ^ __LINE__) % 3); \
        return ::kernelcloak::obfuscation::detail::mba_add<_kc_T, _kc_v>::compute( \
            static_cast<_kc_T>(a), static_cast<_kc_T>(b)); \
    }()

#define KC_SUB(a, b) \
    [&]() -> decltype((a) - (b)) { \
        using _kc_T = decltype((a) - (b)); \
        constexpr int _kc_v = static_cast<int>((__COUNTER__ * 0x45D9F3Bu ^ __LINE__) % 3); \
        return ::kernelcloak::obfuscation::detail::mba_sub<_kc_T, _kc_v>::compute( \
            static_cast<_kc_T>(a), static_cast<_kc_T>(b)); \
    }()

#define KC_AND(a, b) \
    [&]() -> decltype((a) & (b)) { \
        using _kc_T = decltype((a) & (b)); \
        constexpr int _kc_v = static_cast<int>((__COUNTER__ * 0x45D9F3Bu ^ __LINE__) % 3); \
        return ::kernelcloak::obfuscation::detail::mba_and<_kc_T, _kc_v>::compute( \
            static_cast<_kc_T>(a), static_cast<_kc_T>(b)); \
    }()

#define KC_OR(a, b) \
    [&]() -> decltype((a) | (b)) { \
        using _kc_T = decltype((a) | (b)); \
        constexpr int _kc_v = static_cast<int>((__COUNTER__ * 0x45D9F3Bu ^ __LINE__) % 3); \
        return ::kernelcloak::obfuscation::detail::mba_or<_kc_T, _kc_v>::compute( \
            static_cast<_kc_T>(a), static_cast<_kc_T>(b)); \
    }()

#define KC_XOR(a, b) \
    [&]() -> decltype((a) ^ (b)) { \
        using _kc_T = decltype((a) ^ (b)); \
        constexpr int _kc_v = static_cast<int>((__COUNTER__ * 0x45D9F3Bu ^ __LINE__) % 3); \
        return ::kernelcloak::obfuscation::detail::mba_xor<_kc_T, _kc_v>::compute( \
            static_cast<_kc_T>(a), static_cast<_kc_T>(b)); \
    }()

#define KC_NEG(a) \
    [&]() -> decltype(-(a)) { \
        using _kc_T = decltype(-(a)); \
        constexpr int _kc_v = static_cast<int>((__COUNTER__ * 0x45D9F3Bu ^ __LINE__) % 3); \
        return ::kernelcloak::obfuscation::detail::mba_neg<_kc_T, _kc_v>::compute( \
            static_cast<_kc_T>(a)); \
    }()

#else // KC_ENABLE_MBA disabled

#define KC_MBA(x)     (x)
#define KC_ADD(a, b)  ((a) + (b))
#define KC_SUB(a, b)  ((a) - (b))
#define KC_AND(a, b)  ((a) & (b))
#define KC_OR(a, b)   ((a) | (b))
#define KC_XOR(a, b)  ((a) ^ (b))
#define KC_NEG(a)     (-(a))

#endif // KC_ENABLE_MBA
