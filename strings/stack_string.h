#pragma once
#include "../config.h"
#include "../core/types.h"

#if KC_ENABLE_STRING_ENCRYPTION

// character-by-character stack construction
// no string literal appears anywhere in the binary - not even encrypted
// each character is XOR'd with a compile-time key and decoded at runtime

namespace kernelcloak {
namespace strings {
namespace detail {

// single obfuscated character - stores XOR'd value as template param
template<typename CharT, CharT C, uint32_t Key, size_t Idx>
struct obfuscated_char {
    static constexpr CharT key_byte() {
        return static_cast<CharT>((Key >> ((Idx % 4) * 8)) ^ (Idx * 0x27D4EB2Du));
    }
    static constexpr CharT encrypted = C ^ key_byte();

    KC_FORCEINLINE static CharT decode() {
        // the volatile prevents the compiler from folding this back to a constant
        volatile CharT enc = encrypted;
        return enc ^ key_byte();
    }
};

} // namespace detail
} // namespace strings
} // namespace kernelcloak

// internal helpers for key generation per macro site
#define KC_STACK_KEY_                                                            \
    (static_cast<::kernelcloak::uint32_t>(                                      \
        (__COUNTER__ + 1) * 0x45D9F3Bu ^                                        \
        __LINE__ * 0x1B873593u ^                                                \
        0xDEADBEEFu                                                             \
    ))

// char-by-char assignment with obfuscation
// expands to: name[0] = decode<char, 'h', key, 0>(); name[1] = ...
#define KC_SC_(name, key, idx, c)                                               \
    name[idx] = ::kernelcloak::strings::detail::obfuscated_char<                \
        char, c, key, idx>::decode()

#define KC_SWC_(name, key, idx, c)                                              \
    name[idx] = ::kernelcloak::strings::detail::obfuscated_char<                \
        wchar_t, c, key, idx>::decode()

// variadic char assignment dispatch
// we need to manually enumerate since C++17 doesn't have __VA_OPT__ reliably
// and fold expressions can't do indexed assignment

#define KC_SC_1(n, k, c0) \
    KC_SC_(n,k,0,c0)
#define KC_SC_2(n, k, c0, c1) \
    KC_SC_1(n,k,c0); KC_SC_(n,k,1,c1)
#define KC_SC_3(n, k, c0, c1, c2) \
    KC_SC_2(n,k,c0,c1); KC_SC_(n,k,2,c2)
#define KC_SC_4(n, k, c0, c1, c2, c3) \
    KC_SC_3(n,k,c0,c1,c2); KC_SC_(n,k,3,c3)
#define KC_SC_5(n, k, c0, c1, c2, c3, c4) \
    KC_SC_4(n,k,c0,c1,c2,c3); KC_SC_(n,k,4,c4)
#define KC_SC_6(n, k, c0, c1, c2, c3, c4, c5) \
    KC_SC_5(n,k,c0,c1,c2,c3,c4); KC_SC_(n,k,5,c5)
#define KC_SC_7(n, k, c0, c1, c2, c3, c4, c5, c6) \
    KC_SC_6(n,k,c0,c1,c2,c3,c4,c5); KC_SC_(n,k,6,c6)
#define KC_SC_8(n, k, c0, c1, c2, c3, c4, c5, c6, c7) \
    KC_SC_7(n,k,c0,c1,c2,c3,c4,c5,c6); KC_SC_(n,k,7,c7)
#define KC_SC_9(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8) \
    KC_SC_8(n,k,c0,c1,c2,c3,c4,c5,c6,c7); KC_SC_(n,k,8,c8)
#define KC_SC_10(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9) \
    KC_SC_9(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8); KC_SC_(n,k,9,c9)
#define KC_SC_11(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) \
    KC_SC_10(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9); KC_SC_(n,k,10,c10)
#define KC_SC_12(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11) \
    KC_SC_11(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10); KC_SC_(n,k,11,c11)
#define KC_SC_13(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12) \
    KC_SC_12(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11); KC_SC_(n,k,12,c12)
#define KC_SC_14(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13) \
    KC_SC_13(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12); KC_SC_(n,k,13,c13)
#define KC_SC_15(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14) \
    KC_SC_14(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13); KC_SC_(n,k,14,c14)
#define KC_SC_16(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15) \
    KC_SC_15(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14); KC_SC_(n,k,15,c15)
#define KC_SC_17(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16) \
    KC_SC_16(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15); KC_SC_(n,k,16,c16)
#define KC_SC_18(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17) \
    KC_SC_17(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15,c16); KC_SC_(n,k,17,c17)
#define KC_SC_19(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18) \
    KC_SC_18(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15,c16,c17); KC_SC_(n,k,18,c18)
#define KC_SC_20(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19) \
    KC_SC_19(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15,c16,c17,c18); KC_SC_(n,k,19,c19)

// wide char variants
#define KC_SWC_1(n, k, c0) \
    KC_SWC_(n,k,0,c0)
#define KC_SWC_2(n, k, c0, c1) \
    KC_SWC_1(n,k,c0); KC_SWC_(n,k,1,c1)
#define KC_SWC_3(n, k, c0, c1, c2) \
    KC_SWC_2(n,k,c0,c1); KC_SWC_(n,k,2,c2)
#define KC_SWC_4(n, k, c0, c1, c2, c3) \
    KC_SWC_3(n,k,c0,c1,c2); KC_SWC_(n,k,3,c3)
#define KC_SWC_5(n, k, c0, c1, c2, c3, c4) \
    KC_SWC_4(n,k,c0,c1,c2,c3); KC_SWC_(n,k,4,c4)
#define KC_SWC_6(n, k, c0, c1, c2, c3, c4, c5) \
    KC_SWC_5(n,k,c0,c1,c2,c3,c4); KC_SWC_(n,k,5,c5)
#define KC_SWC_7(n, k, c0, c1, c2, c3, c4, c5, c6) \
    KC_SWC_6(n,k,c0,c1,c2,c3,c4,c5); KC_SWC_(n,k,6,c6)
#define KC_SWC_8(n, k, c0, c1, c2, c3, c4, c5, c6, c7) \
    KC_SWC_7(n,k,c0,c1,c2,c3,c4,c5,c6); KC_SWC_(n,k,7,c7)
#define KC_SWC_9(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8) \
    KC_SWC_8(n,k,c0,c1,c2,c3,c4,c5,c6,c7); KC_SWC_(n,k,8,c8)
#define KC_SWC_10(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9) \
    KC_SWC_9(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8); KC_SWC_(n,k,9,c9)
#define KC_SWC_11(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10) \
    KC_SWC_10(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9); KC_SWC_(n,k,10,c10)
#define KC_SWC_12(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11) \
    KC_SWC_11(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10); KC_SWC_(n,k,11,c11)
#define KC_SWC_13(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12) \
    KC_SWC_12(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11); KC_SWC_(n,k,12,c12)
#define KC_SWC_14(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13) \
    KC_SWC_13(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12); KC_SWC_(n,k,13,c13)
#define KC_SWC_15(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14) \
    KC_SWC_14(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13); KC_SWC_(n,k,14,c14)
#define KC_SWC_16(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15) \
    KC_SWC_15(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14); KC_SWC_(n,k,15,c15)
#define KC_SWC_17(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16) \
    KC_SWC_16(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15); KC_SWC_(n,k,16,c16)
#define KC_SWC_18(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17) \
    KC_SWC_17(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15,c16); KC_SWC_(n,k,17,c17)
#define KC_SWC_19(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18) \
    KC_SWC_18(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15,c16,c17); KC_SWC_(n,k,18,c18)
#define KC_SWC_20(n, k, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19) \
    KC_SWC_19(n,k,c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,c10,c11,c12,c13,c14,c15,c16,c17,c18); KC_SWC_(n,k,19,c19)

// argument counting
#define KC_SC_COUNT_(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20,N,...) N
#define KC_SC_COUNT(...) KC_SC_COUNT_(__VA_ARGS__,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1)

#define KC_SC_PASTE_(a, b) a##b
#define KC_SC_PASTE(a, b) KC_SC_PASTE_(a, b)

// KC_STACK_STR(name, 'h','e','l','l','o','\0')
// constructs char name[N] on the stack with each char individually obfuscated
// no string literal in the binary whatsoever
#define KC_STACK_STR(name, ...)                                                 \
    char name[KC_SC_COUNT(__VA_ARGS__)];                                        \
    do {                                                                        \
        constexpr auto _kc_sk_ = KC_STACK_KEY_;                                 \
        KC_SC_PASTE(KC_SC_, KC_SC_COUNT(__VA_ARGS__))(name, _kc_sk_, __VA_ARGS__); \
    } while(0)

// KC_STACK_WSTR(name, L'h', L'e', ...)
#define KC_STACK_WSTR(name, ...)                                                \
    wchar_t name[KC_SC_COUNT(__VA_ARGS__)];                                     \
    do {                                                                        \
        constexpr auto _kc_sk_ = KC_STACK_KEY_;                                 \
        KC_SC_PASTE(KC_SWC_, KC_SC_COUNT(__VA_ARGS__))(name, _kc_sk_, __VA_ARGS__); \
    } while(0)

#else // KC_ENABLE_STRING_ENCRYPTION disabled

// passthrough - just declare a char array with the literal characters
#define KC_STACK_STR(name, ...) \
    char name[] = { __VA_ARGS__ }

#define KC_STACK_WSTR(name, ...) \
    wchar_t name[] = { __VA_ARGS__ }

#endif // KC_ENABLE_STRING_ENCRYPTION
