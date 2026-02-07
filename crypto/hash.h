#pragma once
#include "../config.h"
#include "../core/types.h"

namespace kernelcloak {
namespace crypto {

namespace detail {

// fnv-1a 64-bit constants
constexpr uint64_t fnv64_offset_basis = 0xcbf29ce484222325ull;
constexpr uint64_t fnv64_prime        = 0x00000100000001B3ull;

// fnv-1a 32-bit constants
constexpr uint32_t fnv32_offset_basis = 0x811c9dc5u;
constexpr uint32_t fnv32_prime        = 0x01000193u;

constexpr char to_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

constexpr wchar_t to_lower_w(wchar_t c) {
    return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c + (L'a' - L'A')) : c;
}

// 64-bit fnv-1a
constexpr uint64_t fnv1a_64(const char* str, size_t len) {
    uint64_t hash = fnv64_offset_basis;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint64_t>(static_cast<uint8_t>(str[i]));
        hash *= fnv64_prime;
    }
    return hash;
}

constexpr uint64_t fnv1a_64_ci(const char* str, size_t len) {
    uint64_t hash = fnv64_offset_basis;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint64_t>(static_cast<uint8_t>(to_lower(str[i])));
        hash *= fnv64_prime;
    }
    return hash;
}

constexpr uint64_t fnv1a_64_wide(const wchar_t* str, size_t len) {
    uint64_t hash = fnv64_offset_basis;
    for (size_t i = 0; i < len; ++i) {
        uint16_t ch = static_cast<uint16_t>(str[i]);
        hash ^= static_cast<uint64_t>(ch & 0xFF);
        hash *= fnv64_prime;
        hash ^= static_cast<uint64_t>((ch >> 8) & 0xFF);
        hash *= fnv64_prime;
    }
    return hash;
}

constexpr uint64_t fnv1a_64_wide_ci(const wchar_t* str, size_t len) {
    uint64_t hash = fnv64_offset_basis;
    for (size_t i = 0; i < len; ++i) {
        uint16_t ch = static_cast<uint16_t>(to_lower_w(str[i]));
        hash ^= static_cast<uint64_t>(ch & 0xFF);
        hash *= fnv64_prime;
        hash ^= static_cast<uint64_t>((ch >> 8) & 0xFF);
        hash *= fnv64_prime;
    }
    return hash;
}

// 32-bit fnv-1a
constexpr uint32_t fnv1a_32(const char* str, size_t len) {
    uint32_t hash = fnv32_offset_basis;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint32_t>(static_cast<uint8_t>(str[i]));
        hash *= fnv32_prime;
    }
    return hash;
}

constexpr uint32_t fnv1a_32_ci(const char* str, size_t len) {
    uint32_t hash = fnv32_offset_basis;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint32_t>(static_cast<uint8_t>(to_lower(str[i])));
        hash *= fnv32_prime;
    }
    return hash;
}

constexpr uint32_t fnv1a_32_wide(const wchar_t* str, size_t len) {
    uint32_t hash = fnv32_offset_basis;
    for (size_t i = 0; i < len; ++i) {
        uint16_t ch = static_cast<uint16_t>(str[i]);
        hash ^= static_cast<uint32_t>(ch & 0xFF);
        hash *= fnv32_prime;
        hash ^= static_cast<uint32_t>((ch >> 8) & 0xFF);
        hash *= fnv32_prime;
    }
    return hash;
}

constexpr uint32_t fnv1a_32_wide_ci(const wchar_t* str, size_t len) {
    uint32_t hash = fnv32_offset_basis;
    for (size_t i = 0; i < len; ++i) {
        uint16_t ch = static_cast<uint16_t>(to_lower_w(str[i]));
        hash ^= static_cast<uint32_t>(ch & 0xFF);
        hash *= fnv32_prime;
        hash ^= static_cast<uint32_t>((ch >> 8) & 0xFF);
        hash *= fnv32_prime;
    }
    return hash;
}

// null-terminated runtime variants
KC_FORCEINLINE uint64_t fnv1a_64_rt(const char* str) {
    uint64_t hash = fnv64_offset_basis;
    for (; *str; ++str) {
        hash ^= static_cast<uint64_t>(static_cast<uint8_t>(*str));
        hash *= fnv64_prime;
    }
    return hash;
}

KC_FORCEINLINE uint64_t fnv1a_64_rt_ci(const char* str) {
    uint64_t hash = fnv64_offset_basis;
    for (; *str; ++str) {
        hash ^= static_cast<uint64_t>(static_cast<uint8_t>(to_lower(*str)));
        hash *= fnv64_prime;
    }
    return hash;
}

KC_FORCEINLINE uint64_t fnv1a_64_rt_wide(const wchar_t* str) {
    uint64_t hash = fnv64_offset_basis;
    for (; *str; ++str) {
        uint16_t ch = static_cast<uint16_t>(*str);
        hash ^= static_cast<uint64_t>(ch & 0xFF);
        hash *= fnv64_prime;
        hash ^= static_cast<uint64_t>((ch >> 8) & 0xFF);
        hash *= fnv64_prime;
    }
    return hash;
}

KC_FORCEINLINE uint64_t fnv1a_64_rt_wide_ci(const wchar_t* str) {
    uint64_t hash = fnv64_offset_basis;
    for (; *str; ++str) {
        uint16_t ch = static_cast<uint16_t>(to_lower_w(*str));
        hash ^= static_cast<uint64_t>(ch & 0xFF);
        hash *= fnv64_prime;
        hash ^= static_cast<uint64_t>((ch >> 8) & 0xFF);
        hash *= fnv64_prime;
    }
    return hash;
}

KC_FORCEINLINE uint32_t fnv1a_32_rt(const char* str) {
    uint32_t hash = fnv32_offset_basis;
    for (; *str; ++str) {
        hash ^= static_cast<uint32_t>(static_cast<uint8_t>(*str));
        hash *= fnv32_prime;
    }
    return hash;
}

KC_FORCEINLINE uint32_t fnv1a_32_rt_ci(const char* str) {
    uint32_t hash = fnv32_offset_basis;
    for (; *str; ++str) {
        hash ^= static_cast<uint32_t>(static_cast<uint8_t>(to_lower(*str)));
        hash *= fnv32_prime;
    }
    return hash;
}

KC_FORCEINLINE uint32_t fnv1a_32_rt_wide(const wchar_t* str) {
    uint32_t hash = fnv32_offset_basis;
    for (; *str; ++str) {
        uint16_t ch = static_cast<uint16_t>(*str);
        hash ^= static_cast<uint32_t>(ch & 0xFF);
        hash *= fnv32_prime;
        hash ^= static_cast<uint32_t>((ch >> 8) & 0xFF);
        hash *= fnv32_prime;
    }
    return hash;
}

KC_FORCEINLINE uint32_t fnv1a_32_rt_wide_ci(const wchar_t* str) {
    uint32_t hash = fnv32_offset_basis;
    for (; *str; ++str) {
        uint16_t ch = static_cast<uint16_t>(to_lower_w(*str));
        hash ^= static_cast<uint32_t>(ch & 0xFF);
        hash *= fnv32_prime;
        hash ^= static_cast<uint32_t>((ch >> 8) & 0xFF);
        hash *= fnv32_prime;
    }
    return hash;
}

// constexpr strlen for compile-time use
constexpr size_t ct_strlen(const char* s) {
    size_t len = 0;
    while (s[len]) ++len;
    return len;
}

constexpr size_t ct_wcslen(const wchar_t* s) {
    size_t len = 0;
    while (s[len]) ++len;
    return len;
}

} // namespace detail

// public constexpr API - 64-bit (default)
constexpr uint64_t hash(const char* str, size_t len) {
    return detail::fnv1a_64(str, len);
}

constexpr uint64_t hash_ci(const char* str, size_t len) {
    return detail::fnv1a_64_ci(str, len);
}

constexpr uint64_t hash_wide(const wchar_t* str, size_t len) {
    return detail::fnv1a_64_wide(str, len);
}

constexpr uint64_t hash_wide_ci(const wchar_t* str, size_t len) {
    return detail::fnv1a_64_wide_ci(str, len);
}

// public constexpr API - 32-bit
constexpr uint32_t hash32(const char* str, size_t len) {
    return detail::fnv1a_32(str, len);
}

constexpr uint32_t hash32_ci(const char* str, size_t len) {
    return detail::fnv1a_32_ci(str, len);
}

constexpr uint32_t hash32_wide(const wchar_t* str, size_t len) {
    return detail::fnv1a_32_wide(str, len);
}

constexpr uint32_t hash32_wide_ci(const wchar_t* str, size_t len) {
    return detail::fnv1a_32_wide_ci(str, len);
}

// runtime API - null-terminated strings
KC_FORCEINLINE uint64_t hash_rt(const char* str) {
    return detail::fnv1a_64_rt(str);
}

KC_FORCEINLINE uint64_t hash_rt_ci(const char* str) {
    return detail::fnv1a_64_rt_ci(str);
}

KC_FORCEINLINE uint64_t hash_rt_wide(const wchar_t* str) {
    return detail::fnv1a_64_rt_wide(str);
}

KC_FORCEINLINE uint64_t hash_rt_wide_ci(const wchar_t* str) {
    return detail::fnv1a_64_rt_wide_ci(str);
}

KC_FORCEINLINE uint32_t hash32_rt(const char* str) {
    return detail::fnv1a_32_rt(str);
}

KC_FORCEINLINE uint32_t hash32_rt_ci(const char* str) {
    return detail::fnv1a_32_rt_ci(str);
}

KC_FORCEINLINE uint32_t hash32_rt_wide(const wchar_t* str) {
    return detail::fnv1a_32_rt_wide(str);
}

KC_FORCEINLINE uint32_t hash32_rt_wide_ci(const wchar_t* str) {
    return detail::fnv1a_32_rt_wide_ci(str);
}

} // namespace crypto
} // namespace kernelcloak

// compile-time hash macros - 64-bit
#define KC_HASH(s) \
    (::kernelcloak::crypto::detail::fnv1a_64((s), ::kernelcloak::crypto::detail::ct_strlen(s)))

#define KC_HASH_CI(s) \
    (::kernelcloak::crypto::detail::fnv1a_64_ci((s), ::kernelcloak::crypto::detail::ct_strlen(s)))

#define KC_HASH_WIDE(s) \
    (::kernelcloak::crypto::detail::fnv1a_64_wide((s), ::kernelcloak::crypto::detail::ct_wcslen(s)))

#define KC_HASH_WIDE_CI(s) \
    (::kernelcloak::crypto::detail::fnv1a_64_wide_ci((s), ::kernelcloak::crypto::detail::ct_wcslen(s)))

// compile-time hash macros - 32-bit
#define KC_HASH32(s) \
    (::kernelcloak::crypto::detail::fnv1a_32((s), ::kernelcloak::crypto::detail::ct_strlen(s)))

#define KC_HASH32_CI(s) \
    (::kernelcloak::crypto::detail::fnv1a_32_ci((s), ::kernelcloak::crypto::detail::ct_strlen(s)))

// runtime hash macros - 64-bit
#define KC_HASH_RT(s)    (::kernelcloak::crypto::detail::fnv1a_64_rt(s))
#define KC_HASH_RT_CI(s) (::kernelcloak::crypto::detail::fnv1a_64_rt_ci(s))

// runtime hash macros - wide
#define KC_HASH_RT_WIDE(s)    (::kernelcloak::crypto::detail::fnv1a_64_rt_wide(s))
#define KC_HASH_RT_WIDE_CI(s) (::kernelcloak::crypto::detail::fnv1a_64_rt_wide_ci(s))
