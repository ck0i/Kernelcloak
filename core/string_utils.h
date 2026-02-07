#pragma once
#include "../config.h"
#include "types.h"

#pragma warning(push)
#pragma warning(disable: 4201) // nameless struct/union

// NTSTATUS typedef - only when kernel headers aren't already included
#if !defined(_NTDDK_) && !defined(_WDMDDK_)
extern "C" {
    using NTSTATUS = long;

    // ntstrsafe string functions
    NTSTATUS __stdcall RtlStringCbCopyA(char* pszDest, unsigned __int64 cbDest, const char* pszSrc);
    NTSTATUS __stdcall RtlStringCbCatA(char* pszDest, unsigned __int64 cbDest, const char* pszSrc);
    NTSTATUS __stdcall RtlStringCbLengthA(const char* psz, unsigned __int64 cbMax, unsigned __int64* pcbLength);
    NTSTATUS __stdcall RtlStringCbCopyW(wchar_t* pszDest, unsigned __int64 cbDest, const wchar_t* pszSrc);
    NTSTATUS __stdcall RtlStringCbCatW(wchar_t* pszDest, unsigned __int64 cbDest, const wchar_t* pszSrc);
    NTSTATUS __stdcall RtlStringCbLengthW(const wchar_t* psz, unsigned __int64 cbMax, unsigned __int64* pcbLength);
    NTSTATUS __stdcall RtlStringCbPrintfA(char* pszDest, unsigned __int64 cbDest, const char* pszFormat, ...);
    NTSTATUS __stdcall RtlStringCbPrintfW(wchar_t* pszDest, unsigned __int64 cbDest, const wchar_t* pszFormat, ...);

    // safe max length for ntstrsafe (NTSTRSAFE_MAX_CCH * sizeof(char))
    // ntstrsafe.h defines NTSTRSAFE_MAX_CCH as 2147483647 (INT_MAX)
}
#endif

#define KC_NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)

// ntstrsafe max buffer size
#ifndef KC_STRSAFE_MAX_CB
#define KC_STRSAFE_MAX_CB (2147483647ULL)
#endif

namespace kernelcloak {
namespace core {

// compile-time string length
template<typename CharT>
constexpr size_t kc_strlen(const CharT* str) noexcept {
    size_t len = 0;
    while (str[len] != CharT(0)) {
        ++len;
    }
    return len;
}

// compile-time string compare
constexpr int kc_strcmp(const char* a, const char* b) noexcept {
    while (*a && (*a == *b)) {
        ++a;
        ++b;
    }
    return static_cast<unsigned char>(*a) - static_cast<unsigned char>(*b);
}

constexpr int kc_wcscmp(const wchar_t* a, const wchar_t* b) noexcept {
    while (*a && (*a == *b)) {
        ++a;
        ++b;
    }
    return (*a > *b) ? 1 : ((*a < *b) ? -1 : 0);
}

// compile-time case-insensitive compare
constexpr int kc_stricmp(const char* a, const char* b) noexcept {
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? (*a + ('a' - 'A')) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (*b + ('a' - 'A')) : *b;
        if (ca != cb) {
            return static_cast<unsigned char>(ca) - static_cast<unsigned char>(cb);
        }
        ++a;
        ++b;
    }
    char ca = (*a >= 'A' && *a <= 'Z') ? (*a + ('a' - 'A')) : *a;
    char cb = (*b >= 'A' && *b <= 'Z') ? (*b + ('a' - 'A')) : *b;
    return static_cast<unsigned char>(ca) - static_cast<unsigned char>(cb);
}

// compile-time n-bounded compare
constexpr int kc_strncmp(const char* a, const char* b, size_t n) noexcept {
    for (size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) {
            return static_cast<unsigned char>(a[i]) - static_cast<unsigned char>(b[i]);
        }
        if (a[i] == '\0') {
            return 0;
        }
    }
    return 0;
}

// compile-time tolower/toupper
constexpr char kc_tolower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? (c + ('a' - 'A')) : c;
}

constexpr char kc_toupper(char c) noexcept {
    return (c >= 'a' && c <= 'z') ? (c - ('a' - 'A')) : c;
}

constexpr wchar_t kc_towlower(wchar_t c) noexcept {
    return (c >= L'A' && c <= L'Z') ? (c + (L'a' - L'A')) : c;
}

constexpr wchar_t kc_towupper(wchar_t c) noexcept {
    return (c >= L'a' && c <= L'z') ? (c - (L'a' - L'A')) : c;
}

// compile-time string search
constexpr const char* kc_strstr(const char* haystack, const char* needle) noexcept {
    if (*needle == '\0') return haystack;
    for (; *haystack; ++haystack) {
        const char* h = haystack;
        const char* n = needle;
        while (*h && *n && (*h == *n)) {
            ++h;
            ++n;
        }
        if (*n == '\0') return haystack;
    }
    return nullptr;
}

// compile-time char search
constexpr const char* kc_strchr(const char* str, char c) noexcept {
    while (*str) {
        if (*str == c) return str;
        ++str;
    }
    return (c == '\0') ? str : nullptr;
}

// compile-time string copy (bounded)
constexpr void kc_strncpy(char* dst, const char* src, size_t n) noexcept {
    size_t i = 0;
    for (; i < n && src[i] != '\0'; ++i) {
        dst[i] = src[i];
    }
    for (; i < n; ++i) {
        dst[i] = '\0';
    }
}

// runtime safe string operations (wrapping ntstrsafe)
// these are NOT constexpr as they call external kernel functions

struct StringResult {
    NTSTATUS status;
    KC_FORCEINLINE bool ok() const noexcept { return KC_NT_SUCCESS(status); }
    KC_FORCEINLINE operator bool() const noexcept { return ok(); }
};

KC_FORCEINLINE StringResult kc_safe_copy(char* dst, size_t dst_size, const char* src) noexcept {
    return { RtlStringCbCopyA(dst, dst_size, src) };
}

KC_FORCEINLINE StringResult kc_safe_copy(wchar_t* dst, size_t dst_size, const wchar_t* src) noexcept {
    return { RtlStringCbCopyW(dst, dst_size, src) };
}

KC_FORCEINLINE StringResult kc_safe_cat(char* dst, size_t dst_size, const char* src) noexcept {
    return { RtlStringCbCatA(dst, dst_size, src) };
}

KC_FORCEINLINE StringResult kc_safe_cat(wchar_t* dst, size_t dst_size, const wchar_t* src) noexcept {
    return { RtlStringCbCatW(dst, dst_size, src) };
}

KC_FORCEINLINE StringResult kc_safe_length(const char* str, size_t max_size, size_t* out_length) noexcept {
    unsigned __int64 len = 0;
    auto status = RtlStringCbLengthA(str, max_size, &len);
    *out_length = static_cast<size_t>(len);
    return { status };
}

KC_FORCEINLINE StringResult kc_safe_length(const wchar_t* str, size_t max_size, size_t* out_length) noexcept {
    unsigned __int64 len = 0;
    auto status = RtlStringCbLengthW(str, max_size, &len);
    *out_length = static_cast<size_t>(len);
    return { status };
}

// compile-time FNV-1a hash for string comparison without exposing plaintext
constexpr uint32_t kc_hash32(const char* str) noexcept {
    uint32_t hash = 0x811c9dc5u;
    while (*str) {
        hash ^= static_cast<uint32_t>(static_cast<unsigned char>(*str));
        hash *= 0x01000193u;
        ++str;
    }
    return hash;
}

constexpr uint64_t kc_hash64(const char* str) noexcept {
    uint64_t hash = 0xcbf29ce484222325ull;
    while (*str) {
        hash ^= static_cast<uint64_t>(static_cast<unsigned char>(*str));
        hash *= 0x100000001b3ull;
        ++str;
    }
    return hash;
}

// wide char hashing
constexpr uint32_t kc_hash32(const wchar_t* str) noexcept {
    uint32_t hash = 0x811c9dc5u;
    while (*str) {
        hash ^= static_cast<uint32_t>(*str) & 0xFF;
        hash *= 0x01000193u;
        hash ^= (static_cast<uint32_t>(*str) >> 8) & 0xFF;
        hash *= 0x01000193u;
        ++str;
    }
    return hash;
}

// case-insensitive hash
constexpr uint32_t kc_hash32_i(const char* str) noexcept {
    uint32_t hash = 0x811c9dc5u;
    while (*str) {
        char c = (*str >= 'A' && *str <= 'Z') ? (*str + ('a' - 'A')) : *str;
        hash ^= static_cast<uint32_t>(static_cast<unsigned char>(c));
        hash *= 0x01000193u;
        ++str;
    }
    return hash;
}

} // namespace core
} // namespace kernelcloak

#pragma warning(pop)
