#pragma once
#include "../config.h"
#include "../core/types.h"
#include "../core/random.h"
#include "../crypto/xor_cipher.h"

#if KC_ENABLE_STRING_ENCRYPTION

namespace kernelcloak {
namespace strings {
namespace detail {

// compile-time wide string encryption with stack-local decryption
// wchar_t is 2 bytes on Windows
template<size_t N, uint32_t Key>
class encrypted_wstring {
    uint16_t m_encrypted[N];

    static constexpr uint16_t encrypt_wchar(wchar_t c, size_t idx) {
        uint32_t derived = Key ^ static_cast<uint32_t>(idx * 0x9E3779B9u);
        uint16_t k = static_cast<uint16_t>(derived ^ (derived >> 16));
        return static_cast<uint16_t>(c) ^ k;
    }

public:
    template<size_t... Is>
    constexpr encrypted_wstring(const wchar_t(&str)[N], kernelcloak::detail::index_sequence<Is...>)
        : m_encrypted{ encrypt_wchar(str[Is], Is)... }
    {}

    KC_FORCEINLINE void decrypt(wchar_t* out) const {
        for (size_t i = 0; i < N; ++i) {
            uint32_t derived = Key ^ static_cast<uint32_t>(i * 0x9E3779B9u);
            uint16_t k = static_cast<uint16_t>(derived ^ (derived >> 16));
            out[i] = static_cast<wchar_t>(m_encrypted[i] ^ k);
        }
    }

    static constexpr size_t length() { return N - 1; }
    static constexpr size_t size() { return N; }
};

template<size_t N, uint32_t Key>
struct decrypted_wstring {
    wchar_t buf[N];

    KC_FORCEINLINE decrypted_wstring(const encrypted_wstring<N, Key>& enc) {
        enc.decrypt(buf);
    }

    KC_FORCEINLINE operator const wchar_t*() const { return buf; }
    KC_FORCEINLINE const wchar_t* c_str() const { return buf; }
    KC_FORCEINLINE size_t length() const { return N - 1; }
    KC_FORCEINLINE size_t size() const { return N; }
};

template<size_t N, uint32_t Key>
KC_FORCEINLINE decrypted_wstring<N, Key> make_decrypted_w(const encrypted_wstring<N, Key>& enc) {
    return decrypted_wstring<N, Key>(enc);
}

} // namespace detail
} // namespace strings
} // namespace kernelcloak

// KC_WSTR(L"text") - wide string encryption, returns temporary with
// implicit conversion to const wchar_t*
#define KC_WSTR(s)                                                              \
    ::kernelcloak::strings::detail::make_decrypted_w(                           \
        []() -> const auto& {                                                   \
            constexpr ::kernelcloak::size_t _wn = sizeof(s) / sizeof(wchar_t);  \
            constexpr ::kernelcloak::uint32_t _k =                              \
                static_cast<::kernelcloak::uint32_t>(                           \
                    (__COUNTER__ + 1) * 0x45D9F3Bu ^                            \
                    __LINE__ * 0x1B873593u ^                                    \
                    _wn * 0xCC9E2D51u                                           \
                );                                                              \
            static constexpr ::kernelcloak::strings::detail::encrypted_wstring< \
                _wn, _k> e(                                                     \
                s, ::kernelcloak::detail::make_index_sequence<_wn>{}            \
            );                                                                  \
            return e;                                                           \
        }()                                                                     \
    )

// KC_WSTR_DECL(name, L"text") - named wide string in caller's scope
#define KC_WSTR_DECL_IMPL_(name, s, wlen, key)                                  \
    static constexpr ::kernelcloak::strings::detail::encrypted_wstring<         \
        wlen, key> _kc_wenc_##name(                                             \
        s, ::kernelcloak::detail::make_index_sequence<wlen>{}                   \
    );                                                                          \
    auto name = ::kernelcloak::strings::detail::make_decrypted_w(               \
        _kc_wenc_##name)

#define KC_WSTR_DECL(name, s)                                                   \
    KC_WSTR_DECL_IMPL_(name, s,                                                 \
        sizeof(s) / sizeof(wchar_t),                                            \
        static_cast<::kernelcloak::uint32_t>(                                   \
            (__COUNTER__ + 1) * 0x45D9F3Bu ^                                    \
            __LINE__ * 0x1B873593u ^                                            \
            (sizeof(s) / sizeof(wchar_t)) * 0xCC9E2D51u                         \
        )                                                                       \
    )

// KC_WSTR_N - same as KC_WSTR with .c_str() and .length()
#define KC_WSTR_N(s) KC_WSTR(s)

#else // KC_ENABLE_STRING_ENCRYPTION disabled

#define KC_WSTR(s)             (s)
#define KC_WSTR_DECL(name, s)  const wchar_t* name = (s)
#define KC_WSTR_N(s)           (s)

#endif // KC_ENABLE_STRING_ENCRYPTION
