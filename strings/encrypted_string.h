#pragma once
#include "../config.h"
#include "../core/types.h"
#include "../core/random.h"
#include "../crypto/xor_cipher.h"

#if KC_ENABLE_STRING_ENCRYPTION

namespace kernelcloak {
namespace strings {
namespace detail {

// compile-time string encryption with stack-local decryption
// no static destructors, no atexit, no CRT - safe at any IRQL
template<size_t N, uint32_t Key>
class encrypted_string {
    uint8_t m_encrypted[N];

    static constexpr uint8_t encrypt_byte(char c, size_t idx) {
        uint8_t k = static_cast<uint8_t>((Key >> ((idx % 4) * 8)) ^ (idx * 0x9E3779B9u));
        return static_cast<uint8_t>(c) ^ k;
    }

public:
    template<size_t... Is>
    constexpr encrypted_string(const char(&str)[N], kernelcloak::detail::index_sequence<Is...>)
        : m_encrypted{ encrypt_byte(str[Is], Is)... }
    {}

    KC_FORCEINLINE void decrypt(char* out) const {
        for (size_t i = 0; i < N; ++i) {
            uint8_t k = static_cast<uint8_t>((Key >> ((i % 4) * 8)) ^ (i * 0x9E3779B9u));
            out[i] = static_cast<char>(m_encrypted[i] ^ k);
        }
    }

    static constexpr size_t length() { return N - 1; }
    static constexpr size_t size() { return N; }
};

// stack-local decryption wrapper returned by value from KC_STR
// the temporary lives for the duration of the full-expression it appears in,
// so passing KC_STR("hello") to a function is safe.
// for longer-lived strings, use KC_STR_DECL or `auto s = KC_STR(...)`.
template<size_t N, uint32_t Key>
struct decrypted_string {
    char buf[N];

    KC_FORCEINLINE decrypted_string(const encrypted_string<N, Key>& enc) {
        enc.decrypt(buf);
    }

    KC_FORCEINLINE operator const char*() const { return buf; }
    KC_FORCEINLINE const char* c_str() const { return buf; }
    KC_FORCEINLINE size_t length() const { return N - 1; }
    KC_FORCEINLINE size_t size() const { return N; }
};

// helper: deduces template params from encrypted_string to avoid
// needing to repeat them in the macro expansion
template<size_t N, uint32_t Key>
KC_FORCEINLINE decrypted_string<N, Key> make_decrypted(const encrypted_string<N, Key>& enc) {
    return decrypted_string<N, Key>(enc);
}

} // namespace detail
} // namespace strings
} // namespace kernelcloak

// KC_STR("text") - returns a temporary decrypted_string that implicitly
// converts to const char*. safe to pass directly to functions.
//
//   DbgPrint("%s\n", KC_STR("hello")); // safe
//   auto s = KC_STR("hello");          // safe, s owns the buffer
//   const char* p = KC_STR("hello");   // dangling! use KC_STR_DECL instead
//
// the __COUNTER__ is consumed once inside the lambda, and make_decrypted
// deduces the key from the encrypted_string type, so no key mismatch.
#define KC_STR(s)                                                               \
    ::kernelcloak::strings::detail::make_decrypted(                             \
        []() -> const auto& {                                                   \
            constexpr ::kernelcloak::uint32_t _k =                              \
                static_cast<::kernelcloak::uint32_t>(                           \
                    (__COUNTER__ + 1) * 0x45D9F3Bu ^                            \
                    __LINE__ * 0x1B873593u ^                                    \
                    sizeof(s) * 0xCC9E2D51u                                     \
                );                                                              \
            static constexpr ::kernelcloak::strings::detail::encrypted_string<  \
                sizeof(s), _k> e(                                               \
                s, ::kernelcloak::detail::make_index_sequence<sizeof(s)>{}      \
            );                                                                  \
            return e;                                                           \
        }()                                                                     \
    )

// KC_STR_DECL(name, "text") - declares a named decrypted_string in the
// caller's scope. buffer is valid for the variable's lifetime.
//
//   KC_STR_DECL(greeting, "hello world");
//   use_string(greeting.c_str(), greeting.length());
//
// uses a do-nothing enum trick to capture __COUNTER__ once and reuse it
#define KC_STR_DECL_IMPL_(name, s, key)                                         \
    static constexpr ::kernelcloak::strings::detail::encrypted_string<          \
        sizeof(s), key> _kc_enc_##name(                                         \
        s, ::kernelcloak::detail::make_index_sequence<sizeof(s)>{}              \
    );                                                                          \
    auto name = ::kernelcloak::strings::detail::make_decrypted(_kc_enc_##name)

#define KC_STR_DECL(name, s)                                                    \
    KC_STR_DECL_IMPL_(name, s,                                                  \
        static_cast<::kernelcloak::uint32_t>(                                   \
            (__COUNTER__ + 1) * 0x45D9F3Bu ^                                    \
            __LINE__ * 0x1B873593u ^                                            \
            sizeof(s) * 0xCC9E2D51u                                             \
        )                                                                       \
    )

// KC_STR_N("text") - same as KC_STR, the returned decrypted_string has
// both .c_str() and .length() accessors
#define KC_STR_N(s) KC_STR(s)

#else // KC_ENABLE_STRING_ENCRYPTION disabled

#define KC_STR(s)              (s)
#define KC_STR_DECL(name, s)   const char* name = (s)
#define KC_STR_N(s)            (s)

#endif // KC_ENABLE_STRING_ENCRYPTION
