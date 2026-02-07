#pragma once
#include "../config.h"
#include "../core/types.h"
#include "../core/random.h"
#include "../crypto/xor_cipher.h"
#include "../crypto/xtea.h"

#if KC_ENABLE_STRING_ENCRYPTION

// intrinsics - no windows.h needed
extern "C" long __cdecl _InterlockedIncrement(long volatile*);
extern "C" unsigned __int64 __rdtsc();
#pragma intrinsic(_InterlockedIncrement)
#pragma intrinsic(__rdtsc)

namespace kernelcloak {
namespace strings {
namespace detail {

// compile-time byte permutation via fisher-yates
template<size_t N, uint32_t Seed>
struct byte_permutation {
    size_t forward[N];  // forward[i] = where byte i goes
    size_t inverse[N];  // inverse[j] = which byte is at position j

    constexpr byte_permutation() : forward{}, inverse{} {
        for (size_t i = 0; i < N; ++i)
            forward[i] = i;

        uint32_t state = Seed;
        for (size_t i = N - 1; i > 0; --i) {
            state = state * 0x41C64E6Du + 0x3039u;
            size_t j = (state >> 16) % (i + 1);
            size_t tmp = forward[i];
            forward[i] = forward[j];
            forward[j] = tmp;
        }

        for (size_t i = 0; i < N; ++i)
            inverse[forward[i]] = i;
    }
};

// triple-layered string encryption:
//   layer 1: rolling XOR with KeyA
//   layer 2: XTEA on 8-byte blocks with KeyB[4]
//   layer 3: byte shuffle with deterministic permutation
template<size_t N, uint32_t KeyA,
    uint32_t KeyB0, uint32_t KeyB1, uint32_t KeyB2, uint32_t KeyB3,
    uint32_t ShuffleSeed>
class layered_encrypted_string {
    static constexpr size_t padded = ((N + 7) / 8) * 8;

    uint8_t m_data[padded];
    static constexpr byte_permutation<padded, ShuffleSeed> s_perm{};

    static constexpr uint8_t xor_key(size_t idx) {
        return static_cast<uint8_t>(
            (KeyA >> ((idx % 4) * 8)) ^ (idx * 0x9E3779B9u));
    }

public:
    template<size_t... Is>
    constexpr layered_encrypted_string(const char(&str)[N],
        kernelcloak::detail::index_sequence<Is...>)
        : m_data{}
    {
        // start with padded plaintext
        uint8_t buf[padded] = {};
        const uint8_t src[] = { static_cast<uint8_t>(str[Is])... };
        for (size_t i = 0; i < N; ++i) buf[i] = src[i];

        // layer 1: XOR
        for (size_t i = 0; i < padded; ++i)
            buf[i] ^= xor_key(i);

        // layer 2: XTEA encrypt each 8-byte block
        constexpr uint32_t delta = 0x9E3779B9u;
        constexpr uint32_t tk[4] = { KeyB0, KeyB1, KeyB2, KeyB3 };
        for (size_t blk = 0; blk < padded; blk += 8) {
            uint32_t v0 = static_cast<uint32_t>(buf[blk])
                | (static_cast<uint32_t>(buf[blk+1]) << 8)
                | (static_cast<uint32_t>(buf[blk+2]) << 16)
                | (static_cast<uint32_t>(buf[blk+3]) << 24);
            uint32_t v1 = static_cast<uint32_t>(buf[blk+4])
                | (static_cast<uint32_t>(buf[blk+5]) << 8)
                | (static_cast<uint32_t>(buf[blk+6]) << 16)
                | (static_cast<uint32_t>(buf[blk+7]) << 24);

            uint32_t sum = 0;
            for (size_t r = 0; r < KC_XTEA_ROUNDS; ++r) {
                v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + tk[sum & 3]);
                sum += delta;
                v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + tk[(sum >> 11) & 3]);
            }

            buf[blk]   = static_cast<uint8_t>(v0);
            buf[blk+1] = static_cast<uint8_t>(v0 >> 8);
            buf[blk+2] = static_cast<uint8_t>(v0 >> 16);
            buf[blk+3] = static_cast<uint8_t>(v0 >> 24);
            buf[blk+4] = static_cast<uint8_t>(v1);
            buf[blk+5] = static_cast<uint8_t>(v1 >> 8);
            buf[blk+6] = static_cast<uint8_t>(v1 >> 16);
            buf[blk+7] = static_cast<uint8_t>(v1 >> 24);
        }

        // layer 3: shuffle bytes
        for (size_t i = 0; i < padded; ++i)
            m_data[s_perm.forward[i]] = buf[i];
    }

    KC_FORCEINLINE void decrypt(char* out) const {
        uint8_t buf[padded];

        // undo shuffle: buf[i] = m_data[forward[i]] undone by inverse
        for (size_t i = 0; i < padded; ++i)
            buf[s_perm.inverse[i]] = m_data[i];

        // undo XTEA
        constexpr uint32_t delta = 0x9E3779B9u;
        constexpr uint32_t tk[4] = { KeyB0, KeyB1, KeyB2, KeyB3 };
        for (size_t blk = 0; blk < padded; blk += 8) {
            uint32_t v0 = static_cast<uint32_t>(buf[blk])
                | (static_cast<uint32_t>(buf[blk+1]) << 8)
                | (static_cast<uint32_t>(buf[blk+2]) << 16)
                | (static_cast<uint32_t>(buf[blk+3]) << 24);
            uint32_t v1 = static_cast<uint32_t>(buf[blk+4])
                | (static_cast<uint32_t>(buf[blk+5]) << 8)
                | (static_cast<uint32_t>(buf[blk+6]) << 16)
                | (static_cast<uint32_t>(buf[blk+7]) << 24);

            uint32_t sum = delta * KC_XTEA_ROUNDS;
            for (size_t r = 0; r < KC_XTEA_ROUNDS; ++r) {
                v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + tk[(sum >> 11) & 3]);
                sum -= delta;
                v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + tk[sum & 3]);
            }

            buf[blk]   = static_cast<uint8_t>(v0);
            buf[blk+1] = static_cast<uint8_t>(v0 >> 8);
            buf[blk+2] = static_cast<uint8_t>(v0 >> 16);
            buf[blk+3] = static_cast<uint8_t>(v0 >> 24);
            buf[blk+4] = static_cast<uint8_t>(v1);
            buf[blk+5] = static_cast<uint8_t>(v1 >> 8);
            buf[blk+6] = static_cast<uint8_t>(v1 >> 16);
            buf[blk+7] = static_cast<uint8_t>(v1 >> 24);
        }

        // undo XOR and output only the original N bytes
        for (size_t i = 0; i < N; ++i)
            out[i] = static_cast<char>(buf[i] ^ xor_key(i));
    }

    static constexpr size_t length() { return N - 1; }
    static constexpr size_t size() { return N; }
};

// decryption wrapper for layered strings - same pattern as encrypted_string
template<size_t N, uint32_t KeyA,
    uint32_t KeyB0, uint32_t KeyB1, uint32_t KeyB2, uint32_t KeyB3,
    uint32_t ShuffleSeed>
struct decrypted_layered_string {
    char buf[N];

    using enc_t = layered_encrypted_string<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed>;

    KC_FORCEINLINE decrypted_layered_string(const enc_t& enc) {
        enc.decrypt(buf);
    }

    KC_FORCEINLINE operator const char*() const { return buf; }
    KC_FORCEINLINE const char* c_str() const { return buf; }
    KC_FORCEINLINE size_t length() const { return N - 1; }
};

template<size_t N, uint32_t KeyA,
    uint32_t KeyB0, uint32_t KeyB1, uint32_t KeyB2, uint32_t KeyB3,
    uint32_t ShuffleSeed>
KC_FORCEINLINE auto make_decrypted_layered(
    const layered_encrypted_string<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed>& enc)
{
    return decrypted_layered_string<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed>(enc);
}

// re-keying holder for high-security strings
// caller owns this struct. after KC_LAYERED_REKEY_INTERVAL accesses,
// the cached decryption re-encrypts with a fresh runtime key.
// uses InterlockedIncrement for thread safety, no CRT, no atexit.
template<size_t N, uint32_t KeyA,
    uint32_t KeyB0, uint32_t KeyB1, uint32_t KeyB2, uint32_t KeyB3,
    uint32_t ShuffleSeed>
struct layered_string_holder {
    using enc_t = layered_encrypted_string<N, KeyA, KeyB0, KeyB1, KeyB2, KeyB3, ShuffleSeed>;

    const enc_t* source;
    uint8_t runtime_cache[N];
    uint32_t runtime_key;
    volatile long access_count;
    bool cache_valid;

    KC_FORCEINLINE void init(const enc_t* src) {
        source = src;
        runtime_key = 0;
        access_count = 0;
        cache_valid = false;
    }

    KC_NOINLINE void rekey() {
        char plain[N];
        source->decrypt(plain);

        // entropy from rdtsc + counter
        uint32_t seed = static_cast<uint32_t>(access_count) * 0x45D9F3Bu;
        seed ^= static_cast<uint32_t>(__rdtsc());
        runtime_key = seed | 1u;

        for (size_t i = 0; i < N; ++i) {
            uint8_t k = static_cast<uint8_t>(
                (runtime_key >> ((i % 4) * 8)) ^ (i * 0x27D4EB2Du));
            runtime_cache[i] = static_cast<uint8_t>(plain[i]) ^ k;
        }

        // scrub plaintext
        volatile char* vp = plain;
        for (size_t i = 0; i < N; ++i) vp[i] = 0;

        cache_valid = true;
    }

    KC_FORCEINLINE void decrypt(char* out) {
        long count = _InterlockedIncrement(&access_count);

        if (!cache_valid || (count % KC_LAYERED_REKEY_INTERVAL) == 0)
            rekey();

        for (size_t i = 0; i < N; ++i) {
            uint8_t k = static_cast<uint8_t>(
                (runtime_key >> ((i % 4) * 8)) ^ (i * 0x27D4EB2Du));
            out[i] = static_cast<char>(runtime_cache[i] ^ k);
        }
    }
};

} // namespace detail
} // namespace strings
} // namespace kernelcloak

// six keys derived from a single __COUNTER__ expansion inside the lambda
// make_decrypted_layered deduces all template params from the encrypted type
#define KC_STR_LAYERED(s)                                                       \
    ::kernelcloak::strings::detail::make_decrypted_layered(                     \
        []() -> const auto& {                                                   \
            constexpr ::kernelcloak::uint32_t _cnt =                            \
                static_cast<::kernelcloak::uint32_t>(__COUNTER__);              \
            constexpr ::kernelcloak::uint32_t _ln =                             \
                static_cast<::kernelcloak::uint32_t>(__LINE__);                 \
            constexpr ::kernelcloak::uint32_t _ka =                             \
                (_cnt + 1) * 0x45D9F3Bu ^ _ln * 0x1B873593u;                    \
            constexpr ::kernelcloak::uint32_t _kb0 =                            \
                (_cnt + 2) * 0xCC9E2D51u ^ _ln * 0x85EBCA6Bu;                   \
            constexpr ::kernelcloak::uint32_t _kb1 =                            \
                (_cnt + 3) * 0xC2B2AE35u ^ _ln * 0x27D4EB2Du;                   \
            constexpr ::kernelcloak::uint32_t _kb2 =                            \
                (_cnt + 4) * 0x165667B1u ^ _ln * 0xE6546B64u;                   \
            constexpr ::kernelcloak::uint32_t _kb3 =                            \
                (_cnt + 5) * 0x9E3779B9u ^ _ln * 0x41C64E6Du;                   \
            constexpr ::kernelcloak::uint32_t _sh =                             \
                (_cnt + 6) * 0x6C62272Eu ^ _ln * 0xBEA6E8C5u;                   \
            static constexpr ::kernelcloak::strings::detail::                   \
                layered_encrypted_string<sizeof(s),                             \
                    _ka, _kb0, _kb1, _kb2, _kb3, _sh> e(                        \
                s, ::kernelcloak::detail::make_index_sequence<sizeof(s)>{}      \
            );                                                                  \
            return e;                                                           \
        }()                                                                     \
    )

// re-keyable holder - caller owns the struct
// usage:
//   KC_STR_LAYERED_HOLDER(my_str, "secret");
//   char buf[sizeof("secret")];
//   my_str.decrypt(buf);
#define KC_STR_LAYERED_HOLDER(name, s)                                          \
    auto name = [&]() {                                                         \
        constexpr ::kernelcloak::uint32_t _cnt =                                \
            static_cast<::kernelcloak::uint32_t>(__COUNTER__);                  \
        constexpr ::kernelcloak::uint32_t _ln =                                 \
            static_cast<::kernelcloak::uint32_t>(__LINE__);                     \
        constexpr ::kernelcloak::uint32_t _ka =                                 \
            (_cnt + 1) * 0x45D9F3Bu ^ _ln * 0x1B873593u;                        \
        constexpr ::kernelcloak::uint32_t _kb0 =                                \
            (_cnt + 2) * 0xCC9E2D51u ^ _ln * 0x85EBCA6Bu;                       \
        constexpr ::kernelcloak::uint32_t _kb1 =                                \
            (_cnt + 3) * 0xC2B2AE35u ^ _ln * 0x27D4EB2Du;                       \
        constexpr ::kernelcloak::uint32_t _kb2 =                                \
            (_cnt + 4) * 0x165667B1u ^ _ln * 0xE6546B64u;                       \
        constexpr ::kernelcloak::uint32_t _kb3 =                                \
            (_cnt + 5) * 0x9E3779B9u ^ _ln * 0x41C64E6Du;                       \
        constexpr ::kernelcloak::uint32_t _sh =                                 \
            (_cnt + 6) * 0x6C62272Eu ^ _ln * 0xBEA6E8C5u;                       \
        using _enc_t = ::kernelcloak::strings::detail::                         \
            layered_encrypted_string<sizeof(s),                                 \
                _ka, _kb0, _kb1, _kb2, _kb3, _sh>;                              \
        static constexpr _enc_t _src(                                           \
            s, ::kernelcloak::detail::make_index_sequence<sizeof(s)>{}          \
        );                                                                      \
        using _holder_t = ::kernelcloak::strings::detail::                      \
            layered_string_holder<sizeof(s),                                    \
                _ka, _kb0, _kb1, _kb2, _kb3, _sh>;                              \
        _holder_t h;                                                            \
        h.init(&_src);                                                          \
        return h;                                                               \
    }()

#else // KC_ENABLE_STRING_ENCRYPTION disabled

#define KC_STR_LAYERED(s)              (s)
#define KC_STR_LAYERED_HOLDER(name, s) const char* name = (s)

#endif // KC_ENABLE_STRING_ENCRYPTION
