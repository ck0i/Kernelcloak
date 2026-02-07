#pragma once
#include "../config.h"
#include "../core/types.h"
#include "../core/array.h"
#include "../core/random.h"

namespace kernelcloak {
namespace crypto {

namespace detail {

template<size_t KeyLen>
struct xor_key {
    uint8_t bytes[KeyLen];
};

template<size_t N, size_t KeyLen>
constexpr core::KArray<uint8_t, N> xor_encode(const xor_key<KeyLen>& key, const uint8_t (&input)[N]) {
    core::KArray<uint8_t, N> output{};
    uint8_t rolling = key.bytes[0];
    for (size_t i = 0; i < N; ++i) {
        uint8_t k = key.bytes[i % KeyLen] ^ rolling;
        output[i] = input[i] ^ k;
        rolling = static_cast<uint8_t>(rolling + input[i] + key.bytes[(i + 1) % KeyLen]);
    }
    return output;
}

template<size_t N, size_t KeyLen>
constexpr core::KArray<uint8_t, N> xor_encode_chars(const xor_key<KeyLen>& key, const char (&input)[N]) {
    core::KArray<uint8_t, N> output{};
    uint8_t rolling = key.bytes[0];
    for (size_t i = 0; i < N; ++i) {
        uint8_t b = static_cast<uint8_t>(input[i]);
        uint8_t k = key.bytes[i % KeyLen] ^ rolling;
        output[i] = b ^ k;
        rolling = static_cast<uint8_t>(rolling + b + key.bytes[(i + 1) % KeyLen]);
    }
    return output;
}

template<size_t N, size_t KeyLen>
KC_FORCEINLINE void xor_decode(const xor_key<KeyLen>& key, uint8_t* data) {
    uint8_t rolling = key.bytes[0];
    for (size_t i = 0; i < N; ++i) {
        uint8_t k = key.bytes[i % KeyLen] ^ rolling;
        uint8_t decoded = data[i] ^ k;
        rolling = static_cast<uint8_t>(rolling + decoded + key.bytes[(i + 1) % KeyLen]);
        data[i] = decoded;
    }
}

} // namespace detail

template<size_t N, uint32_t Seed>
class xor_encrypted {
    static constexpr size_t key_len = 16;

    static constexpr detail::xor_key<key_len> generate_key() {
        detail::xor_key<key_len> key{};
        core::ct_random rng(Seed);
        for (size_t i = 0; i < key_len; ++i)
            key.bytes[i] = static_cast<uint8_t>(rng.next() & 0xFF);
        return key;
    }

    static constexpr detail::xor_key<key_len> key_ = generate_key();

    core::KArray<uint8_t, N> data_;

public:
    constexpr xor_encrypted(const core::KArray<uint8_t, N>& encrypted)
        : data_(encrypted) {}

    KC_FORCEINLINE void decrypt(uint8_t* out) const {
        for (size_t i = 0; i < N; ++i)
            out[i] = data_[i];
        detail::xor_decode<N, key_len>(key_, out);
    }

    KC_FORCEINLINE core::KArray<uint8_t, N> decrypt() const {
        core::KArray<uint8_t, N> out{};
        for (size_t i = 0; i < N; ++i)
            out[i] = data_[i];
        detail::xor_decode<N, key_len>(key_, out.data());
        return out;
    }

    static constexpr size_t size() { return N; }
};

namespace detail {

template<size_t N, uint32_t Seed>
constexpr auto make_xor_encrypted(const uint8_t (&input)[N]) {
    constexpr size_t key_len = 16;
    core::ct_random rng(Seed);
    xor_key<key_len> key{};
    for (size_t i = 0; i < key_len; ++i)
        key.bytes[i] = static_cast<uint8_t>(rng.next() & 0xFF);
    auto enc = xor_encode<N, key_len>(key, input);
    return xor_encrypted<N, Seed>(enc);
}

template<size_t N, uint32_t Seed>
constexpr auto make_xor_from_chars(const char (&input)[N]) {
    constexpr size_t key_len = 16;
    core::ct_random rng(Seed);
    xor_key<key_len> key{};
    for (size_t i = 0; i < key_len; ++i)
        key.bytes[i] = static_cast<uint8_t>(rng.next() & 0xFF);
    auto enc = xor_encode_chars<N, key_len>(key, input);
    return xor_encrypted<N, Seed>(enc);
}

} // namespace detail

} // namespace crypto
} // namespace kernelcloak

#define KC_XOR_ENCRYPT(data) \
    ([]() { \
        constexpr auto _kc_enc = ::kernelcloak::crypto::detail::make_xor_encrypted< \
            sizeof(data), KC_RANDOM_CT()>(data); \
        return _kc_enc; \
    }())

#define KC_XOR_ENCRYPT_STR(str) \
    ([]() { \
        constexpr auto _kc_enc = ::kernelcloak::crypto::detail::make_xor_from_chars< \
            sizeof(str), KC_RANDOM_CT()>(str); \
        return _kc_enc; \
    }())
