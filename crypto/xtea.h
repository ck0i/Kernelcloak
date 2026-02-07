#pragma once
#include "../config.h"
#include "../core/types.h"
#include "../core/array.h"
#include "../core/random.h"

namespace kernelcloak {
namespace crypto {

namespace detail {

struct xtea_key {
    uint32_t k[4];
};

constexpr uint32_t xtea_delta = 0x9E3779B9u;

constexpr void xtea_encrypt_block(const xtea_key& key, uint32_t& v0, uint32_t& v1) {
    uint32_t sum = 0;
    for (int i = 0; i < KC_XTEA_ROUNDS; ++i) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key.k[sum & 3]);
        sum += xtea_delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key.k[(sum >> 11) & 3]);
    }
}

constexpr void xtea_decrypt_block(const xtea_key& key, uint32_t& v0, uint32_t& v1) {
    uint32_t sum = xtea_delta * KC_XTEA_ROUNDS;
    for (int i = 0; i < KC_XTEA_ROUNDS; ++i) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key.k[(sum >> 11) & 3]);
        sum -= xtea_delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key.k[sum & 3]);
    }
}

constexpr uint32_t read_u32_le(const uint8_t* data) {
    return static_cast<uint32_t>(data[0])
         | (static_cast<uint32_t>(data[1]) << 8)
         | (static_cast<uint32_t>(data[2]) << 16)
         | (static_cast<uint32_t>(data[3]) << 24);
}

constexpr void write_u32_le(uint8_t* data, uint32_t val) {
    data[0] = static_cast<uint8_t>(val);
    data[1] = static_cast<uint8_t>(val >> 8);
    data[2] = static_cast<uint8_t>(val >> 16);
    data[3] = static_cast<uint8_t>(val >> 24);
}

// constexpr-safe helpers that use KArray + offset instead of interior pointers
// (MSVC's constexpr evaluator can't handle &arr[off] passed to another function)
template<size_t N>
constexpr uint32_t read_u32_le_arr(const core::KArray<uint8_t, N>& arr, size_t off) {
    return static_cast<uint32_t>(arr[off])
         | (static_cast<uint32_t>(arr[off + 1]) << 8)
         | (static_cast<uint32_t>(arr[off + 2]) << 16)
         | (static_cast<uint32_t>(arr[off + 3]) << 24);
}

template<size_t N>
constexpr void write_u32_le_arr(core::KArray<uint8_t, N>& arr, size_t off, uint32_t val) {
    arr[off]     = static_cast<uint8_t>(val);
    arr[off + 1] = static_cast<uint8_t>(val >> 8);
    arr[off + 2] = static_cast<uint8_t>(val >> 16);
    arr[off + 3] = static_cast<uint8_t>(val >> 24);
}

template<size_t N>
constexpr core::KArray<uint8_t, N> xtea_encrypt_buffer(const xtea_key& key, const core::KArray<uint8_t, N>& input) {
    core::KArray<uint8_t, N> output{};

    for (size_t i = 0; i < N; ++i)
        output[i] = input[i];

    size_t full_blocks = N / 8;
    for (size_t b = 0; b < full_blocks; ++b) {
        size_t off = b * 8;
        uint32_t v0 = read_u32_le_arr(output, off);
        uint32_t v1 = read_u32_le_arr(output, off + 4);
        xtea_encrypt_block(key, v0, v1);
        write_u32_le_arr(output, off, v0);
        write_u32_le_arr(output, off + 4, v1);
    }

    // tail bytes XOR'd with key material
    size_t tail_start = full_blocks * 8;
    if (tail_start < N) {
        uint32_t pad0 = key.k[0] ^ key.k[2];
        uint32_t pad1 = key.k[1] ^ key.k[3];
        core::KArray<uint8_t, 8> pad{};
        write_u32_le_arr(pad, 0, pad0);
        write_u32_le_arr(pad, 4, pad1);
        for (size_t i = tail_start; i < N; ++i)
            output[i] ^= pad[i - tail_start];
    }

    return output;
}

template<size_t N>
KC_FORCEINLINE void xtea_decrypt_buffer(const xtea_key& key, uint8_t* data) {
    // process full 8-byte blocks
    size_t full_blocks = N / 8;
    for (size_t b = 0; b < full_blocks; ++b) {
        size_t off = b * 8;
        uint32_t v0 = read_u32_le(data + off);
        uint32_t v1 = read_u32_le(data + off + 4);
        xtea_decrypt_block(key, v0, v1);
        write_u32_le(data + off, v0);
        write_u32_le(data + off + 4, v1);
    }

    // tail bytes - same XOR as encrypt (symmetric)
    size_t tail_start = full_blocks * 8;
    if (tail_start < N) {
        uint32_t pad0 = key.k[0] ^ key.k[2];
        uint32_t pad1 = key.k[1] ^ key.k[3];
        uint8_t pad[8];
        write_u32_le(pad, pad0);
        write_u32_le(pad + 4, pad1);
        for (size_t i = tail_start; i < N; ++i)
            data[i] ^= pad[i - tail_start];
    }
}

} // namespace detail

template<size_t N, uint32_t K0, uint32_t K1, uint32_t K2, uint32_t K3>
class xtea_encrypted {
    static constexpr detail::xtea_key key_ = { { K0, K1, K2, K3 } };

    static constexpr core::KArray<uint8_t, N> encrypt_data(const uint8_t (&input)[N]) {
        core::KArray<uint8_t, N> buf{};
        for (size_t i = 0; i < N; ++i)
            buf[i] = input[i];
        return detail::xtea_encrypt_buffer<N>(key_, buf);
    }

    core::KArray<uint8_t, N> data_;

public:
    constexpr xtea_encrypted(const core::KArray<uint8_t, N>& encrypted)
        : data_(encrypted) {}

    KC_FORCEINLINE void decrypt(uint8_t* out) const {
        for (size_t i = 0; i < N; ++i)
            out[i] = data_[i];
        detail::xtea_decrypt_buffer<N>(key_, out);
    }

    KC_FORCEINLINE core::KArray<uint8_t, N> decrypt() const {
        core::KArray<uint8_t, N> out{};
        for (size_t i = 0; i < N; ++i)
            out[i] = data_[i];
        detail::xtea_decrypt_buffer<N>(key_, out.data());
        return out;
    }

    static constexpr size_t size() { return N; }
};

namespace detail {

template<size_t N, uint32_t K0, uint32_t K1, uint32_t K2, uint32_t K3>
constexpr auto make_xtea_encrypted(const uint8_t (&input)[N]) {
    core::KArray<uint8_t, N> buf{};
    for (size_t i = 0; i < N; ++i)
        buf[i] = input[i];
    auto enc = xtea_encrypt_buffer<N>({ { K0, K1, K2, K3 } }, buf);
    return xtea_encrypted<N, K0, K1, K2, K3>(enc);
}

template<size_t N, uint32_t K0, uint32_t K1, uint32_t K2, uint32_t K3>
constexpr auto make_xtea_from_chars(const char (&input)[N]) {
    core::KArray<uint8_t, N> buf{};
    for (size_t i = 0; i < N; ++i)
        buf[i] = static_cast<uint8_t>(input[i]);
    auto enc = xtea_encrypt_buffer<N>({ { K0, K1, K2, K3 } }, buf);
    return xtea_encrypted<N, K0, K1, K2, K3>(enc);
}

} // namespace detail

} // namespace crypto
} // namespace kernelcloak

// encrypt arbitrary byte data with per-site XTEA keys
#define KC_XTEA_ENCRYPT(data) \
    ([]() { \
        constexpr auto _kc_enc = ::kernelcloak::crypto::detail::make_xtea_encrypted< \
            sizeof(data), \
            KC_RANDOM_CT(), KC_RANDOM_CT(), KC_RANDOM_CT(), KC_RANDOM_CT()>(data); \
        return _kc_enc; \
    }())

// encrypt a string literal with XTEA
#define KC_XTEA_ENCRYPT_STR(str) \
    ([]() { \
        constexpr auto _kc_enc = ::kernelcloak::crypto::detail::make_xtea_from_chars< \
            sizeof(str), \
            KC_RANDOM_CT(), KC_RANDOM_CT(), KC_RANDOM_CT(), KC_RANDOM_CT()>(str); \
        return _kc_enc; \
    }())
