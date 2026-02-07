#pragma once
#include "../config.h"
#include "types.h"

namespace kernelcloak {
namespace core {

// stack-allocated fixed-size array, constexpr-friendly, no heap
// aggregate type when possible for brace-init
template<typename T, size_t N>
struct KArray {
    static_assert(N > 0, "KArray size must be > 0");

    // public data member for aggregate initialization
    T m_data[N];

    // element access
    KC_FORCEINLINE constexpr T& operator[](size_t i) noexcept { return m_data[i]; }
    KC_FORCEINLINE constexpr const T& operator[](size_t i) const noexcept { return m_data[i]; }

    KC_FORCEINLINE constexpr T& at(size_t i) noexcept { return m_data[i]; }
    KC_FORCEINLINE constexpr const T& at(size_t i) const noexcept { return m_data[i]; }

    KC_FORCEINLINE constexpr T& front() noexcept { return m_data[0]; }
    KC_FORCEINLINE constexpr const T& front() const noexcept { return m_data[0]; }

    KC_FORCEINLINE constexpr T& back() noexcept { return m_data[N - 1]; }
    KC_FORCEINLINE constexpr const T& back() const noexcept { return m_data[N - 1]; }

    // capacity
    KC_FORCEINLINE static constexpr size_t size() noexcept { return N; }
    KC_FORCEINLINE static constexpr bool empty() noexcept { return false; }
    KC_FORCEINLINE static constexpr size_t max_size() noexcept { return N; }

    // data access
    KC_FORCEINLINE constexpr T* data() noexcept { return m_data; }
    KC_FORCEINLINE constexpr const T* data() const noexcept { return m_data; }

    // iterators
    KC_FORCEINLINE constexpr T* begin() noexcept { return m_data; }
    KC_FORCEINLINE constexpr const T* begin() const noexcept { return m_data; }
    KC_FORCEINLINE constexpr T* end() noexcept { return m_data + N; }
    KC_FORCEINLINE constexpr const T* end() const noexcept { return m_data + N; }

    // fill
    KC_FORCEINLINE constexpr void fill(const T& value) noexcept {
        for (size_t i = 0; i < N; ++i) {
            m_data[i] = value;
        }
    }

    // swap
    KC_FORCEINLINE constexpr void swap(KArray& other) noexcept {
        for (size_t i = 0; i < N; ++i) {
            T tmp = detail::kc_move(m_data[i]);
            m_data[i] = detail::kc_move(other.m_data[i]);
            other.m_data[i] = detail::kc_move(tmp);
        }
    }
};

// deduction guide
template<typename T, typename... U>
KArray(T, U...) -> KArray<T, 1 + sizeof...(U)>;

// zero-size specialization - still valid type, just empty
template<typename T>
struct KArray<T, 0> {
    KC_FORCEINLINE static constexpr size_t size() noexcept { return 0; }
    KC_FORCEINLINE static constexpr bool empty() noexcept { return true; }
    KC_FORCEINLINE static constexpr size_t max_size() noexcept { return 0; }
    KC_FORCEINLINE constexpr T* data() noexcept { return nullptr; }
    KC_FORCEINLINE constexpr const T* data() const noexcept { return nullptr; }
    KC_FORCEINLINE constexpr T* begin() noexcept { return nullptr; }
    KC_FORCEINLINE constexpr const T* begin() const noexcept { return nullptr; }
    KC_FORCEINLINE constexpr T* end() noexcept { return nullptr; }
    KC_FORCEINLINE constexpr const T* end() const noexcept { return nullptr; }
    KC_FORCEINLINE constexpr void fill(const T&) noexcept {}
    KC_FORCEINLINE constexpr void swap(KArray&) noexcept {}
};

} // namespace core
} // namespace kernelcloak
