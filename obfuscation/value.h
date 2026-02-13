#pragma once
#include "../config.h"
#include "../core/types.h"

#if KC_ENABLE_VALUE_OBFUSCATION

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace kernelcloak {
namespace obfuscation {
namespace detail {

// compiler barrier to prevent MSVC from folding XOR pairs
KC_FORCEINLINE void compiler_barrier() {
#ifdef _MSC_VER
    _ReadWriteBarrier();
#else
    __asm__ __volatile__("" ::: "memory");
#endif
}

// obfuscated integer storage - value XOR'd with compile-time key
// dispatch is handled by obfuscated_value alias, no SFINAE needed here
template<typename T, uint32_t Key>
class obfuscated_int {
    volatile T stored_;

    static KC_FORCEINLINE T encode(T val) {
        return val ^ static_cast<T>(Key);
    }

    static KC_FORCEINLINE T decode(T val) {
        return val ^ static_cast<T>(Key);
    }

public:
    KC_FORCEINLINE obfuscated_int() : stored_(encode(T(0))) {}

    KC_FORCEINLINE obfuscated_int(T val) : stored_(encode(val)) {}

    KC_FORCEINLINE operator T() const {
        T tmp = stored_;
        compiler_barrier();
        return decode(tmp);
    }

    KC_FORCEINLINE obfuscated_int& operator=(T val) {
        stored_ = encode(val);
        return *this;
    }

    KC_FORCEINLINE obfuscated_int& operator+=(T val) {
        T cur = decode(stored_);
        stored_ = encode(cur + val);
        return *this;
    }

    KC_FORCEINLINE obfuscated_int& operator-=(T val) {
        T cur = decode(stored_);
        stored_ = encode(cur - val);
        return *this;
    }

    KC_FORCEINLINE obfuscated_int& operator*=(T val) {
        T cur = decode(stored_);
        stored_ = encode(cur * val);
        return *this;
    }

    KC_FORCEINLINE obfuscated_int& operator&=(T val) {
        T cur = decode(stored_);
        stored_ = encode(cur & val);
        return *this;
    }

    KC_FORCEINLINE obfuscated_int& operator|=(T val) {
        T cur = decode(stored_);
        stored_ = encode(cur | val);
        return *this;
    }

    KC_FORCEINLINE obfuscated_int& operator^=(T val) {
        T cur = decode(stored_);
        stored_ = encode(cur ^ val);
        return *this;
    }

    KC_FORCEINLINE obfuscated_int& operator++() {
        T cur = decode(stored_);
        stored_ = encode(cur + T(1));
        return *this;
    }

    KC_FORCEINLINE T operator++(int) {
        T cur = decode(stored_);
        stored_ = encode(cur + T(1));
        return cur;
    }

    KC_FORCEINLINE obfuscated_int& operator--() {
        T cur = decode(stored_);
        stored_ = encode(cur - T(1));
        return *this;
    }

    KC_FORCEINLINE T operator--(int) {
        T cur = decode(stored_);
        stored_ = encode(cur - T(1));
        return cur;
    }
};

// obfuscated pointer storage - XOR'd with compile-time key
template<typename T, uint32_t Key>
class obfuscated_ptr {
    volatile uintptr_t stored_;

    static KC_FORCEINLINE uintptr_t encode(T val) {
        return reinterpret_cast<uintptr_t>(val) ^ static_cast<uintptr_t>(Key);
    }

    static KC_FORCEINLINE T decode(uintptr_t val) {
        return reinterpret_cast<T>(val ^ static_cast<uintptr_t>(Key));
    }

public:
    KC_FORCEINLINE obfuscated_ptr() : stored_(encode(nullptr)) {}

    KC_FORCEINLINE obfuscated_ptr(T val) : stored_(encode(val)) {}

    KC_FORCEINLINE operator T() const {
        uintptr_t tmp = stored_;
        compiler_barrier();
        return decode(tmp);
    }

    KC_FORCEINLINE obfuscated_ptr& operator=(T val) {
        stored_ = encode(val);
        return *this;
    }

    KC_FORCEINLINE auto operator*() const -> decltype(*static_cast<T>(nullptr)) {
        return *static_cast<T>(decode(stored_));
    }

    KC_FORCEINLINE T operator->() const {
        return decode(stored_);
    }

    KC_FORCEINLINE bool operator==(T other) const {
        return decode(stored_) == other;
    }

    KC_FORCEINLINE bool operator!=(T other) const {
        return decode(stored_) != other;
    }
};

// type dispatcher - picks int vs ptr implementation
template<typename T, uint32_t Key>
using obfuscated_value = kernelcloak::detail::conditional_t<
    kernelcloak::detail::is_pointer<T>::value,
    obfuscated_ptr<T, Key>,
    obfuscated_int<T, Key>
>;

} // namespace detail
} // namespace obfuscation
} // namespace kernelcloak

#define KC_INT(x) \
    ::kernelcloak::obfuscation::detail::obfuscated_value< \
        decltype(x), \
        static_cast<::kernelcloak::uint32_t>( \
            (__COUNTER__ + 1) * 0x45D9F3Bu ^ __LINE__ * 0x1B873593u \
        )>(x)

#else // KC_ENABLE_VALUE_OBFUSCATION disabled

#define KC_INT(x) (x)

#endif // KC_ENABLE_VALUE_OBFUSCATION
