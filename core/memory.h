#pragma once
#include "../config.h"
#include "types.h"

#pragma warning(push)
#pragma warning(disable: 4471)  // forward decl of unscoped enum (POOL_TYPE)
#pragma warning(disable: 4005)  // macro redefinition (ntddk vs wdm overlap)

extern "C" {
    // pool allocation - actual ntoskrnl exports
#if !defined(_NTDDK_) && !defined(_WDMDDK_)
    void* __stdcall ExAllocatePool2(
        unsigned __int64 Flags,
        kernelcloak::size_t NumberOfBytes,
        unsigned long Tag
    );

    void __stdcall ExFreePoolWithTag(
        void* P,
        unsigned long Tag
    );
#endif

    // kernel memcpy/memset/memmove - available as compiler intrinsics and/or kernel exports.
    // note: Rtl*Memory helpers are macros in WDK headers; avoid declaring them here.
    void* __cdecl memcpy(void* dst, const void* src, kernelcloak::size_t size);
    void* __cdecl memset(void* dst, int val, kernelcloak::size_t size);
    void* __cdecl memmove(void* dst, const void* src, kernelcloak::size_t size);
}

#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED 0x0000000000000040ULL
#endif

#ifndef POOL_FLAG_PAGED
#define POOL_FLAG_PAGED 0x0000000000000100ULL
#endif

// placement new - kernel mode builds often don't include <new>. avoid redefining if <new> was included.
#if !defined(_KC_PLACEMENT_NEW_DEFINED) && !defined(_NEW_) && !defined(_INC_NEW)
#define _KC_PLACEMENT_NEW_DEFINED
inline void* operator new(kernelcloak::size_t, void* p) noexcept { return p; }
inline void* operator new[](kernelcloak::size_t, void* p) noexcept { return p; }
inline void operator delete(void*, void*) noexcept {}
inline void operator delete[](void*, void*) noexcept {}
#endif

namespace kernelcloak {
namespace core {

KC_FORCEINLINE void* kc_memcpy(void* dst, const void* src, size_t n) {
    memcpy(dst, src, n);
    return dst;
}

KC_FORCEINLINE void* kc_memset(void* dst, int val, size_t n) {
    memset(dst, val, n);
    return dst;
}

KC_FORCEINLINE void* kc_memmove(void* dst, const void* src, size_t n) {
    memmove(dst, src, n);
    return dst;
}

KC_FORCEINLINE void kc_memzero(void* dst, size_t n) {
    memset(dst, 0, n);
}

KC_FORCEINLINE void* kc_pool_alloc(size_t size, uint64_t flags = POOL_FLAG_NON_PAGED, uint32_t tag = KC_POOL_TAG) {
    return ExAllocatePool2(flags, size, tag);
}

KC_FORCEINLINE void kc_pool_free(void* ptr, uint32_t tag = KC_POOL_TAG) {
    if (ptr) {
        ExFreePoolWithTag(ptr, tag);
    }
}

// RAII kernel pool buffer
// non-paged by default (safe at DISPATCH_LEVEL), supports move, deleted copy
template<typename T>
class KernelBuffer {
    T* m_ptr = nullptr;
    size_t m_size = 0;
    uint32_t m_tag = KC_POOL_TAG;

public:
    KernelBuffer() noexcept = default;

    explicit KernelBuffer(size_t count, uint64_t flags = POOL_FLAG_NON_PAGED, uint32_t tag = KC_POOL_TAG) noexcept
        : m_tag(tag)
    {
        if (count == 0)
            return;

        constexpr size_t kc_size_max = ~static_cast<size_t>(0);
        if (count > (kc_size_max / sizeof(T)))
            return;

        m_size = count * sizeof(T);
        m_ptr = static_cast<T*>(ExAllocatePool2(flags, m_size, m_tag));
        if (m_ptr) {
            kc_memzero(m_ptr, m_size);
        } else {
            m_size = 0;
        }
    }

    ~KernelBuffer() noexcept {
        reset();
    }

    KernelBuffer(KernelBuffer&& other) noexcept
        : m_ptr(detail::kc_exchange(other.m_ptr, nullptr))
        , m_size(detail::kc_exchange(other.m_size, static_cast<size_t>(0)))
        , m_tag(other.m_tag)
    {}

    KernelBuffer& operator=(KernelBuffer&& other) noexcept {
        if (this != &other) {
            reset();
            m_ptr = detail::kc_exchange(other.m_ptr, nullptr);
            m_size = detail::kc_exchange(other.m_size, static_cast<size_t>(0));
            m_tag = other.m_tag;
        }
        return *this;
    }

    KernelBuffer(const KernelBuffer&) = delete;
    KernelBuffer& operator=(const KernelBuffer&) = delete;

    void reset() noexcept {
        if (auto* p = detail::kc_exchange(m_ptr, nullptr)) {
            ExFreePoolWithTag(p, m_tag);
        }
        m_size = 0;
    }

    KC_FORCEINLINE T* get() noexcept { return m_ptr; }
    KC_FORCEINLINE const T* get() const noexcept { return m_ptr; }
    KC_FORCEINLINE size_t size_bytes() const noexcept { return m_size; }
    KC_FORCEINLINE size_t count() const noexcept { return m_size / sizeof(T); }
    KC_FORCEINLINE explicit operator bool() const noexcept { return m_ptr != nullptr; }

    KC_FORCEINLINE T& operator[](size_t i) noexcept { return m_ptr[i]; }
    KC_FORCEINLINE const T& operator[](size_t i) const noexcept { return m_ptr[i]; }

    KC_FORCEINLINE T* operator->() noexcept { return m_ptr; }
    KC_FORCEINLINE const T* operator->() const noexcept { return m_ptr; }

    KC_FORCEINLINE T& operator*() noexcept { return *m_ptr; }
    KC_FORCEINLINE const T& operator*() const noexcept { return *m_ptr; }

    KC_FORCEINLINE T* release() noexcept {
        m_size = 0;
        return detail::kc_exchange(m_ptr, nullptr);
    }

    KC_FORCEINLINE T* begin() noexcept { return m_ptr; }
    KC_FORCEINLINE T* end() noexcept { return m_ptr + count(); }
    KC_FORCEINLINE const T* begin() const noexcept { return m_ptr; }
    KC_FORCEINLINE const T* end() const noexcept { return m_ptr + count(); }
};

template<typename T>
KC_FORCEINLINE KernelBuffer<T> make_kernel_buffer(size_t count, uint64_t flags = POOL_FLAG_NON_PAGED) {
    return KernelBuffer<T>(count, flags);
}

} // namespace core
} // namespace kernelcloak

#pragma warning(pop)
