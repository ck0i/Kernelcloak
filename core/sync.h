#pragma once
#include "../config.h"
#include "types.h"

#pragma warning(push)
#pragma warning(disable: 4201) // nameless struct/union
#pragma warning(disable: 4324) // structure padded due to alignment

#if !defined(_NTDDK_) && !defined(_WDMDDK_)
extern "C" {
    // avoid defining WDK typedef names (KSPIN_LOCK/KIRQL) so include order doesn't break builds.
    // these signatures match the WDK on both x86/x64 (KSPIN_LOCK == ULONG_PTR, KIRQL == UCHAR).
    void __stdcall KeInitializeSpinLock(kernelcloak::uintptr_t* SpinLock);
    void __stdcall KeAcquireSpinLock(kernelcloak::uintptr_t* SpinLock, unsigned char* OldIrql);
    void __stdcall KeReleaseSpinLock(kernelcloak::uintptr_t* SpinLock, unsigned char NewIrql);
    void __stdcall KeAcquireSpinLockAtDpcLevel(kernelcloak::uintptr_t* SpinLock);
    void __stdcall KeReleaseSpinLockFromDpcLevel(kernelcloak::uintptr_t* SpinLock);
    unsigned char __stdcall KeGetCurrentIrql();
}
#endif

extern "C" {
    // interlocked intrinsics - compiler builtins, always need declaration
    long _InterlockedIncrement(long volatile*);
    long _InterlockedDecrement(long volatile*);
    long _InterlockedExchange(long volatile*, long);
    long _InterlockedCompareExchange(long volatile*, long, long);
    long _InterlockedExchangeAdd(long volatile*, long);
    long _InterlockedOr(long volatile*, long);
    long _InterlockedAnd(long volatile*, long);
    long _InterlockedXor(long volatile*, long);

    __int64 _InterlockedIncrement64(__int64 volatile*);
    __int64 _InterlockedDecrement64(__int64 volatile*);
    __int64 _InterlockedExchange64(__int64 volatile*, __int64);
    __int64 _InterlockedCompareExchange64(__int64 volatile*, __int64, __int64);
    __int64 _InterlockedExchangeAdd64(__int64 volatile*, __int64);
    __int64 _InterlockedOr64(__int64 volatile*, __int64);
    __int64 _InterlockedAnd64(__int64 volatile*, __int64);
    __int64 _InterlockedXor64(__int64 volatile*, __int64);

    void* _InterlockedExchangePointer(void* volatile*, void*);
    void* _InterlockedCompareExchangePointer(void* volatile*, void*, void*);
}

#pragma intrinsic(_InterlockedIncrement)
#pragma intrinsic(_InterlockedDecrement)
#pragma intrinsic(_InterlockedExchange)
#pragma intrinsic(_InterlockedCompareExchange)
#pragma intrinsic(_InterlockedExchangeAdd)
#pragma intrinsic(_InterlockedOr)
#pragma intrinsic(_InterlockedAnd)
#pragma intrinsic(_InterlockedXor)
#pragma intrinsic(_InterlockedIncrement64)
#pragma intrinsic(_InterlockedDecrement64)
#pragma intrinsic(_InterlockedExchange64)
#pragma intrinsic(_InterlockedCompareExchange64)
#pragma intrinsic(_InterlockedExchangeAdd64)
#pragma intrinsic(_InterlockedOr64)
#pragma intrinsic(_InterlockedAnd64)
#pragma intrinsic(_InterlockedXor64)
#pragma intrinsic(_InterlockedExchangePointer)
#pragma intrinsic(_InterlockedCompareExchangePointer)

// irql constants
#ifndef PASSIVE_LEVEL
#define PASSIVE_LEVEL 0
#endif
#ifndef APC_LEVEL
#define APC_LEVEL 1
#endif
#ifndef DISPATCH_LEVEL
#define DISPATCH_LEVEL 2
#endif

namespace kernelcloak {
namespace core {

// RAII spinlock wrapper with IRQL save/restore
class KSpinLock {
    uintptr_t m_lock = 0;

public:
    KSpinLock() noexcept {
        KeInitializeSpinLock(&m_lock);
    }

    // non-copyable, non-movable
    KSpinLock(const KSpinLock&) = delete;
    KSpinLock& operator=(const KSpinLock&) = delete;
    KSpinLock(KSpinLock&&) = delete;
    KSpinLock& operator=(KSpinLock&&) = delete;

    KC_FORCEINLINE void acquire(unsigned char* old_irql) noexcept {
        KeAcquireSpinLock(&m_lock, old_irql);
    }

    KC_FORCEINLINE void release(unsigned char old_irql) noexcept {
        KeReleaseSpinLock(&m_lock, old_irql);
    }

    // for callers already at DISPATCH_LEVEL
    KC_FORCEINLINE void acquire_at_dpc() noexcept {
        KeAcquireSpinLockAtDpcLevel(&m_lock);
    }

    KC_FORCEINLINE void release_from_dpc() noexcept {
        KeReleaseSpinLockFromDpcLevel(&m_lock);
    }

    KC_FORCEINLINE uintptr_t* native() noexcept { return &m_lock; }

    // scoped guard - acquires on construction, releases on destruction
    class Guard {
        KSpinLock& m_parent;
        unsigned char m_old_irql = PASSIVE_LEVEL;
        bool m_owned = false;

    public:
        explicit Guard(KSpinLock& lock) noexcept
            : m_parent(lock), m_owned(true)
        {
            m_parent.acquire(&m_old_irql);
        }

        ~Guard() noexcept {
            if (m_owned) {
                m_parent.release(m_old_irql);
            }
        }

        Guard(const Guard&) = delete;
        Guard& operator=(const Guard&) = delete;
        Guard(Guard&&) = delete;
        Guard& operator=(Guard&&) = delete;

        KC_FORCEINLINE unsigned char saved_irql() const noexcept { return m_old_irql; }
    };

    // scoped guard for code already at DISPATCH_LEVEL
    class DpcGuard {
        KSpinLock& m_parent;
        bool m_owned = false;

    public:
        explicit DpcGuard(KSpinLock& lock) noexcept
            : m_parent(lock), m_owned(true)
        {
            m_parent.acquire_at_dpc();
        }

        ~DpcGuard() noexcept {
            if (m_owned) {
                m_parent.release_from_dpc();
            }
        }

        DpcGuard(const DpcGuard&) = delete;
        DpcGuard& operator=(const DpcGuard&) = delete;
        DpcGuard(DpcGuard&&) = delete;
        DpcGuard& operator=(DpcGuard&&) = delete;
    };

    // convenience
    KC_FORCEINLINE Guard lock() noexcept { return Guard(*this); }
    KC_FORCEINLINE DpcGuard lock_at_dpc() noexcept { return DpcGuard(*this); }
};

// interlocked operations dispatcher - selects 32/64 bit intrinsics
namespace detail_sync {

template<typename T, size_t = sizeof(T)>
struct interlocked_ops;

// 32-bit specialization
template<typename T>
struct interlocked_ops<T, 4> {
    using storage_type = long;
    using volatile_ptr = long volatile*;

    static KC_FORCEINLINE T increment(volatile T* target) noexcept {
        return static_cast<T>(_InterlockedIncrement(reinterpret_cast<volatile_ptr>(target)));
    }
    static KC_FORCEINLINE T decrement(volatile T* target) noexcept {
        return static_cast<T>(_InterlockedDecrement(reinterpret_cast<volatile_ptr>(target)));
    }
    static KC_FORCEINLINE T exchange(volatile T* target, T value) noexcept {
        return static_cast<T>(_InterlockedExchange(
            reinterpret_cast<volatile_ptr>(target),
            static_cast<storage_type>(value)));
    }
    static KC_FORCEINLINE T compare_exchange(volatile T* target, T exchange_val, T comparand) noexcept {
        return static_cast<T>(_InterlockedCompareExchange(
            reinterpret_cast<volatile_ptr>(target),
            static_cast<storage_type>(exchange_val),
            static_cast<storage_type>(comparand)));
    }
    static KC_FORCEINLINE T add(volatile T* target, T value) noexcept {
        return static_cast<T>(_InterlockedExchangeAdd(
            reinterpret_cast<volatile_ptr>(target),
            static_cast<storage_type>(value)));
    }
    static KC_FORCEINLINE T or_op(volatile T* target, T value) noexcept {
        return static_cast<T>(_InterlockedOr(
            reinterpret_cast<volatile_ptr>(target),
            static_cast<storage_type>(value)));
    }
    static KC_FORCEINLINE T and_op(volatile T* target, T value) noexcept {
        return static_cast<T>(_InterlockedAnd(
            reinterpret_cast<volatile_ptr>(target),
            static_cast<storage_type>(value)));
    }
    static KC_FORCEINLINE T xor_op(volatile T* target, T value) noexcept {
        return static_cast<T>(_InterlockedXor(
            reinterpret_cast<volatile_ptr>(target),
            static_cast<storage_type>(value)));
    }
    static KC_FORCEINLINE T load(const volatile T* target) noexcept {
        // interlocked compare-exchange with itself to get an atomic read
        return static_cast<T>(_InterlockedCompareExchange(
            const_cast<volatile_ptr>(reinterpret_cast<const volatile long*>(target)), 0, 0));
    }
    static KC_FORCEINLINE void store(volatile T* target, T value) noexcept {
        _InterlockedExchange(
            reinterpret_cast<volatile_ptr>(target),
            static_cast<storage_type>(value));
    }
};

// 64-bit specialization
template<typename T>
struct interlocked_ops<T, 8> {
    using storage_type = __int64;
    using volatile_ptr = __int64 volatile*;

    static KC_FORCEINLINE T increment(volatile T* target) noexcept {
        return static_cast<T>(_InterlockedIncrement64(reinterpret_cast<volatile_ptr>(target)));
    }
    static KC_FORCEINLINE T decrement(volatile T* target) noexcept {
        return static_cast<T>(_InterlockedDecrement64(reinterpret_cast<volatile_ptr>(target)));
    }
    static KC_FORCEINLINE T exchange(volatile T* target, T value) noexcept {
        return static_cast<T>(_InterlockedExchange64(
            reinterpret_cast<volatile_ptr>(target),
            static_cast<storage_type>(value)));
    }
    static KC_FORCEINLINE T compare_exchange(volatile T* target, T exchange_val, T comparand) noexcept {
        return static_cast<T>(_InterlockedCompareExchange64(
            reinterpret_cast<volatile_ptr>(target),
            static_cast<storage_type>(exchange_val),
            static_cast<storage_type>(comparand)));
    }
    static KC_FORCEINLINE T add(volatile T* target, T value) noexcept {
        return static_cast<T>(_InterlockedExchangeAdd64(
            reinterpret_cast<volatile_ptr>(target),
            static_cast<storage_type>(value)));
    }
    static KC_FORCEINLINE T or_op(volatile T* target, T value) noexcept {
        return static_cast<T>(_InterlockedOr64(
            reinterpret_cast<volatile_ptr>(target),
            static_cast<storage_type>(value)));
    }
    static KC_FORCEINLINE T and_op(volatile T* target, T value) noexcept {
        return static_cast<T>(_InterlockedAnd64(
            reinterpret_cast<volatile_ptr>(target),
            static_cast<storage_type>(value)));
    }
    static KC_FORCEINLINE T xor_op(volatile T* target, T value) noexcept {
        return static_cast<T>(_InterlockedXor64(
            reinterpret_cast<volatile_ptr>(target),
            static_cast<storage_type>(value)));
    }
    static KC_FORCEINLINE T load(const volatile T* target) noexcept {
        return static_cast<T>(_InterlockedCompareExchange64(
            const_cast<volatile_ptr>(reinterpret_cast<const volatile __int64*>(target)), 0, 0));
    }
    static KC_FORCEINLINE void store(volatile T* target, T value) noexcept {
        _InterlockedExchange64(
            reinterpret_cast<volatile_ptr>(target),
            static_cast<storage_type>(value));
    }
};

// pointer specialization
template<typename T>
struct interlocked_ops<T*, 8> {
    static KC_FORCEINLINE T* exchange(T* volatile* target, T* value) noexcept {
        return static_cast<T*>(_InterlockedExchangePointer(
            reinterpret_cast<void* volatile*>(target), value));
    }
    static KC_FORCEINLINE T* compare_exchange(T* volatile* target, T* exchange_val, T* comparand) noexcept {
        return static_cast<T*>(_InterlockedCompareExchangePointer(
            reinterpret_cast<void* volatile*>(target), exchange_val, comparand));
    }
    static KC_FORCEINLINE T* load(T* const volatile* target) noexcept {
        return static_cast<T*>(_InterlockedCompareExchangePointer(
            const_cast<void* volatile*>(reinterpret_cast<void* const volatile*>(target)),
            nullptr, nullptr));
    }
    static KC_FORCEINLINE void store(T* volatile* target, T* value) noexcept {
        _InterlockedExchangePointer(
            reinterpret_cast<void* volatile*>(target), value);
    }
};

} // namespace detail_sync

// kernel-safe atomic wrapper using Interlocked* family
// safe at DISPATCH_LEVEL (no paged pool, no blocking)
template<typename T>
class KernelAtomic {
    static_assert(sizeof(T) == 4 || sizeof(T) == 8,
        "KernelAtomic only supports 32 and 64 bit types");

    using ops = detail_sync::interlocked_ops<T>;
    volatile T m_value;

public:
    KernelAtomic() noexcept : m_value{} {}
    explicit KernelAtomic(T initial) noexcept : m_value(initial) {}

    // no copy/move - atomics should be stationary
    KernelAtomic(const KernelAtomic&) = delete;
    KernelAtomic& operator=(const KernelAtomic&) = delete;

    KC_FORCEINLINE T load() const noexcept {
        return ops::load(&m_value);
    }

    KC_FORCEINLINE void store(T value) noexcept {
        ops::store(&m_value, value);
    }

    KC_FORCEINLINE T exchange(T value) noexcept {
        return ops::exchange(&m_value, value);
    }

    // returns the OLD value at m_value. if old == comparand, exchange happened.
    KC_FORCEINLINE T compare_exchange(T exchange_val, T comparand) noexcept {
        return ops::compare_exchange(&m_value, exchange_val, comparand);
    }

    // returns true if exchange succeeded
    KC_FORCEINLINE bool compare_exchange_strong(T& expected, T desired) noexcept {
        T old = ops::compare_exchange(&m_value, desired, expected);
        if (old == expected) {
            return true;
        }
        expected = old;
        return false;
    }

    KC_FORCEINLINE T increment() noexcept { return ops::increment(&m_value); }
    KC_FORCEINLINE T decrement() noexcept { return ops::decrement(&m_value); }
    KC_FORCEINLINE T add(T value) noexcept { return ops::add(&m_value, value); }
    KC_FORCEINLINE T fetch_or(T value) noexcept { return ops::or_op(&m_value, value); }
    KC_FORCEINLINE T fetch_and(T value) noexcept { return ops::and_op(&m_value, value); }
    KC_FORCEINLINE T fetch_xor(T value) noexcept { return ops::xor_op(&m_value, value); }

    // operator overloads for convenience
    KC_FORCEINLINE operator T() const noexcept { return load(); }
    KC_FORCEINLINE T operator=(T value) noexcept { store(value); return value; }
    KC_FORCEINLINE T operator++() noexcept { return increment(); }
    KC_FORCEINLINE T operator--() noexcept { return decrement(); }
    KC_FORCEINLINE T operator++(int) noexcept { return increment() - 1; }
    KC_FORCEINLINE T operator--(int) noexcept { return decrement() + 1; }
    KC_FORCEINLINE T operator+=(T v) noexcept { return add(v) + v; }
    KC_FORCEINLINE T operator|=(T v) noexcept { return fetch_or(v) | v; }
    KC_FORCEINLINE T operator&=(T v) noexcept { return fetch_and(v) & v; }
    KC_FORCEINLINE T operator^=(T v) noexcept { return fetch_xor(v) ^ v; }
};

// pointer specialization
template<typename T>
class KernelAtomic<T*> {
    using ops = detail_sync::interlocked_ops<T*>;
    T* volatile m_value;

public:
    KernelAtomic() noexcept : m_value(nullptr) {}
    explicit KernelAtomic(T* initial) noexcept : m_value(initial) {}

    KernelAtomic(const KernelAtomic&) = delete;
    KernelAtomic& operator=(const KernelAtomic&) = delete;

    KC_FORCEINLINE T* load() const noexcept {
        return ops::load(&m_value);
    }

    KC_FORCEINLINE void store(T* value) noexcept {
        ops::store(&m_value, value);
    }

    KC_FORCEINLINE T* exchange(T* value) noexcept {
        return ops::exchange(&m_value, value);
    }

    KC_FORCEINLINE bool compare_exchange_strong(T*& expected, T* desired) noexcept {
        T* old = ops::compare_exchange(&m_value, desired, expected);
        if (old == expected) {
            return true;
        }
        expected = old;
        return false;
    }

    KC_FORCEINLINE operator T*() const noexcept { return load(); }
    KC_FORCEINLINE T* operator=(T* value) noexcept { store(value); return value; }
    KC_FORCEINLINE T* operator->() const noexcept { return load(); }
    KC_FORCEINLINE T& operator*() const noexcept { return *load(); }
};

} // namespace core
} // namespace kernelcloak

#pragma warning(pop)
