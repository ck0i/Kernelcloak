#pragma once
#include "../config.h"
#include "../core/types.h"
#include "../core/memory.h"
#include "../crypto/hash.h"

#if KC_ENABLE_ANTI_VM

extern "C" {
    void __cpuid(int cpuInfo[4], int function_id);
    unsigned __int64 __readmsr(unsigned long register_id);
}

#if !defined(_NTDDK_) && !defined(_WDMDDK_)
extern "C" {
#ifndef _KC_UNICODE_STRING_DEFINED
#define _KC_UNICODE_STRING_DEFINED
    struct _UNICODE_STRING {
        unsigned short Length;
        unsigned short MaximumLength;
        wchar_t* Buffer;
    };
    using UNICODE_STRING = _UNICODE_STRING;
#endif
    using PUNICODE_STRING = UNICODE_STRING*;

    // IRQL: PASSIVE_LEVEL
    long __stdcall ZwOpenKey(void** KeyHandle, unsigned long DesiredAccess, void* ObjectAttributes);
    long __stdcall ZwQueryValueKey(void* KeyHandle, UNICODE_STRING* ValueName,
                                   unsigned long KeyValueInformationClass,
                                   void* KeyValueInformation, unsigned long Length,
                                   unsigned long* ResultLength);
    long __stdcall ZwClose(void* Handle);
    void __stdcall RtlInitUnicodeString(UNICODE_STRING* DestinationString, const wchar_t* SourceString);
    unsigned char __stdcall MmIsAddressValid(void* VirtualAddress);
    void __stdcall KeBugCheck(unsigned long BugCheckCode);
}
#endif

#pragma intrinsic(__cpuid)

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040
#endif
#ifndef OBJ_KERNEL_HANDLE
#define OBJ_KERNEL_HANDLE 0x00000200
#endif
#ifndef KEY_READ
#define KEY_READ 0x20019
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000L
#endif
// only define as macro when ntddk.h isn't present (it's an enum constant there)
#if !defined(_NTDDK_) && !defined(_WDMDDK_)
#ifndef KeyValuePartialInformation
#define KeyValuePartialInformation 2
#endif
#endif

namespace kernelcloak {
namespace security {

namespace detail {

struct kc_object_attributes {
    unsigned long Length;
    void* RootDirectory;
    UNICODE_STRING* ObjectName;
    unsigned long Attributes;
    void* SecurityDescriptor;
    void* SecurityQualityOfService;
};

struct key_value_partial_info {
    unsigned long TitleIndex;
    unsigned long Type;
    unsigned long DataLength;
    unsigned char Data[1];
};

// known hypervisor vendor string hashes (12-byte CPUID vendor, FNV-1a 64-bit)
namespace vm_vendors {
    constexpr uint64_t vmware     = crypto::detail::fnv1a_64("VMwareVMware", 12);
    constexpr uint64_t virtualbox = crypto::detail::fnv1a_64("VBoxVBoxVBox", 12);
    constexpr uint64_t hyperv     = crypto::detail::fnv1a_64("Microsoft Hv", 12);
    constexpr uint64_t kvm        = crypto::detail::fnv1a_64("KVMKVMKVM\0\0\0", 12);
    constexpr uint64_t xen        = crypto::detail::fnv1a_64("XenVMMXenVMM", 12);
    constexpr uint64_t qemu       = crypto::detail::fnv1a_64("TCGTCGTCGTCG", 12);
    constexpr uint64_t parallels  = crypto::detail::fnv1a_64("prl hyperv  ", 12);
}

// CPUID leaf 1, ECX bit 31
KC_NOINLINE bool check_hypervisor_bit() {
    __try {
        int regs[4] = {};
        __cpuid(regs, 1);
        return (regs[2] & (1 << 31)) != 0;
    } __except (1) {
        return false;
    }
}

// CPUID leaf 0x40000000 vendor string -> FNV-1a hash, or 0
KC_NOINLINE uint64_t get_hypervisor_vendor() {
    __try {
        if (!check_hypervisor_bit())
            return 0;

        int regs[4] = {};
        __cpuid(regs, 0x40000000);

        char vendor[13] = {};
        *reinterpret_cast<int*>(&vendor[0]) = regs[1];
        *reinterpret_cast<int*>(&vendor[4]) = regs[2];
        *reinterpret_cast<int*>(&vendor[8]) = regs[3];

        return crypto::detail::fnv1a_64(vendor, 12);
    } __except (1) {
        return 0;
    }
}

// IA32_VMX_BASIC MSR read - faults if VMX not available
KC_NOINLINE bool check_vmx_msr() {
    __try {
        (void)__readmsr(0x480);
        return true;
    } __except (1) {
        return false;
    }
}

// IRQL: PASSIVE_LEVEL
KC_NOINLINE bool registry_key_exists(const wchar_t* path) {
    __try {
        UNICODE_STRING key_path;
        RtlInitUnicodeString(&key_path, path);

#if defined(_NTDDK_) || defined(_WDMDDK_)
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &key_path,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
#else
        kc_object_attributes oa = {};
        oa.Length = sizeof(kc_object_attributes);
        oa.ObjectName = &key_path;
        oa.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
#endif

        void* key_handle = nullptr;
        long status = ZwOpenKey(&key_handle, KEY_READ, &oa);
        if (status == STATUS_SUCCESS && key_handle) {
            ZwClose(key_handle);
            return true;
        }
        return false;
    } __except (1) {
        return false;
    }
}

// IRQL: PASSIVE_LEVEL
KC_NOINLINE bool registry_read_string(const wchar_t* key_path, const wchar_t* value_name,
                                       wchar_t* buffer, uint32_t buffer_chars) {
    __try {
        UNICODE_STRING ukey;
        RtlInitUnicodeString(&ukey, key_path);

#if defined(_NTDDK_) || defined(_WDMDDK_)
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &ukey,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
#else
        kc_object_attributes oa = {};
        oa.Length = sizeof(kc_object_attributes);
        oa.ObjectName = &ukey;
        oa.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
#endif

        void* key_handle = nullptr;
        long status = ZwOpenKey(&key_handle, KEY_READ, &oa);
        if (status != STATUS_SUCCESS || !key_handle)
            return false;

        UNICODE_STRING uval;
        RtlInitUnicodeString(&uval, value_name);

        uint8_t info_buf[512] = {};
        unsigned long result_len = 0;
        status = ZwQueryValueKey(key_handle, &uval, KeyValuePartialInformation,
                                 info_buf, sizeof(info_buf), &result_len);
        ZwClose(key_handle);

        if (status != STATUS_SUCCESS)
            return false;

        auto* info = reinterpret_cast<key_value_partial_info*>(info_buf);
        uint32_t copy_bytes = info->DataLength;
        if (copy_bytes > (buffer_chars - 1) * sizeof(wchar_t))
            copy_bytes = (buffer_chars - 1) * sizeof(wchar_t);

        core::kc_memcpy(buffer, info->Data, copy_bytes);
        buffer[copy_bytes / sizeof(wchar_t)] = L'\0';
        return true;
    } __except (1) {
        return false;
    }
}

// IRQL: PASSIVE_LEVEL
KC_NOINLINE bool check_registry_artifacts() {
    __try {
        if (registry_key_exists(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\vmtools"))
            return true;
        if (registry_key_exists(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\VBoxService"))
            return true;
        if (registry_key_exists(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\vmci"))
            return true;
        if (registry_key_exists(L"\\Registry\\Machine\\SOFTWARE\\VMware, Inc.\\VMware Tools"))
            return true;
        return false;
    } __except (1) {
        return false;
    }
}

// IRQL: PASSIVE_LEVEL
KC_NOINLINE bool check_smbios_manufacturer() {
    __try {
        wchar_t manufacturer[128] = {};
        if (!registry_read_string(
                L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
                L"SystemManufacturer", manufacturer, 128))
            return false;

        uint64_t h = crypto::detail::fnv1a_64_rt_wide_ci(manufacturer);

        if (h == KC_HASH_WIDE_CI(L"VMware, Inc."))              return true;
        if (h == KC_HASH_WIDE_CI(L"innotek GmbH"))              return true;
        if (h == KC_HASH_WIDE_CI(L"Oracle Corporation"))         return true;
        if (h == KC_HASH_WIDE_CI(L"Microsoft Corporation"))      return true;
        if (h == KC_HASH_WIDE_CI(L"Xen"))                        return true;
        if (h == KC_HASH_WIDE_CI(L"QEMU"))                       return true;
        if (h == KC_HASH_WIDE_CI(L"Parallels Software International Inc.")) return true;

        return false;
    } __except (1) {
        return false;
    }
}

KC_NOINLINE bool check_vm() {
    if (check_hypervisor_bit())
        return true;
    if (check_vmx_msr())
        return true;
    if (check_registry_artifacts())
        return true;
    if (check_smbios_manufacturer())
        return true;
    return false;
}

KC_NOINLINE void take_vm_response() {
#if KC_ANTI_DEBUG_RESPONSE == 1
    KeBugCheck(0x000000E2);
#elif KC_ANTI_DEBUG_RESPONSE == 2
    volatile uint8_t* sp = reinterpret_cast<volatile uint8_t*>(&sp);
    for (int i = 0; i < 4096; ++i)
        sp[i] = 0;
#endif
}

} // namespace detail

} // namespace security
} // namespace kernelcloak

#define KC_ANTI_VM() \
    do { \
        if (::kernelcloak::security::detail::check_vm()) { \
            ::kernelcloak::security::detail::take_vm_response(); \
        } \
    } while (0)

#define KC_CHECK_VM() \
    (::kernelcloak::security::detail::check_vm())

#define KC_DETECT_HYPERVISOR() \
    (::kernelcloak::security::detail::check_hypervisor_bit())

#define KC_DETECT_VM_VENDOR() \
    (::kernelcloak::security::detail::get_hypervisor_vendor())

#else // KC_ENABLE_ANTI_VM disabled

#define KC_ANTI_VM()           do {} while (0)
#define KC_CHECK_VM()          (false)
#define KC_DETECT_HYPERVISOR() (false)
#define KC_DETECT_VM_VENDOR()  (static_cast<::kernelcloak::uint64_t>(0))

#endif // KC_ENABLE_ANTI_VM
