#pragma once
#include "../config.h"
#include "../core/types.h"
#include "../core/memory.h"
#include "../crypto/hash.h"

#if KC_ENABLE_IMPORT_HIDING

#ifndef PASSIVE_LEVEL
#define PASSIVE_LEVEL 0
#endif

struct _ERESOURCE;

#if !defined(_NTDDK_) && !defined(_WDMDDK_)
extern "C" {
#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
    typedef struct _UNICODE_STRING {
        unsigned short Length;
        unsigned short MaximumLength;
        wchar_t* Buffer;
    } UNICODE_STRING, *PUNICODE_STRING;
#endif

    void* __stdcall MmGetSystemRoutineAddress(UNICODE_STRING* SystemRoutineName);
    unsigned char __stdcall MmIsAddressValid(void* VirtualAddress);
#if KC_IMPORT_HIDING_LOCK_MODULE_LIST
    unsigned char __stdcall KeGetCurrentIrql();

    struct _ERESOURCE;
    unsigned char __stdcall ExAcquireResourceSharedLite(struct _ERESOURCE* Resource, unsigned char Wait);
    void __stdcall ExReleaseResourceLite(struct _ERESOURCE* Resource);
    void __stdcall KeEnterCriticalRegion();
    void __stdcall KeLeaveCriticalRegion();
#endif

    // PsLoadedModuleList - undocumented export from ntoskrnl.exe
    // head of doubly-linked list of KLDR_DATA_TABLE_ENTRY structures
    // describing all loaded kernel modules
#ifndef _LIST_ENTRY_DEFINED
#define _LIST_ENTRY_DEFINED
    typedef struct _LIST_ENTRY {
        _LIST_ENTRY* Flink;
        _LIST_ENTRY* Blink;
    } LIST_ENTRY, *PLIST_ENTRY;
#endif

    extern LIST_ENTRY PsLoadedModuleList;
#if KC_IMPORT_HIDING_LOCK_MODULE_LIST
    extern struct _ERESOURCE PsLoadedModuleResource;
#endif
}
#else
// when ntddk/wdm is included, PsLoadedModuleList still needs declaration
// as it's not in the standard WDK headers
extern "C" {
    extern LIST_ENTRY PsLoadedModuleList;
#if KC_IMPORT_HIDING_LOCK_MODULE_LIST
    extern struct _ERESOURCE PsLoadedModuleResource;
#endif
}
#endif

namespace kernelcloak {
namespace security {

namespace detail {

// undocumented KLDR_DATA_TABLE_ENTRY - kernel loader data structure
#pragma pack(push, 8)
typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    void* ExceptionTable;
    uint32_t ExceptionTableSize;
    void* GpValue;
    void* NonPagedDebugInfo;
    void* DllBase;
    void* EntryPoint;
    uint32_t SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;
#pragma pack(pop)

// pe structures for export directory parsing
struct imp_dos_header {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
};

struct imp_file_header {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct imp_data_directory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct imp_optional_header64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    imp_data_directory DataDirectory[16];
};

struct imp_nt_headers64 {
    uint32_t Signature;
    imp_file_header FileHeader;
    imp_optional_header64 OptionalHeader;
};

struct imp_export_directory {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
};

// UNICODE_STRING buffers are not guaranteed to be null-terminated. for module names we
// treat them as ASCII (low byte) and hash with the same algo as KC_HASH_CI("ntoskrnl.exe").
KC_FORCEINLINE uint64_t fnv1a_64_rt_unicode_ci_to_ascii(const wchar_t* str, size_t len_chars) {
    uint64_t hash = crypto::detail::fnv64_offset_basis;
    for (size_t i = 0; i < len_chars; ++i) {
        char c = static_cast<char>(static_cast<uint16_t>(str[i]) & 0xFFu);
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c + ('a' - 'A'));
        hash ^= static_cast<uint64_t>(static_cast<uint8_t>(c));
        hash *= crypto::detail::fnv64_prime;
    }
    return hash;
}

KC_FORCEINLINE bool is_valid_pe(void* base) {
    if (!base || !MmIsAddressValid(base))
        return false;

    auto* dos = static_cast<imp_dos_header*>(base);
    if (dos->e_magic != 0x5A4D)
        return false;

    int32_t lfanew = dos->e_lfanew;
    if (lfanew <= 0 || lfanew >= 0x1000)
        return false;

    auto* nt = reinterpret_cast<imp_nt_headers64*>(
        reinterpret_cast<uint8_t*>(base) + lfanew);
    if (!MmIsAddressValid(nt))
        return false;

    return nt->Signature == 0x00004550;
}

// walk PsLoadedModuleList for module base by case-insensitive wide-string hash
KC_NOINLINE inline void* find_module_by_hash(uint64_t name_hash) {
#if KC_IMPORT_HIDING_LOCK_MODULE_LIST
    bool in_critical = false;
    bool resource_acquired = false;
#endif
    void* found = nullptr;

    __try {
#if KC_IMPORT_HIDING_LOCK_MODULE_LIST
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            __try {
                KeEnterCriticalRegion();
                in_critical = true;

                ExAcquireResourceSharedLite(&PsLoadedModuleResource, 1);
                resource_acquired = true;
            } __except (1) {
                resource_acquired = false;
                if (in_critical) {
                    KeLeaveCriticalRegion();
                    in_critical = false;
                }
            }
        }
#endif

        auto* head = &PsLoadedModuleList;
        if (!MmIsAddressValid(head) || !MmIsAddressValid(head->Flink))
            goto out;

        for (auto* entry = head->Flink; entry != head; entry = entry->Flink) {
            if (!MmIsAddressValid(entry))
                break;

            auto* mod = reinterpret_cast<PKLDR_DATA_TABLE_ENTRY>(entry);
            if (!mod->BaseDllName.Buffer || !mod->BaseDllName.Length)
                continue;
            if (!MmIsAddressValid(mod->BaseDllName.Buffer))
                continue;

            size_t wchar_len = static_cast<size_t>(mod->BaseDllName.Length) / sizeof(wchar_t);
            if (!wchar_len)
                continue;
            if (wchar_len > 260)
                continue;

            uint64_t h = fnv1a_64_rt_unicode_ci_to_ascii(mod->BaseDllName.Buffer, wchar_len);
            if (h == name_hash) {
                found = mod->DllBase;
                break;
            }
        }

    out:
#if KC_IMPORT_HIDING_LOCK_MODULE_LIST
        if (resource_acquired) {
            ExReleaseResourceLite(&PsLoadedModuleResource);
            resource_acquired = false;
        }
        if (in_critical) {
            KeLeaveCriticalRegion();
            in_critical = false;
        }
#endif

        return found;
    } __except (1) {
#if KC_IMPORT_HIDING_LOCK_MODULE_LIST
        if (resource_acquired) {
            ExReleaseResourceLite(&PsLoadedModuleResource);
        }
        if (in_critical) {
            KeLeaveCriticalRegion();
        }
#endif
        return nullptr;
    }
}

// resolve export from module base by case-insensitive function name hash
// handles forwarded exports by recursing into the target module
KC_NOINLINE inline void* find_export_by_hash(void* module_base, uint64_t func_hash, uint32_t depth = 0) {
    __try {
        if (depth > 8)
            return nullptr;

        if (!is_valid_pe(module_base))
            return nullptr;

        auto base = reinterpret_cast<uint8_t*>(module_base);
        auto* dos = reinterpret_cast<imp_dos_header*>(base);
        auto* nt = reinterpret_cast<imp_nt_headers64*>(base + dos->e_lfanew);

        auto& export_entry = nt->OptionalHeader.DataDirectory[0];
        if (!export_entry.VirtualAddress || !export_entry.Size)
            return nullptr;

        auto* exports = reinterpret_cast<imp_export_directory*>(
            base + export_entry.VirtualAddress);
        if (!MmIsAddressValid(exports))
            return nullptr;

        auto* names = reinterpret_cast<uint32_t*>(base + exports->AddressOfNames);
        auto* ordinals = reinterpret_cast<uint16_t*>(base + exports->AddressOfNameOrdinals);
        auto* functions = reinterpret_cast<uint32_t*>(base + exports->AddressOfFunctions);

        if (!MmIsAddressValid(names) || !MmIsAddressValid(ordinals) || !MmIsAddressValid(functions))
            return nullptr;

        uint32_t dir_start = export_entry.VirtualAddress;
        uint32_t dir_end = dir_start + export_entry.Size;

        for (uint32_t i = 0; i < exports->NumberOfNames; ++i) {
            auto* func_name = reinterpret_cast<const char*>(base + names[i]);
            if (!MmIsAddressValid(const_cast<char*>(func_name)))
                continue;

            uint64_t h = crypto::detail::fnv1a_64_rt_ci(func_name);
            if (h != func_hash)
                continue;

            uint16_t ordinal = ordinals[i];
            if (ordinal >= exports->NumberOfFunctions)
                continue;

            uint32_t func_rva = functions[ordinal];

            // forwarded export check
            if (func_rva >= dir_start && func_rva < dir_end) {
                auto* fwd_str = reinterpret_cast<const char*>(base + func_rva);
                if (!MmIsAddressValid(const_cast<char*>(fwd_str)))
                    return nullptr;

                const char* dot = fwd_str;
                while (*dot && *dot != '.') ++dot;
                if (!*dot)
                    return nullptr;

                char mod_name[128] = {};
                size_t mod_len = static_cast<size_t>(dot - fwd_str);
                if (mod_len >= sizeof(mod_name) - 5)
                    return nullptr;

                for (size_t j = 0; j < mod_len; ++j)
                    mod_name[j] = fwd_str[j];
                mod_name[mod_len]     = '.';
                mod_name[mod_len + 1] = 'd';
                mod_name[mod_len + 2] = 'l';
                mod_name[mod_len + 3] = 'l';
                mod_name[mod_len + 4] = '\0';

                uint64_t fwd_mod_hash = crypto::detail::fnv1a_64_rt_ci(mod_name);
                uint64_t fwd_func_hash = crypto::detail::fnv1a_64_rt_ci(dot + 1);

                void* fwd_base = find_module_by_hash(fwd_mod_hash);
                if (!fwd_base)
                    return nullptr;

                return find_export_by_hash(fwd_base, fwd_func_hash, depth + 1);
            }

            return base + func_rva;
        }
    } __except (1) {
        return nullptr;
    }

    return nullptr;
}

// fallback: MmGetSystemRoutineAddress for documented APIs
// IRQL: PASSIVE_LEVEL
KC_NOINLINE inline void* resolve_via_mm(const wchar_t* func_name) {
    __try {
        UNICODE_STRING name;
        name.Buffer = const_cast<wchar_t*>(func_name);
        name.Length = 0;
        name.MaximumLength = 0;

        const wchar_t* p = func_name;
        while (*p) ++p;
        auto len = static_cast<unsigned short>((p - func_name) * sizeof(wchar_t));
        name.Length = len;
        name.MaximumLength = len + sizeof(wchar_t);

        return MmGetSystemRoutineAddress(&name);
    } __except (1) {
        return nullptr;
    }
}

} // namespace detail

// public API
KC_FORCEINLINE void* get_module(uint64_t name_hash) {
    return detail::find_module_by_hash(name_hash);
}

KC_FORCEINLINE void* get_export(void* module_base, uint64_t func_hash) {
    return detail::find_export_by_hash(module_base, func_hash);
}

KC_FORCEINLINE void* resolve_import(uint64_t mod_hash, uint64_t func_hash) {
    void* mod = detail::find_module_by_hash(mod_hash);
    if (!mod)
        return nullptr;
    return detail::find_export_by_hash(mod, func_hash);
}

} // namespace security
} // namespace kernelcloak

// resolve import by compile-time hashed module + function names
// usage: auto fn = reinterpret_cast<fn_type>(KC_IMPORT("ntoskrnl.exe", "MmGetSystemRoutineAddress"));
#define KC_IMPORT(mod, func) \
    (::kernelcloak::security::resolve_import( \
        KC_HASH_CI(mod), KC_HASH_CI(func)))

#define KC_GET_MODULE(name) \
    (::kernelcloak::security::get_module(KC_HASH_CI(name)))

#define KC_GET_PROC(mod_base, func) \
    (::kernelcloak::security::get_export( \
        static_cast<void*>(mod_base), KC_HASH_CI(func)))

#else // KC_ENABLE_IMPORT_HIDING disabled

#define KC_IMPORT(mod, func)        (nullptr)
#define KC_GET_MODULE(name)         (nullptr)
#define KC_GET_PROC(mod_base, func) (nullptr)

#endif // KC_ENABLE_IMPORT_HIDING

