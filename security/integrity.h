#pragma once
#include "../config.h"
#include "../core/types.h"
#include "../core/memory.h"
#include "../crypto/hash.h"

#if KC_ENABLE_INTEGRITY

#if !defined(_NTDDK_) && !defined(_WDMDDK_)
extern "C" {
    unsigned char __stdcall MmIsAddressValid(void* VirtualAddress);
}
#endif

namespace kernelcloak {
namespace security {

namespace detail {

// pe structures for section parsing
struct integrity_dos_header {
    uint16_t e_magic;
    uint8_t  _pad[58];
    int32_t  e_lfanew;
};

struct integrity_file_header {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct integrity_data_directory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct integrity_optional_header64 {
    uint16_t Magic;
    uint8_t  _pad1[14];
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint8_t  _pad2[16];
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
    integrity_data_directory DataDirectory[16];
};

struct integrity_nt_headers64 {
    uint32_t Signature;
    integrity_file_header FileHeader;
    integrity_optional_header64 OptionalHeader;
};

#pragma pack(push, 1)
struct integrity_section_header {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};
#pragma pack(pop)

// find driver base by scanning backwards from a function address to MZ
KC_NOINLINE inline void* find_own_base_from_address(void* addr) {
    __try {
        auto ptr = reinterpret_cast<uintptr_t>(addr);
        ptr &= ~static_cast<uintptr_t>(0xFFF);

        for (int i = 0; i < 0x4000; ++i) {
            if (!MmIsAddressValid(reinterpret_cast<void*>(ptr)))
                goto skip;

            {
                auto* dos = reinterpret_cast<integrity_dos_header*>(ptr);
                if (dos->e_magic == 0x5A4D && dos->e_lfanew > 0 && dos->e_lfanew < 0x1000) {
                    auto* nt = reinterpret_cast<integrity_nt_headers64*>(ptr + dos->e_lfanew);
                    if (MmIsAddressValid(nt) && nt->Signature == 0x00004550)
                        return reinterpret_cast<void*>(ptr);
                }
            }

        skip:
            ptr -= 0x1000;
        }
    } __except (1) {}

    return nullptr;
}

// find .text section (or first executable section) in PE image
KC_NOINLINE inline bool find_text_section(void* base, uintptr_t& text_va, uint32_t& text_size) {
    __try {
        auto* dos = static_cast<integrity_dos_header*>(base);
        if (dos->e_magic != 0x5A4D)
            return false;

        auto* nt = reinterpret_cast<integrity_nt_headers64*>(
            reinterpret_cast<uint8_t*>(base) + dos->e_lfanew);
        if (!MmIsAddressValid(nt) || nt->Signature != 0x00004550)
            return false;

        auto* section = reinterpret_cast<integrity_section_header*>(
            reinterpret_cast<uint8_t*>(&nt->OptionalHeader) +
            nt->FileHeader.SizeOfOptionalHeader);

        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (!MmIsAddressValid(&section[i]))
                return false;

            if (section[i].Name[0] == '.' && section[i].Name[1] == 't' &&
                section[i].Name[2] == 'e' && section[i].Name[3] == 'x' &&
                section[i].Name[4] == 't') {
                text_va = reinterpret_cast<uintptr_t>(base) + section[i].VirtualAddress;
                text_size = section[i].VirtualSize;
                return true;
            }
        }

        // fallback: first section with IMAGE_SCN_MEM_EXECUTE
        constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                text_va = reinterpret_cast<uintptr_t>(base) + section[i].VirtualAddress;
                text_size = section[i].VirtualSize;
                return true;
            }
        }
    } __except (1) {}

    return false;
}

// FNV-1a hash over arbitrary memory region
KC_NOINLINE inline uint64_t compute_region_hash(const void* ptr, uint32_t size) {
    __try {
        if (!ptr || size == 0)
            return 0;

        auto* data = static_cast<const uint8_t*>(ptr);

        // validate per-page rather than per-byte. this avoids high overhead on larger
        // regions while still keeping us from faulting at elevated irql.
        uintptr_t start = reinterpret_cast<uintptr_t>(data);
        uintptr_t end = start + static_cast<uintptr_t>(size - 1);
        uintptr_t page = start & ~static_cast<uintptr_t>(0xFFFull);
        for (; page <= end; page += 0x1000) {
            if (!MmIsAddressValid(reinterpret_cast<void*>(page)))
                return 0;
        }

        uint64_t hash = crypto::detail::fnv64_offset_basis;
        for (uint32_t i = 0; i < size; ++i) {
            hash ^= static_cast<uint64_t>(data[i]);
            hash *= crypto::detail::fnv64_prime;
        }

        return hash;
    } __except (1) {
        return 0;
    }
}

inline uint64_t& stored_text_hash() {
    static uint64_t hash = 0;
    return hash;
}

inline void*& stored_driver_base() {
    static void* base = nullptr;
    return base;
}

// detect common inline hook patterns on a function
KC_NOINLINE inline bool detect_hook(void* func_addr) {
    __try {
        if (!func_addr || !MmIsAddressValid(func_addr))
            return false;

        auto* b = static_cast<uint8_t*>(func_addr);

        // validate readability of first 16 bytes
        for (int i = 0; i < 16; ++i) {
            if (!MmIsAddressValid(&b[i]))
                return false;
        }

        if (b[0] == 0xE9)                                  return true; // jmp rel32
        if (b[0] == 0xFF && b[1] == 0x25)                  return true; // jmp [rip+disp32]
        if (b[0] == 0x48 && b[1] == 0xB8 &&
            b[10] == 0xFF && b[11] == 0xE0)                 return true; // mov rax, imm64; jmp rax
        if (b[0] == 0xCC)                                   return true; // int 3
        if (b[0] == 0x68 && b[5] == 0xC3)                   return true; // push imm32; ret

        return false;
    } __except (1) {
        return false;
    }
}

// .text section self-checksum verification
// first call stores baseline hash, subsequent calls compare against it
KC_NOINLINE inline bool verify_integrity() {
    __try {
        if (!stored_driver_base()) {
            stored_driver_base() = find_own_base_from_address(
                reinterpret_cast<void*>(&verify_integrity));
        }

        void* base = stored_driver_base();
        if (!base)
            return true; // can't locate base, degrade gracefully

        uintptr_t text_va = 0;
        uint32_t text_size = 0;
        if (!find_text_section(base, text_va, text_size))
            return true;

        uint64_t current = compute_region_hash(
            reinterpret_cast<void*>(text_va), text_size);
        if (current == 0)
            return true;

        if (stored_text_hash() == 0) {
            stored_text_hash() = current;
            return true;
        }

        return stored_text_hash() == current;
    } __except (1) {
        return true;
    }
}

} // namespace detail

} // namespace security
} // namespace kernelcloak

#define KC_DETECT_HOOK(func) \
    (::kernelcloak::security::detail::detect_hook(reinterpret_cast<void*>(func)))

#define KC_COMPUTE_HASH(ptr, size) \
    (::kernelcloak::security::detail::compute_region_hash( \
        static_cast<const void*>(ptr), static_cast<::kernelcloak::uint32_t>(size)))

#define KC_VERIFY_INTEGRITY() \
    (::kernelcloak::security::detail::verify_integrity())

#else // KC_ENABLE_INTEGRITY disabled

#define KC_DETECT_HOOK(func)        (false)
#define KC_COMPUTE_HASH(ptr, size)  (static_cast<::kernelcloak::uint64_t>(0))
#define KC_VERIFY_INTEGRITY()       (true)

#endif // KC_ENABLE_INTEGRITY

