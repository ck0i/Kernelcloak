#pragma once
#include "../config.h"
#include "../core/types.h"
#include "../core/memory.h"

#if KC_ENABLE_PE_ERASE

#if !defined(_NTDDK_) && !defined(_WDMDDK_)
extern "C" {
    unsigned char __stdcall MmIsAddressValid(void* VirtualAddress);
}
#endif

// RtlSecureZeroMemory is a forceinline in WDK, not an export.
// we implement our own volatile version to ensure the compiler doesn't optimize it away.
namespace kernelcloak {
namespace security {
namespace detail {

KC_FORCEINLINE void secure_zero(void* dst, size_t len) {
    volatile unsigned char* p = static_cast<volatile unsigned char*>(dst);
    while (len--) *p++ = 0;
}

} // namespace detail
} // namespace security
} // namespace kernelcloak

namespace kernelcloak {
namespace security {

namespace detail {

struct pe_dos_header {
    uint16_t e_magic;
    uint8_t  _pad[58];
    int32_t  e_lfanew;
};

struct pe_file_header {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct pe_data_directory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct pe_optional_header64 {
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
    pe_data_directory DataDirectory[16];
};

struct pe_nt_headers64 {
    uint32_t Signature;
    pe_file_header FileHeader;
    pe_optional_header64 OptionalHeader;
};

#pragma pack(push, 1)
struct pe_section_header {
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

// find own driver base by scanning backward from known function address
KC_NOINLINE void* find_driver_base() {
    __try {
        auto ptr = reinterpret_cast<uintptr_t>(&find_driver_base);
        ptr &= ~static_cast<uintptr_t>(0xFFF);

        for (int i = 0; i < 0x4000; ++i) {
            if (!MmIsAddressValid(reinterpret_cast<void*>(ptr)))
                goto skip;

            {
                auto* dos = reinterpret_cast<pe_dos_header*>(ptr);
                if (dos->e_magic == 0x5A4D && dos->e_lfanew > 0 && dos->e_lfanew < 0x1000) {
                    auto* nt = reinterpret_cast<pe_nt_headers64*>(ptr + dos->e_lfanew);
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

// erase PE headers from driver image
// IRQL: PASSIVE_LEVEL - modifying own image pages
// after this call, WinDbg !dh and similar tools will fail to parse the driver
KC_NOINLINE bool erase_pe_headers() {
    __try {
        void* base = find_driver_base();
        if (!base)
            return false;

        auto* raw = reinterpret_cast<uint8_t*>(base);
        auto* dos = reinterpret_cast<pe_dos_header*>(base);

        if (dos->e_magic != 0x5A4D)
            return false;

        int32_t lfanew = dos->e_lfanew;
        if (lfanew <= 0 || lfanew >= 0x1000)
            return false;

        auto* nt = reinterpret_cast<pe_nt_headers64*>(raw + lfanew);
        if (!MmIsAddressValid(nt) || nt->Signature != 0x00004550)
            return false;

        uint16_t num_sections = nt->FileHeader.NumberOfSections;
        uint16_t opt_hdr_size = nt->FileHeader.SizeOfOptionalHeader;

        auto* first_section = reinterpret_cast<pe_section_header*>(
            reinterpret_cast<uint8_t*>(&nt->OptionalHeader) + opt_hdr_size);
        auto* last_section = &first_section[num_sections];

        uintptr_t erase_end = reinterpret_cast<uintptr_t>(last_section);
        uintptr_t erase_start = reinterpret_cast<uintptr_t>(base);
        size_t erase_size = erase_end - erase_start;

        // clamp to SizeOfHeaders or 2 pages
        uint32_t size_of_headers = nt->OptionalHeader.SizeOfHeaders;
        if (erase_size > size_of_headers)
            erase_size = size_of_headers;
        if (erase_size > 0x2000)
            erase_size = 0x2000;

        // validate all pages in range
        for (size_t offset = 0; offset < erase_size; offset += 0x1000) {
            if (!MmIsAddressValid(raw + offset))
                return false;
        }
        if (erase_size > 0 && !MmIsAddressValid(raw + erase_size - 1))
            return false;

        secure_zero(raw, erase_size);
        return true;
    } __except (1) {
        return false;
    }
}

} // namespace detail

} // namespace security
} // namespace kernelcloak

// erase PE headers from own driver image. call once at PASSIVE_LEVEL
// after driver initialization is complete
#define KC_ERASE_PE_HEADER() \
    (::kernelcloak::security::detail::erase_pe_headers())

#else // KC_ENABLE_PE_ERASE disabled

#define KC_ERASE_PE_HEADER() (false)

#endif // KC_ENABLE_PE_ERASE
