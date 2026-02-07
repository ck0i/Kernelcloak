# KernelCloak

Header-only C++17 obfuscation library designed exclusively for Windows kernel-mode drivers (WDM/KMDF/WDF).

A spiritual successor to [Cloakwork](https://github.com/ck0i/Cloakwork), but where Cloakwork's kernel support is mostly no-ops, KernelCloak makes **every feature fully functional at IRQL-aware ring 0**.

## Features

### String Encryption
- `KC_STR("text")` - compile-time encrypted, stack-decrypted strings with no static destructors
- `KC_WSTR(L"text")` - wide string variant
- `KC_STACK_STR(name, 'h','e','l','l','o','\0')` - char-by-char construction, zero string literals
- `KC_STR_LAYERED("text")` - triple-layer encryption (XOR + XTEA + byte shuffle) with runtime re-keying

### Value Obfuscation
- `KC_INT(x)` - XOR-encoded integer/pointer storage with volatile decode
- `KC_ADD/SUB/AND/OR/XOR/NEG` - Mixed Boolean Arithmetic operations
- `KC_EQ/NE/LT/GT/LE/GE` - obfuscated comparisons via MBA

### Control Flow
- `KC_IF/KC_ELSE/KC_ENDIF` - conditionals with opaque predicate injection
- `KC_JUNK()` / `KC_JUNK_FLOW()` - dead code insertion
- `KC_FLAT_FUNC/BLOCK/GOTO/IF/RETURN/END` - full CFG flattening with XOR-encrypted state transitions
- `KC_PROTECT(ret_type, body)` - lightweight CFG protection wrapper
- `KC_TRUE/KC_FALSE/KC_BOOL` - opaque predicates sourced from `__rdtsc`, stack entropy, kernel APIs

### Cryptographic Primitives
- XTEA block cipher - fully constexpr encrypt, runtime decrypt
- Rolling XOR cipher - lightweight fast-path encryption
- FNV-1a hash - 32/64-bit, case-insensitive, wide string variants

### Security
- **Anti-Debug** - `KdDebuggerEnabled`, hardware breakpoint detection, RDTSC timing checks
- **Anti-VM** - CPUID hypervisor detection, MSR checks, registry artifact scanning
- **Integrity** - hook detection, function prologue hashing, .text section self-checksum
- **PE Erase** - zero DOS/NT headers and section table after load
- **Import Hiding** - PsLoadedModuleList walking with hash-based export resolution, forwarded export support

### Core Primitives
- `KernelBuffer<T>` - RAII pool allocation with move semantics
- `KSpinLock` - RAII spinlock with IRQL save/restore guards
- `KernelAtomic<T>` - lock-free atomics via Interlocked* intrinsics
- `KArray<T, N>` - stack-allocated constexpr array
- Compile-time and runtime PRNG (xorshift, KASLR entropy)

## Quick Start

```cpp
#include "kernelcloak/kernelcloak.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    // encrypted strings - plaintext never in binary
    DbgPrint("%s\n", KC_STR("driver loaded successfully"));

    // obfuscated values - constants not visible in disassembly
    auto magic = KC_INT(0xDEADBEEF);
    auto result = KC_ADD(magic, KC_INT(0x1000));

    // hidden imports - functions not in IAT
    auto fn = reinterpret_cast<decltype(&MmGetSystemRoutineAddress)>(
        KC_IMPORT("ntoskrnl.exe", "MmGetSystemRoutineAddress")
    );

    // anti-debug/anti-vm
    if (KC_IS_DEBUGGED()) {
        return STATUS_ACCESS_DENIED;
    }

    // PE header erasure
    KC_ERASE_PE_HEADER();

    return STATUS_SUCCESS;
}
```

## Usage

Single header include:

```cpp
#include "kernelcloak/kernelcloak.h"
```

Or include only what you need:

```cpp
#include "kernelcloak/strings/encrypted_string.h"
#include "kernelcloak/obfuscation/value.h"
```

## Configuration

Define before including to customize:

```cpp
#define KC_ENABLE_ALL 0                    // disable everything by default
#define KC_ENABLE_STRING_ENCRYPTION 1      // enable only what you need
#define KC_ENABLE_VALUE_OBFUSCATION 1
#define KC_POOL_TAG 'myTg'                 // custom pool tag
#define KC_ANTI_DEBUG_RESPONSE 0           // 0=ignore, 1=bugcheck, 2=corrupt
#include "kernelcloak/kernelcloak.h"
```

When a feature is disabled, its macros compile to passthrough/no-ops with zero overhead.

## Requirements

- Windows Driver Kit (WDK) 10+
- Visual Studio 2019+ with C++17 support
- Windows 10/11 x64 target

## Design Principles

1. **Header-only** - no .lib or .cpp files to compile
2. **C++17** - no C++20 features (concepts, consteval, ranges)
3. **IRQL-aware** - every function documents its maximum safe IRQL
4. **Zero dependencies** - only WDK headers + compiler intrinsics
5. **Unique per build** - compile-time PRNG seeded from `__TIME__`, `__COUNTER__`, `__LINE__`
6. **No BSOD** - all features degrade gracefully on failure
7. **No CRT** - no static destructors, no atexit, no STL

## What Makes This Different From Cloakwork

| Cloakwork Kernel Gap | KernelCloak Solution |
|---|---|
| `CW_STR()` - no-op (needs atexit) | Stack-decrypt pattern, no static destructors |
| `CW_INT()` - no-op (needs C++20 concepts) | SFINAE-based C++17 implementation |
| `CW_IF()` - regular if (depends on MBA + concepts) | Standalone C++17 MBA + opaque predicates |
| `CW_IMPORT()` - unavailable (PEB walking) | PsLoadedModuleList + export directory parsing |
| `CW_ANTI_VM()` - no-op (usermode APIs) | Kernel-native CPUID/MSR/registry/SMBIOS |
| Integrity checks unavailable (VirtualQuery) | Direct PE section parsing from driver base |

## Project Structure

```
kernelcloak/
├── include/kernelcloak/
│   ├── kernelcloak.h       # master header
│   ├── config.h            # feature toggles
│   ├── core/               # kernel-safe primitives
│   ├── crypto/             # encryption primitives
│   ├── strings/            # string obfuscation
│   ├── obfuscation/        # value/control flow
│   └── security/           # anti-debug/vm/integrity
└── test_driver/            # WDM test driver + RE challenge
```

## License

MIT
