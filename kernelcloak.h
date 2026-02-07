#pragma once

// KernelCloak - Header-only C++17 kernel-mode obfuscation library
// Include this single header to access all features.

// configuration and compiler macros
#include "config.h"

// core primitives (no external dependencies)
#include "core/types.h"
#include "core/array.h"
#include "core/memory.h"
#include "core/sync.h"
#include "core/random.h"
#include "core/string_utils.h"

// cryptographic primitives (depends on core)
#include "crypto/hash.h"
#include "crypto/xor_cipher.h"
#include "crypto/xtea.h"

// string obfuscation (depends on core + crypto)
#if KC_ENABLE_STRING_ENCRYPTION
#include "strings/encrypted_string.h"
#include "strings/encrypted_wstring.h"
#include "strings/stack_string.h"
#include "strings/layered_string.h"
#endif

// value and control flow obfuscation (depends on core)
#if KC_ENABLE_VALUE_OBFUSCATION
#include "obfuscation/value.h"
#endif

#if KC_ENABLE_MBA
#include "obfuscation/mba.h"
#include "obfuscation/compare.h"
#endif

#if KC_ENABLE_BOOLEAN_OBFUSCATION
#include "obfuscation/boolean.h"
#endif

#if KC_ENABLE_CONTROL_FLOW
#include "obfuscation/control_flow.h"
#endif

#if KC_ENABLE_CFG_FLATTEN
#include "obfuscation/cfg_flatten.h"
#include "obfuscation/cfg_protect.h"
#endif

// security features (depends on core + crypto)
#if KC_ENABLE_ANTI_DEBUG
#include "security/anti_debug.h"
#endif

#if KC_ENABLE_ANTI_VM
#include "security/anti_vm.h"
#endif

#if KC_ENABLE_INTEGRITY
#include "security/integrity.h"
#endif

#if KC_ENABLE_PE_ERASE
#include "security/pe_erase.h"
#endif

#if KC_ENABLE_IMPORT_HIDING
#include "security/import_hiding.h"
#endif
