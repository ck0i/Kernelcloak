#pragma once

// KernelCloak Configuration
// Define these before including kernelcloak.h to customize behavior.

// master switch
#ifndef KC_ENABLE_ALL
#define KC_ENABLE_ALL 1
#endif

// feature toggles (all default to KC_ENABLE_ALL)
#ifndef KC_ENABLE_STRING_ENCRYPTION
#define KC_ENABLE_STRING_ENCRYPTION KC_ENABLE_ALL
#endif

#ifndef KC_ENABLE_VALUE_OBFUSCATION
#define KC_ENABLE_VALUE_OBFUSCATION KC_ENABLE_ALL
#endif

#ifndef KC_ENABLE_CONTROL_FLOW
#define KC_ENABLE_CONTROL_FLOW KC_ENABLE_ALL
#endif

#ifndef KC_ENABLE_ANTI_DEBUG
#define KC_ENABLE_ANTI_DEBUG KC_ENABLE_ALL
#endif

#ifndef KC_ENABLE_ANTI_VM
#define KC_ENABLE_ANTI_VM KC_ENABLE_ALL
#endif

#ifndef KC_ENABLE_IMPORT_HIDING
#define KC_ENABLE_IMPORT_HIDING KC_ENABLE_ALL
#endif

#ifndef KC_ENABLE_INTEGRITY
#define KC_ENABLE_INTEGRITY KC_ENABLE_ALL
#endif

#ifndef KC_ENABLE_PE_ERASE
#define KC_ENABLE_PE_ERASE KC_ENABLE_ALL
#endif

#ifndef KC_ENABLE_CFG_FLATTEN
#define KC_ENABLE_CFG_FLATTEN KC_ENABLE_ALL
#endif

#ifndef KC_ENABLE_MBA
#define KC_ENABLE_MBA KC_ENABLE_ALL
#endif

#ifndef KC_ENABLE_BOOLEAN_OBFUSCATION
#define KC_ENABLE_BOOLEAN_OBFUSCATION KC_ENABLE_ALL
#endif

// behavioral config
#ifndef KC_POOL_TAG
#define KC_POOL_TAG 'kcLK'
#endif

#ifndef KC_ANTI_DEBUG_RESPONSE
#define KC_ANTI_DEBUG_RESPONSE 1  // 0=ignore, 1=KeBugCheck, 2=corrupt state
#endif

#ifndef KC_LAYERED_REKEY_INTERVAL
#define KC_LAYERED_REKEY_INTERVAL 1000
#endif

#ifndef KC_XTEA_ROUNDS
#define KC_XTEA_ROUNDS 32
#endif

// compiler intrinsics and annotations
#ifdef _MSC_VER
#define KC_FORCEINLINE __forceinline
#define KC_NOINLINE __declspec(noinline)
#define KC_NOVTABLE __declspec(novtable)
#define KC_SELECTANY __declspec(selectany)
#else
#define KC_FORCEINLINE inline __attribute__((always_inline))
#define KC_NOINLINE __attribute__((noinline))
#define KC_NOVTABLE
#define KC_SELECTANY __attribute__((weak))
#endif

// suppress common WDK warnings
#pragma warning(disable: 4201) // nameless struct/union
#pragma warning(disable: 4324) // structure padded due to alignment
#pragma warning(disable: 4471) // forward declaration of unscoped enum
