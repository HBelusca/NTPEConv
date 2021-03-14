/*
 * PROJECT:     PE Converter for NT PDK v1.196 (September 1991) and PDK October 1991
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Type definitions and useful macros for host tools.
 *
 * Adapted from the ReactOS Host Headers
 * Copyright 2007 Hervé Poussineau (hpoussin@reactos.org)
 * Copyright 2007 Colin Finck (colin@reactos.org)
 * under the same license.
 */

#ifndef _TYPEDEFS_HOST_H
#define _TYPEDEFS_HOST_H

#pragma once

#include <assert.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>

/* Function attributes for GCC */
#if !defined(_MSC_VER) && !defined(__fastcall)
#define __fastcall __attribute__((fastcall))
#endif
#if !defined(_MSC_VER) && !defined(__cdecl)
#define __cdecl __attribute__((cdecl))
#endif
#if !defined(_MSC_VER) && !defined(__stdcall)
#define __stdcall __attribute__((stdcall))
#endif

/* Helper macro to enable GCC's extension */
#ifndef __GNU_EXTENSION
#ifdef __GNUC__
#define __GNU_EXTENSION __extension__
#else
#define __GNU_EXTENSION
#endif
#endif /* __GNU_EXTENSION */

#ifndef DUMMYUNIONNAME
#if defined(NONAMELESSUNION) || !defined(_MSC_EXTENSIONS)
#define _ANONYMOUS_UNION
#define _UNION_NAME(x) x
#define DUMMYUNIONNAME  u
#define DUMMYUNIONNAME1 u1
#define DUMMYUNIONNAME2 u2
#define DUMMYUNIONNAME3 u3
#define DUMMYUNIONNAME4 u4
#define DUMMYUNIONNAME5 u5
#define DUMMYUNIONNAME6 u6
#define DUMMYUNIONNAME7 u7
#define DUMMYUNIONNAME8 u8
#define DUMMYUNIONNAME9  u9
#else
#define _ANONYMOUS_UNION __GNU_EXTENSION
#define _UNION_NAME(x)
#define DUMMYUNIONNAME
#define DUMMYUNIONNAME1
#define DUMMYUNIONNAME2
#define DUMMYUNIONNAME3
#define DUMMYUNIONNAME4
#define DUMMYUNIONNAME5
#define DUMMYUNIONNAME6
#define DUMMYUNIONNAME7
#define DUMMYUNIONNAME8
#define DUMMYUNIONNAME9
#endif /* NONAMELESSUNION */
#endif /* !DUMMYUNIONNAME */

#ifndef DUMMYSTRUCTNAME
#if defined(NONAMELESSUNION) || !defined(_MSC_EXTENSIONS)
#define _ANONYMOUS_STRUCT
#define _STRUCT_NAME(x) x
#define DUMMYSTRUCTNAME s
#define DUMMYSTRUCTNAME1 s1
#define DUMMYSTRUCTNAME2 s2
#define DUMMYSTRUCTNAME3 s3
#define DUMMYSTRUCTNAME4 s4
#define DUMMYSTRUCTNAME5 s5
#else
#define _ANONYMOUS_STRUCT __GNU_EXTENSION
#define _STRUCT_NAME(x)
#define DUMMYSTRUCTNAME
#define DUMMYSTRUCTNAME1
#define DUMMYSTRUCTNAME2
#define DUMMYSTRUCTNAME3
#define DUMMYSTRUCTNAME4
#define DUMMYSTRUCTNAME5
#endif /* NONAMELESSUNION */
#endif /* DUMMYSTRUCTNAME */

#if defined(_M_MRX000) || defined(_M_ALPHA) || defined(_M_PPC) || defined(_M_IA64) || defined(_M_AMD64) || defined(_M_ARM)
#define ALIGNMENT_MACHINE
#define UNALIGNED __unaligned
#if defined(_WIN64)
#define UNALIGNED64 __unaligned
#else
#define UNALIGNED64
#endif
#else
#undef ALIGNMENT_MACHINE
#define UNALIGNED
#define UNALIGNED64
#endif


/* Basic definitions */
#define UNIMPLEMENTED { printf("%s unimplemented\n", __FUNCTION__); exit(1); }
#define UNIMPLEMENTED_ONCE { printf("%s unimplemented\n", __FUNCTION__); exit(1); }
#define ASSERT(x) assert(x)
#define ASSERTMSG(m, x) assert(x)

/* Human-readable Pseudo Modifiers for Input Parameters */
#define IN
#define OUT
#define OPTIONAL

#define FALSE 0
#define TRUE  1

/* Basic types
   Emulate a LLP64 memory model using a LP64 compiler */
typedef void VOID, *PVOID, *LPVOID;
typedef char CHAR, CCHAR, *PCHAR, *PSTR, *LPSTR;
typedef const char *PCSTR, *LPCSTR;
typedef unsigned char UCHAR, *PUCHAR, BYTE, *LPBYTE, BOOLEAN, *PBOOLEAN;
typedef uint8_t UINT8;
typedef int16_t SHORT, *PSHORT;
typedef uint16_t USHORT, *PUSHORT, WORD, *PWORD, *LPWORD, WCHAR, *PWCHAR, *PWSTR, *LPWSTR, UINT16;
typedef const uint16_t *PCWSTR, *LPCWSTR;
typedef int32_t INT, LONG, *PLONG, *LPLONG, BOOL, WINBOOL, INT32;
typedef uint32_t UINT, *PUINT, *LPUINT, ULONG, *PULONG, DWORD, *PDWORD, *LPDWORD, UINT32;
#if defined(_LP64) || defined(_WIN64)
typedef int64_t LONG_PTR, *PLONG_PTR, INT_PTR, *PINT_PTR;
typedef uint64_t ULONG_PTR, DWORD_PTR, *PULONG_PTR, UINT_PTR, *PUINT_PTR;
#else
typedef int32_t LONG_PTR, *PLONG_PTR, INT_PTR, *PINT_PTR;
typedef uint32_t ULONG_PTR, DWORD_PTR, *PULONG_PTR, UINT_PTR, *PUINT_PTR;
#endif
typedef uint64_t ULONG64, DWORD64, *PDWORD64, UINT64, ULONGLONG;
typedef int64_t LONGLONG, LONG64, INT64;

/* Derived types */
typedef INT NTSTATUS;
typedef ULONG_PTR SIZE_T, *PSIZE_T;

#define MAXUCHAR  UCHAR_MAX
#define MAXUSHORT USHRT_MAX
#define MAXULONG  ULONG_MAX

/* Widely used macros */
#define LOBYTE(w)               ((BYTE)(w))
#define HIBYTE(w)               ((BYTE)(((WORD)(w)>>8)&0xFF))
#define LOWORD(l)               ((WORD)((DWORD_PTR)(l)))
#define HIWORD(l)               ((WORD)(((DWORD_PTR)(l)>>16)&0xFFFF))
#define MAKEWORD(a,b)           ((WORD)(((BYTE)(a))|(((WORD)((BYTE)(b)))<<8)))
#define MAKELONG(a,b)           ((LONG)(((WORD)(a))|(((DWORD)((WORD)(b)))<<16)))

#define NT_SUCCESS(x)           ((x)>=0)

/* Defines the "size" of an any-size array */
#define ANYSIZE_ARRAY 1

/* C_ASSERT Definition */
// NOTE: Adding the braces ensures that this "variable" definition
// is always at the beginning of a new code block scope.
#define C_ASSERT(expr) extern char (*c_assert(void)) [(expr) ? 1 : -1]

/* Returns the byte offset of the specified structure's member */
#if !defined(__GNUC__) && !defined(__clang__)
#define FIELD_OFFSET(Type, Field) ((LONG)(LONG_PTR)&(((Type*) 0)->Field))
#else
#define FIELD_OFFSET(Type, Field) ((LONG)__builtin_offsetof(Type, Field))
#endif /* __GNUC__ */

/* Returns the base address of a structure from a structure member */
#define CONTAINING_RECORD(address, type, field)  ((type *)(((ULONG_PTR)address) - (ULONG_PTR)(&(((type *)0)->field))))

#define ROUND_DOWN(n, align) \
    (((ULONG_PTR)(n)) & ~((align) - 1l))

#define ROUND_UP(n, align) \
    ROUND_DOWN(((ULONG_PTR)(n)) + (align) - 1, (align))

#define IS_ALIGNED(addr, align) \
    (((ULONG_PTR)(addr) & ((align) - 1)) == 0)

#define max(a, b)   (((a) > (b)) ? (a) : (b))
#define min(a, b)   (((a) < (b)) ? (a) : (b))


/* Helper Macros */

#define RTL_FIELD_TYPE(type, field)    (((type*)0)->field)
#define RTL_BITS_OF(sizeOfArg)         (sizeof(sizeOfArg) * 8)
#define RTL_BITS_OF_FIELD(type, field) (RTL_BITS_OF(RTL_FIELD_TYPE(type, field)))
#define RTL_FIELD_SIZE(type, field)    (sizeof(((type *)0)->field))

#define RTL_SIZEOF_THROUGH_FIELD(type, field) \
    (FIELD_OFFSET(type, field) + RTL_FIELD_SIZE(type, field))

#define RTL_CONTAINS_FIELD(Struct, Size, Field) \
    ( (((PCHAR)(&(Struct)->Field)) + sizeof((Struct)->Field)) <= (((PCHAR)(Struct))+(Size)) )

#define RTL_NUMBER_OF_V1(A) (sizeof(A)/sizeof((A)[0]))

#ifdef __GNUC__
#define RTL_NUMBER_OF_V2(A) \
     (({ int _check_array_type[__builtin_types_compatible_p(typeof(A), typeof(&A[0])) ? -1 : 1]; (void)_check_array_type; }), \
     RTL_NUMBER_OF_V1(A))
#elif defined(__cplusplus)
extern "C++" {
    template <typename T, size_t N>
    static char(&SAFE_RTL_NUMBER_OF(T(&)[N]))[N];
}
#define RTL_NUMBER_OF_V2(A) sizeof(SAFE_RTL_NUMBER_OF(A))
#else
#define RTL_NUMBER_OF_V2(A) RTL_NUMBER_OF_V1(A)
#endif

#ifdef ENABLE_RTL_NUMBER_OF_V2
#define RTL_NUMBER_OF(A) RTL_NUMBER_OF_V2(A)
#else
#define RTL_NUMBER_OF(A) RTL_NUMBER_OF_V1(A)
#endif

#define ARRAYSIZE(A)    RTL_NUMBER_OF_V2(A)
#define _ARRAYSIZE(A)   RTL_NUMBER_OF_V1(A)

#define RTL_NUMBER_OF_FIELD(type, field) \
    (RTL_NUMBER_OF(RTL_FIELD_TYPE(type, field)))

#define RTL_PADDING_BETWEEN_FIELDS(type, field1, field2) \
    ((FIELD_OFFSET(type, field2) > FIELD_OFFSET(type, field1)) \
        ? (FIELD_OFFSET(type, field2) - FIELD_OFFSET(type, field1) - RTL_FIELD_SIZE(type, field1)) \
        : (FIELD_OFFSET(type, field1) - FIELD_OFFSET(type, field2) - RTL_FIELD_SIZE(type, field2)))


#define RtlFillMemory(Destination, Length, Fill)        memset(Destination, Fill, Length)
#define RtlZeroMemory(Destination, Length)              RtlFillMemory(Destination, Length, 0)
#define RtlCopyMemory(Destination, Source, Length)      memcpy(Destination, Source, Length)
#define RtlMoveMemory(Destination, Source, Length)      memmove(Destination, Source, Length)
#define RtlEqualMemory(Destination, Source, Length)     (!memcmp(Destination, Source, Length))
//
// NOTE: We do not define RtlCompareMemory(), as its return value semantics
// is different than the one from memcmp(), and there is no way to convert
// one into the other.

#endif /* _TYPEDEFS_HOST_H */
