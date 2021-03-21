/*
 * PROJECT:     PE Converter for NT PDK v1.196 (September 1991) and PDK October 1991
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     New PE Format Type definitions (only for x86/MIPS platforms).
 *
 * Adapted from the ReactOS Host Headers
 * Copyright 2002 Casper S. Hornstrup (chorns@users.sourceforge.net)
 * Copyright 2005 Gé van Geldorp (gvg@reactos.org)
 * Copyright 2005 Royce Mitchell III
 * Copyright 2011 Timo Kreuzer (timo.kreuzer@reactos.org)
 * under the same license.
 */

#ifndef _PECOFF_H_
#define _PECOFF_H_

#pragma once

/*
 * Image Formats
 */
#define IMAGE_DOS_SIGNATURE 0x5A4D
 // #define IMAGE_OS2_SIGNATURE 0x454E
 // #define IMAGE_OS2_SIGNATURE_LE 0x454C
 // #define IMAGE_VXD_SIGNATURE 0x454C
#define IMAGE_NT_SIGNATURE 0x00004550

// #define IMAGE_DOS_MAGIC IMAGE_DOS_SIGNATURE
// #define IMAGE_PE_MAGIC  IMAGE_NT_SIGNATURE

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x010b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x020b

/*
 * Image Architectures
 */
#define IMAGE_FILE_MACHINE_UNKNOWN    0
#define IMAGE_FILE_MACHINE_AM33       0x1d3
#define IMAGE_FILE_MACHINE_AMD64      0x8664
#define IMAGE_FILE_MACHINE_ARM        0x1c0
#define IMAGE_FILE_MACHINE_ARMNT      0x1c4
#define IMAGE_FILE_MACHINE_ARMV7      0x1c4
#define IMAGE_FILE_MACHINE_EBC        0xebc
#define	IMAGE_FILE_MACHINE_I860       0x14d
#define IMAGE_FILE_MACHINE_I386       0x14c
#define IMAGE_FILE_MACHINE_IA64       0x200
#define IMAGE_FILE_MACHINE_M32R       0x9041
#define IMAGE_FILE_MACHINE_MIPS16     0x266
#define IMAGE_FILE_MACHINE_MIPSFPU    0x366
#define IMAGE_FILE_MACHINE_MIPSFPU16  0x466
#define IMAGE_FILE_MACHINE_POWERPC    0x1f0
#define IMAGE_FILE_MACHINE_POWERPCFP  0x1f1
#define IMAGE_FILE_MACHINE_R4000      0x166
#define IMAGE_FILE_MACHINE_RISCV32    0x5032
#define IMAGE_FILE_MACHINE_RISCV64    0x5064
#define IMAGE_FILE_MACHINE_RISCV128   0x5128
#define IMAGE_FILE_MACHINE_SH3        0x1a2
#define IMAGE_FILE_MACHINE_SH3E       0x01a4
#define IMAGE_FILE_MACHINE_SH3DSP     0x1a3
#define IMAGE_FILE_MACHINE_SH4        0x1a6
#define IMAGE_FILE_MACHINE_SH5        0x1a8
#define IMAGE_FILE_MACHINE_THUMB      0x1c2
#define IMAGE_FILE_MACHINE_WCEMIPSV2  0x169
#define IMAGE_FILE_MACHINE_R3000      0x162
#define IMAGE_FILE_MACHINE_R10000     0x168
#define IMAGE_FILE_MACHINE_ALPHA      0x184
#define IMAGE_FILE_MACHINE_ALPHA64    0x0284
#define IMAGE_FILE_MACHINE_AXP64      IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_CEE        0xC0EE
#define IMAGE_FILE_MACHINE_TRICORE    0x0520
#define IMAGE_FILE_MACHINE_CEF        0x0CEF
#define IMAGE_FILE_MACHINE_ARM64      0xAA64

/*
 * File Characteristics
 */
#define IMAGE_FILE_RELOCS_STRIPPED           0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010
#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020
#define IMAGE_FILE_16BIT_MACHINE             0x0040
#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080
#define IMAGE_FILE_32BIT_MACHINE             0x0100
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800
#define IMAGE_FILE_SYSTEM                    0x1000
#define IMAGE_FILE_DLL                       0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000
#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000

/*
 * Subsystems
 */
#define IMAGE_SUBSYSTEM_UNKNOWN                         0
#define IMAGE_SUBSYSTEM_NATIVE                          1
#define IMAGE_SUBSYSTEM_WINDOWS_GUI                     2
#define IMAGE_SUBSYSTEM_WINDOWS_CUI                     3
#define IMAGE_SUBSYSTEM_OS2_CUI                         5
#define IMAGE_SUBSYSTEM_POSIX_CUI                       7
// #define IMAGE_SUBSYSTEM_NATIVE_WINDOWS                  8
// #define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI                  9
// #define IMAGE_SUBSYSTEM_EFI_APPLICATION                 10
// #define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER         11
// #define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER              12
// #define IMAGE_SUBSYSTEM_EFI_ROM                         13
// #define IMAGE_SUBSYSTEM_XBOX                            14
// #define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION        16
// #define IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG               17


#define IMAGE_SIZEOF_SHORT_NAME 8

/*
 * Section Characteristics
 */
#define IMAGE_SCN_TYPE_REGULAR            0x00000000    // Reserved - Old name
#define IMAGE_SCN_TYPE_REG                IMAGE_SCN_TYPE_REGULAR
#define IMAGE_SCN_TYPE_DUMMY              0x00000001    // Reserved - Old name
#define IMAGE_SCN_TYPE_DSECT              IMAGE_SCN_TYPE_DUMMY
#define IMAGE_SCN_TYPE_NOLOAD             0x00000002    // Reserved
#define IMAGE_SCN_TYPE_GROUPED            0x00000004    // Reserved - Old name
#define IMAGE_SCN_TYPE_GROUP              IMAGE_SCN_TYPE_GROUPED
#define IMAGE_SCN_TYPE_NO_PAD             0x00000008
#define IMAGE_SCN_TYPE_COPY               0x00000010    // Reserved
#define IMAGE_SCN_CNT_CODE                0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA    0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA  0x00000080
#define IMAGE_SCN_LNK_OTHER               0x00000100    // Reserved
#define IMAGE_SCN_LNK_INFO                0x00000200
#define IMAGE_SCN_LNK_OVERLAY             0x00000400    // Reserved
#define IMAGE_SCN_TYPE_OVER               IMAGE_SCN_LNK_OVERLAY
#define IMAGE_SCN_LNK_REMOVE              0x00000800
#define IMAGE_SCN_LNK_COMDAT              0x00001000
#define IMAGE_SCN_COMPRESSED              0x00002000    // Reserved
#define IMAGE_SCN_MEM_PROTECTED           0x00004000    // Obsolete
#define IMAGE_SCN_NO_DEFER_SPEC_EXC       0x00004000
#define IMAGE_SCN_GPREL                   0x00008000
#define IMAGE_SCN_MEM_FARDATA             IMAGE_SCN_GPREL
#define IMAGE_SCN_MEM_SYSHEAP             0x00010000    // Obsolete
#define IMAGE_SCN_MEM_PURGEABLE           0x00020000    // Reserved
#define IMAGE_SCN_MEM_16BIT               IMAGE_SCN_MEM_PURGEABLE
#define IMAGE_SCN_MEM_LOCKED              0x00040000    // Reserved
#define IMAGE_SCN_MEM_PRELOAD             0x00080000    // Reserved
/* Range of IMAGE_SCN_ALIGN_xxBYTES values */
#define IMAGE_SCN_LNK_NRELOC_OVFL         0x01000000
#define IMAGE_SCN_MEM_DISCARDABLE         0x02000000
#define IMAGE_SCN_MEM_NOT_CACHED          0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED           0x08000000
#define IMAGE_SCN_MEM_SHARED              0x10000000
#define IMAGE_SCN_MEM_EXECUTE             0x20000000
#define IMAGE_SCN_MEM_READ                0x40000000
#define IMAGE_SCN_MEM_WRITE               0x80000000


#define IMAGE_DIRECTORY_ENTRY_EXPORT          0
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7 // x86-specific
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8
#define IMAGE_DIRECTORY_ENTRY_TLS             9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
#define IMAGE_DIRECTORY_ENTRY_IAT            12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

#include <pshpack2.h>
typedef struct _IMAGE_DOS_HEADER
{
    USHORT e_magic;
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_crlc;
    USHORT e_cparhdr;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    USHORT e_ss;
    USHORT e_sp;
    USHORT e_csum;
    USHORT e_ip;
    USHORT e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    LONG   e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
#include <poppack.h>

#include <pshpack4.h>
typedef struct _IMAGE_FILE_HEADER
{
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG  TimeDateStamp;
    ULONG  PointerToSymbolTable;
    ULONG  NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
    ULONG VirtualAddress;
    ULONG Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER32
{
    USHORT Magic;
    UCHAR  MajorLinkerVersion;
    UCHAR  MinorLinkerVersion;
    ULONG  SizeOfCode;
    ULONG  SizeOfInitializedData;
    ULONG  SizeOfUninitializedData;
    ULONG  AddressOfEntryPoint;
    ULONG  BaseOfCode;
    ULONG  BaseOfData;
    ULONG  ImageBase;
    ULONG  SectionAlignment;
    ULONG  FileAlignment;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT MajorImageVersion;
    USHORT MinorImageVersion;
    USHORT MajorSubsystemVersion;
    USHORT MinorSubsystemVersion;
    ULONG  Win32VersionValue;
    ULONG  SizeOfImage;
    ULONG  SizeOfHeaders;
    ULONG  CheckSum;
    USHORT Subsystem;
    USHORT DllCharacteristics;
    ULONG  SizeOfStackReserve;
    ULONG  SizeOfStackCommit;
    ULONG  SizeOfHeapReserve;
    ULONG  SizeOfHeapCommit;
    ULONG  LoaderFlags;
    ULONG  NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

// typedef struct _IMAGE_OPTIONAL_HEADER64
// {
    // USHORT Magic;
    // UCHAR  MajorLinkerVersion;
    // UCHAR  MinorLinkerVersion;
    // ULONG  SizeOfCode;
    // ULONG  SizeOfInitializedData;
    // ULONG  SizeOfUninitializedData;
    // ULONG  AddressOfEntryPoint;
    // ULONG  BaseOfCode;
    // ULONGLONG ImageBase;
    // ULONG SectionAlignment;
    // ULONG FileAlignment;
    // USHORT MajorOperatingSystemVersion;
    // USHORT MinorOperatingSystemVersion;
    // USHORT MajorImageVersion;
    // USHORT MinorImageVersion;
    // USHORT MajorSubsystemVersion;
    // USHORT MinorSubsystemVersion;
    // ULONG  Win32VersionValue;
    // ULONG  SizeOfImage;
    // ULONG  SizeOfHeaders;
    // ULONG  CheckSum;
    // USHORT Subsystem;
    // USHORT DllCharacteristics;
    // ULONGLONG SizeOfStackReserve;
    // ULONGLONG SizeOfStackCommit;
    // ULONGLONG SizeOfHeapReserve;
    // ULONGLONG SizeOfHeapCommit;
    // ULONG  LoaderFlags;
    // ULONG  NumberOfRvaAndSizes;
    // IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
// } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

// #ifdef _TARGET_PE64
// typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
// typedef PIMAGE_OPTIONAL_HEADER64 PIMAGE_OPTIONAL_HEADER;
// #else
typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32 PIMAGE_OPTIONAL_HEADER;
// #endif

typedef struct _IMAGE_NT_HEADERS32
{
    ULONG Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

// typedef struct _IMAGE_NT_HEADERS64
// {
    // ULONG Signature;
    // IMAGE_FILE_HEADER FileHeader;
    // IMAGE_OPTIONAL_HEADER32 OptionalHeader;
// } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

// #ifdef _TARGET_PE64
// typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
// typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
// #else
typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
// #endif

typedef struct _IMAGE_SECTION_HEADER
{
    UCHAR Name[IMAGE_SIZEOF_SHORT_NAME];
    union
    {
        ULONG PhysicalAddress;
        ULONG VirtualSize;
    } Misc;
    ULONG  VirtualAddress;
    ULONG  SizeOfRawData;
    ULONG  PointerToRawData;
    ULONG  PointerToRelocations;
    ULONG  PointerToLinenumbers;
    USHORT NumberOfRelocations;
    USHORT NumberOfLinenumbers;
    ULONG  Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY
{
    ULONG  Characteristics;
    ULONG  TimeDateStamp;
    USHORT MajorVersion;
    USHORT MinorVersion;
    ULONG  Name;                   // RVA from base of image
    ULONG  Base;
    ULONG  NumberOfFunctions;
    ULONG  NumberOfNames;
    ULONG  AddressOfFunctions;     // RVA from base of image
    ULONG  AddressOfNames;         // RVA from base of image
    ULONG  AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;


typedef struct _IMAGE_IMPORT_DESCRIPTOR
{
    _ANONYMOUS_UNION union
    {
        ULONG Characteristics;
        ULONG OriginalFirstThunk;
    } DUMMYUNIONNAME;
    ULONG TimeDateStamp;
    ULONG ForwarderChain;
    ULONG Name;
    ULONG FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_BY_NAME
{
    USHORT Hint;
    UCHAR  Name[ANYSIZE_ARRAY];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

#include <pshpack8.h>
typedef struct _IMAGE_THUNK_DATA64
{
    union
    {
        ULONGLONG ForwarderString;
        ULONGLONG Function;
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;
    } u1;
} IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;
#include <poppack.h>

typedef struct _IMAGE_THUNK_DATA32
{
    union
    {
        ULONG ForwarderString;
        ULONG Function;
        ULONG Ordinal;
        ULONG AddressOfData;
    } u1;
} IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;

#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL
#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)

// #ifdef _WIN64
// #define IMAGE_ORDINAL_FLAG IMAGE_ORDINAL_FLAG64
// #define IMAGE_ORDINAL(Ordinal) IMAGE_ORDINAL64(Ordinal)
// typedef IMAGE_THUNK_DATA64 IMAGE_THUNK_DATA;
// typedef PIMAGE_THUNK_DATA64 PIMAGE_THUNK_DATA;
// #define IMAGE_SNAP_BY_ORDINAL(Ordinal) IMAGE_SNAP_BY_ORDINAL64(Ordinal)
// #else
#define IMAGE_ORDINAL_FLAG IMAGE_ORDINAL_FLAG32
#define IMAGE_ORDINAL(Ordinal) IMAGE_ORDINAL32(Ordinal)
typedef IMAGE_THUNK_DATA32 IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA32 PIMAGE_THUNK_DATA;
#define IMAGE_SNAP_BY_ORDINAL(Ordinal) IMAGE_SNAP_BY_ORDINAL32(Ordinal)
// #endif


typedef struct _IMAGE_RESOURCE_DATA_ENTRY
{
    ULONG OffsetToData;
    ULONG Size;
    ULONG CodePage;
    ULONG Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

typedef struct _IMAGE_DEBUG_DIRECTORY
{
    ULONG  Characteristics;
    ULONG  TimeDateStamp;
    USHORT MajorVersion;
    USHORT MinorVersion;
    ULONG  Type;
    ULONG  SizeOfData;
    ULONG  AddressOfRawData;
    ULONG  PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

#define IMAGE_DEBUG_TYPE_UNKNOWN        0
#define IMAGE_DEBUG_TYPE_COFF           1
#define IMAGE_DEBUG_TYPE_CODEVIEW       2
#define IMAGE_DEBUG_TYPE_FPO            3
#define IMAGE_DEBUG_TYPE_MISC           4
#define IMAGE_DEBUG_TYPE_EXCEPTION      5
#define IMAGE_DEBUG_TYPE_FIXUP          6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC    7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC  8
#define IMAGE_DEBUG_TYPE_BORLAND        9
#define IMAGE_DEBUG_TYPE_RESERVED10     10
#define IMAGE_DEBUG_TYPE_CLSID          11

typedef struct _IMAGE_COFF_SYMBOLS_HEADER
{
    ULONG NumberOfSymbols;
    ULONG LvaToFirstSymbol;
    ULONG NumberOfLinenumbers;
    ULONG LvaToFirstLinenumber;
    ULONG RvaToFirstByteOfCode;
    ULONG RvaToLastByteOfCode;
    ULONG RvaToFirstByteOfData;
    ULONG RvaToLastByteOfData;
} IMAGE_COFF_SYMBOLS_HEADER, *PIMAGE_COFF_SYMBOLS_HEADER;

typedef struct _IMAGE_BASE_RELOCATION
{
    ULONG VirtualAddress;
    ULONG SizeOfBlock;
    // Followed by: USHORT TypeOffset[ANYSIZE_ARRAY];
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;
#include <poppack.h>

#ifndef UNALIGNED
#define UNALIGNED
#endif

#include <pshpack2.h>
typedef struct _IMAGE_RELOCATION
{
    _ANONYMOUS_UNION union
    {
        ULONG VirtualAddress;
        ULONG RelocCount;
    } DUMMYUNIONNAME;
    ULONG  SymbolTableIndex;
    USHORT Type;
} IMAGE_RELOCATION;
typedef struct _IMAGE_RELOCATION UNALIGNED *PIMAGE_RELOCATION;

#define IMAGE_REL_I386_ABSOLUTE 0x0001
#define IMAGE_REL_I386_DIR32    0x0006

typedef struct _IMAGE_SYMBOL
{
    union
    {
        UCHAR ShortName[8];
        struct
        {
            ULONG Short;
            ULONG Long;
        } Name;
        ULONG LongName[2];
    } N;
    ULONG  Value;
    SHORT  SectionNumber;
    USHORT Type;
    UCHAR  StorageClass;
    UCHAR  NumberOfAuxSymbols;
} IMAGE_SYMBOL;
typedef struct _IMAGE_SYMBOL UNALIGNED *PIMAGE_SYMBOL;
#include <poppack.h>

#define IMAGE_FIRST_SECTION(h) ((PIMAGE_SECTION_HEADER)((ULONG_PTR)h + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + ((PIMAGE_NT_HEADERS)(h))->FileHeader.SizeOfOptionalHeader))

#endif /* _PECOFF_H_ */
