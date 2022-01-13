/*
 * PROJECT:     PE Converter for NT PDK v1.196 (September 1991) and PDK October 1991
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Old PE Format Type definitions used in NT PDK v1.196.
 * COPYRIGHT:   Copyright 2021-2022 Hermès Bélusca-Maïto
 *
 * These definitions have been extracted from the
 * embedded debug symbols in the \I386\DEBUG\I386KD.EXE
 * executable of the NT PDK v1.196 release.
 */

#ifndef _NT196PE_H_
#define _NT196PE_H_

#pragma once

/* The usual IMAGE_DOS_HEADER, but using its "legacy" name */
typedef struct _IMAGE_DOS_HEADER _DOS_IMAGE_HEADER, DOS_IMAGE_HEADER, *PDOS_IMAGE_HEADER;

/*
 * This structure is the equivalent of the newer
 *
 * typedef struct _IMAGE_DATA_DIRECTORY
 * {
 *     ULONG VirtualAddress;
 *     ULONG Size;
 * } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
 */
typedef struct _IMAGE_SPECIAL_DIRECTORY
{
    ULONG RVA;
    ULONG Size;
} IMAGE_SPECIAL_DIRECTORY, *PIMAGE_SPECIAL_DIRECTORY;

/* The old version of IMAGE_NUMBEROF_DIRECTORY_ENTRIES */
#define IMAGE_NUMBEROF_SPECIAL_DIRECTORY_ENTRIES 7

// #define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 9 // <-- for the "old" new PE (see ProcessPEImage()).

/*
 * Old NT Subsystems values.
 *
 * These are the values of the IMAGE_HEADER::SubSystem field,
 * that match those mapped from the 'SubSystemType=' option in the
 * CSRSS command line (and stored in the CsrSubSystemType variable).
 * Compare them with the new IMAGE_SUBSYSTEM_xxx ones.
 * Note also that there is no distinction between Windows GUI and CUI.
 */
#define OLD_IMAGE_SUBSYSTEM_UNKNOWN     0
#define OLD_IMAGE_SUBSYSTEM_OS2         1
#define OLD_IMAGE_SUBSYSTEM_WINDOWS     2
// 3 is undefined
#define OLD_IMAGE_SUBSYSTEM_NATIVE      4
#define OLD_IMAGE_SUBSYSTEM_POSIX       5

/*
 * This structure is an old version for the combination of
 * IMAGE_NT_HEADERS + IMAGE_FILE_HEADER + IMAGE_OPTIONAL_HEADER.
 */
typedef struct _IMAGE_HEADER
{
    ULONG  SignatureBytes;
    UCHAR  Endian;
    UCHAR  Reserved1;
    USHORT CPUType;
    USHORT OSType;
    USHORT SubSystem;
    USHORT OSMajor;
    USHORT OSMinor;
    USHORT LinkerMajor;
    USHORT LinkerMinor;
    USHORT UserMajor;
    USHORT UserMinor;
    ULONG  ModuleFlags;
    ULONG  Reserved2;
    ULONG  FileCheckSum;
    ULONG  EntryPointRVA;
    ULONG  ImageBase;
    ULONG  ImageSize;
    ULONG  HeaderSize;
    ULONG  FileAlign;
    ULONG  PageSize;
    ULONG  TimeStamp;
    ULONG  StackReserve;
    ULONG  StackCommit;
    ULONG  HeapReserve;
    ULONG  HeapCommit;
    ULONG  NumberOfObjects;
    ULONG  ObjectTableRVA;
    ULONG  NumberOfDirectives;
    ULONG  DirectiveTableRVA;
    ULONG  Reserved3;
    ULONG  Reserved4;
    ULONG  Reserved5;
    ULONG  NumberOfSpecialRVAs;
    IMAGE_SPECIAL_DIRECTORY DataDirectory[IMAGE_NUMBEROF_SPECIAL_DIRECTORY_ENTRIES];
    /*
     * These are the first 9 PE directories:
     * Export               IMAGE_DIRECTORY_ENTRY_EXPORT
     * Import               IMAGE_DIRECTORY_ENTRY_IMPORT
     * Resource             IMAGE_DIRECTORY_ENTRY_RESOURCE
     * Exception            IMAGE_DIRECTORY_ENTRY_EXCEPTION
     * Security             IMAGE_DIRECTORY_ENTRY_SECURITY
     * Relocations          IMAGE_DIRECTORY_ENTRY_BASERELOC
     * Debug                IMAGE_DIRECTORY_ENTRY_DEBUG
     ****
     * ImageDescription     IMAGE_DIRECTORY_ENTRY_COPYRIGHT (x86-specific) / IMAGE_DIRECTORY_ENTRY_ARCHITECTURE
     * MachineSpecific      IMAGE_DIRECTORY_ENTRY_GLOBALPTR
     */
} IMAGE_HEADER, *PIMAGE_HEADER;

/*
 * This structure is an old version
 * of the newer IMAGE_SECTION_HEADER.
 */
typedef struct _IMAGE_OBJECT_HEADER
{
    ULONG RVA;
    ULONG VirtualSize;
    ULONG SeekOffset;
    ULONG OnDiskSize;
    ULONG ObjectFlags;
    ULONG Reserved;
} IMAGE_OBJECT_HEADER, *PIMAGE_OBJECT_HEADER;

/*
 * This structure can be viewed as an old version
 * of the newer IMAGE_DEBUG_DIRECTORY.
 */
typedef struct _COFF_DEBUG_DIRECTORY
{
    ULONG Characteristics;
    ULONG VersionStamp;
    ULONG SizeOfData;
    ULONG Type;
    ULONG AddressOfRawData;
    ULONG PointerToRawData;
} COFF_DEBUG_DIRECTORY, *PCOFF_DEBUG_DIRECTORY;

/*
 * The usual IMAGE_COFF_SYMBOLS_HEADER, but using its "legacy" name.
 * It should be noted that both LvaToFirstSymbol and LvaToFirstLinenumber
 * are relative to the beginning of their corresponding info structure.
 */
typedef struct _IMAGE_COFF_SYMBOLS_HEADER _COFF_DEBUG_INFO, COFF_DEBUG_INFO, *PCOFF_DEBUG_INFO;


/*
 * Supplementary old NT PE/COFF structures extracted from I386KD.EXE
 * but not currently used in the converter.
 */
#if 0

typedef struct _COFF_FILE_HEADER
{
    USHORT TargetMachine;
    USHORT NumberOfSections;
    ULONG  TimeDateStamp;
    ULONG  PointerToSymbolTable;
    ULONG  NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} COFF_FILE_HEADER, *PCOFF_FILE_HEADER;

typedef struct _COFF_DATA_DIRECTORY
{
    ULONG VirtualAddress;
    ULONG Size;
} COFF_DATA_DIRECTORY, *PCOFF_DATA_DIRECTORY;

typedef struct _COFF_OPTIONAL_HEADER
{
    USHORT TargetVersionStamp;
    USHORT LinkerVersionStamp;
    ULONG  SizeOfCode;
    ULONG  SizeOfInitializedData;
    ULONG  SizeOfUninitializedData;
    ULONG  AddressOfEntryPoint;
    ULONG  BaseOfCode;
    ULONG  BaseOfData;
    ULONG  ImageBase;
    ULONG  ImageAlignment;
    ULONG  FileAlignment;
    USHORT TargetOperatingSystem;
    USHORT TargetSubsystem;
    ULONG  ImageVersionStamp;
    ULONG  SizeOfImage;
    ULONG  SizeOfHeaders;

    ULONG  SizeOfHeapReserve;
    ULONG  SizeOfHeapCommit;
    ULONG  SizeOfStackReserve;
    ULONG  SizeOfStackCommit;

    ULONG  ZeroBits;
    ULONG  CheckSum;
    COFF_DATA_DIRECTORY DataDirectory[7];
    ULONG  AdditionalMachineValues[8];
} COFF_OPTIONAL_HEADER, *PCOFF_OPTIONAL_HEADER;

#ifndef IMAGE_SIZEOF_SHORT_NAME
#define IMAGE_SIZEOF_SHORT_NAME 8
#endif

/*
 * This structure is almost identical to the newer IMAGE_SECTION_HEADER,
 * except that it does not unionize PhysicalAddress with VirtualSize.
 */
typedef struct _COFF_STD_SECTION_HEADER
{
    UCHAR  Name[IMAGE_SIZEOF_SHORT_NAME];
    ULONG  PhysicalAddress;
    ULONG  VirtualAddress;
    ULONG  SizeOfRawData;
    ULONG  PointerToRawData;
    ULONG  PointerToRelocations;
    ULONG  PointerToLinenumbers;
    USHORT NumberOfRelocations;
    USHORT NumberOfLinenumbers;
    ULONG  Characteristics;
} COFF_STD_SECTION_HEADER, *PCOFF_STD_SECTION_HEADER;

/* Same definition as IMAGE_SYMBOL */
typedef struct _COFF_SYMBOL_TABLE
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
    ULONG Value;
    SHORT SectionNumber;
    USHORT Type;
    UCHAR  StorageClass;
    UCHAR  NumberOfAuxSymbols;
    USHORT Pad;
} COFF_SYMBOL_TABLE, *PCOFF_SYMBOL_TABLE;

typedef struct _COFF_LINENUMBER
{
    union
    {
        ULONG SymbolTableIndex;
        ULONG VirtualAddress;
    } Type;
    USHORT Linenumber;
} COFF_LINENUMBER, *PCOFF_LINENUMBER;

/*
 * From I386KD and deciphered thanks mainly to
 * https://github.com/LuaDist/tcc/blob/master/coff.h
 * and to http://osr507doc.sco.com/en/topics/COFF_AuxEntryDecl.html
 * This is a sliglthy older version of the IMAGE_AUX_SYMBOL structure.
 */
typedef union _COFF_AUX_SYMBOL_TABLE
{
    struct
    {
        ULONG TagIndex;

        union
        {
            struct
            {
                USHORT Linenumber;
                USHORT Size;
            } x_lnsz;

            ULONG SizeOfFunction;
        } x_misc;

        union
        {
        // AUX_SYMBOL_F2
            struct
            {
                ULONG PointerToLinenumber;
                ULONG PointerToNextFunction;
            } x_fcn;

            struct
            {
#define DIMNUM    4
                USHORT x_dimen[DIMNUM];
            }
            x_ary;
        } x_fcnary;

        USHORT x_tvndx;
        USHORT Pad;
    } x_sym;

    struct
    {
#define FILNMLEN  14
        CHAR x_fname[FILNMLEN];
    } x_file;

    struct
    {
        ULONG  x_scnlen;
        USHORT x_nreloc;
        USHORT x_nlinno;
    } x_scn;

} COFF_AUX_SYMBOL_TABLE, *PCOFF_AUX_SYMBOL_TABLE;

// typedef IMAGE_AUX_SYMBOL UNALIGNED *PIMAGE_AUX_SYMBOL;

#endif

#endif /* _NT196PE_H_ */
