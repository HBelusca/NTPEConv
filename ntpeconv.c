/*
 * PROJECT:     PE Converter for NT PDK v1.196 (September 1991) and PDK October 1991
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Converts old-style PE format to newer format
 *              that can be recognized by modern tools.
 * COPYRIGHT:   Copyright 2021 Hermès Bélusca-Maïto
 */

#define PROGNAME        "NTPECONV"
#define VERSION         "0.9a2"
#define COPYRIGHT_YEARS "2021"

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h> // For _countof() -- TODO: Make it compiler-independent.
#include <locale.h> // For setlocale().
// #include <io.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include "typedefs.h"
#include "pecoff.h"

/* Supplemental types */
typedef char bool;
#define false 0
#define true  1

// #define NULL ((void*)0)

/* Standard page size for i386 */
#define PAGE_SIZE 0x1000


// #ifdef _PPC_
#define SWAPD(x) ((((x)&0xff)<<24)|(((x)&0xff00)<<8)|(((x)>>8)&0xff00)|(((x)>>24)&0xff))
#define SWAPW(x) ((((x)&0xff)<<8)|(((x)>>8)&0xff))
#define SWAPQ(x) ((SWAPD((x)&0xffffffff) << 32) | (SWAPD((x)>>32)))
// #else
// #define SWAPD(x) (x)
// #define SWAPW(x) (x)
// #define SWAPQ(x) (x)
// #endif


#define RVA(b, m) ((PVOID)((ULONG_PTR)(b) + (ULONG_PTR)(m)))


/*
 * These definitions have been extracted from the
 * embedded debug symbols in the \I386\DEBUG\I386KD.EXE
 * executable of the NT Build 1.196 release.
 */

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
 * IMAGE_NT_HEADERS + IMAGE_FILE_HEADER + IMAGE_OPTIONAL_HEADER
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
     * ImageDescription     IMAGE_DIRECTORY_ENTRY_COPYRIGHT (x86-specific) / IMAGE_DIRECTORY_ENTRY_ARCHITECTURE
     * MachineSpecific      IMAGE_DIRECTORY_ENTRY_GLOBALPTR
     */
} IMAGE_HEADER, *PIMAGE_HEADER;

/*
 * This structure is an old version of
 * the newer IMAGE_SECTION_HEADER.
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
 * VOID
 * __cdecl
 * PrintWarning(
 *     IN PCSTR ErrorFmt,
 *      ...);
 */
#define PrintWarning(WarningFmt, ...) \
    fprintf(stdout, PROGNAME ": " WarningFmt, ##__VA_ARGS__)

/*
 * VOID
 * __cdecl
 * PrintError(
 *     IN PCSTR ErrorFmt,
 *      ...);
 */
#define PrintError(ErrorFmt, ...) \
    fprintf(stderr, PROGNAME ": " ErrorFmt, ##__VA_ARGS__)

typedef enum _ERROR_TYPE
{
    ErrorInvalidPE = 0,
    ErrorMalformedPE,
    ErrorUnsupportedPE,
    ErrorTypeMax
} ERROR_TYPE;

static PCSTR Errors[] =
{
    "Not a valid PE image!",
    "Malformed PE image!",
    "Unsupported PE image!",
    "Unknown"
};

/*
 * VOID
 * __cdecl
 * PrintErrorReason(
 *     IN ERROR_TYPE ErrorType,
 *     IN PCSTR Reason,
 *      ...);
 */
#define PrintErrorReason(ErrorType, Reason, ...)    \
do { \
    C_ASSERT((ErrorType) <= ErrorTypeMax);          \
    PrintError("%s (" Reason ")\n",                 \
               Errors[ErrorType], ##__VA_ARGS__);   \
} while (0)


#define _VAR_AS_PUCHAR(var)     ((PUCHAR)&(var))
#define PRINT_BYTE_CHAR(b)      (isprint(b) ? (b) : '.')
#define PRINT_VAR_CHAR(var, i)  PRINT_BYTE_CHAR(_VAR_AS_PUCHAR(var)[i])


/**
 * @brief   Copies a source file into a destination file.
 *          Handles to both files should already be opened.
 **/
//
// TODO: Implement the portability fixes indicated in
// https://wiki.sei.cmu.edu/confluence/display/c/FIO19-C.+Do+not+use+fseek%28%29+and+ftell%28%29+to+compute+the+size+of+a+regular+file
//
static BOOLEAN
CopyFile(
    IN FILE* pSourceFile,
    IN size_t nFileSize OPTIONAL,
    IN FILE* pDestFile)
{
    BOOLEAN bSuccess = FALSE;
    struct
    {
        UCHAR Static[1024];
        PVOID Local;
        size_t Size;
    } Buffer;
    size_t CopySize;

    /* Retrieve the actual file size if it was zero */
    if (nFileSize == 0)
    {
        fseek(pSourceFile, 0, SEEK_END);
        nFileSize = ftell(pSourceFile);
        rewind(pSourceFile);
    }
    /* If the file size is still zero, there is nothing to copy,
     * just set the destination file to zero and we are done. */
    if (nFileSize == 0)
    {
        fseek(pDestFile, 0, SEEK_SET);
        fflush(pDestFile);
        freopen(NULL, "wb+", pDestFile);
        return TRUE;
    }

    if (nFileSize <= sizeof(Buffer.Static))
    {
        /* Use the static buffer */
        Buffer.Local = Buffer.Static;
        Buffer.Size = nFileSize;
    }
    else
    {
        /* Allocate buffers */
        Buffer.Local = malloc(nFileSize);
        if (Buffer.Local)
        {
            Buffer.Size = nFileSize;
        }
        else
        {
            /* We failed a large allocation, fall back to using the static buffer */
            Buffer.Local = Buffer.Static;
            Buffer.Size = sizeof(Buffer.Static);
        }
    }

    /* Copy by chunks */
    fseek(pSourceFile, 0, SEEK_SET);
    fseek(pDestFile, 0, SEEK_SET);
    while (nFileSize > 0)
    {
        CopySize = min(nFileSize, Buffer.Size);
        if (!fread(Buffer.Local, CopySize, 1, pSourceFile))
        {
            PrintError("Failed to read %lu bytes from source file\n", (ULONG)CopySize);
            goto Quit;
        }
        if (!fwrite(Buffer.Local, CopySize, 1, pDestFile))
        {
            PrintError("Failed to write %lu bytes to destination file\n", (ULONG)CopySize);
            goto Quit;
        }

        nFileSize -= min(nFileSize, Buffer.Size);
    }
    fflush(pDestFile);

    bSuccess = TRUE;

Quit:
    if (Buffer.Local && (Buffer.Local != Buffer.Static))
        free(Buffer.Local);

    return bSuccess;
}

/**
 * @brief   Dumps the DOS and old-style PE headers of a PE image.
 **/
static VOID
DumpOldPEImage(
    IN PDOS_IMAGE_HEADER DosHeader,
    IN PIMAGE_HEADER NtHeader)
{
    static PCSTR IMAGE_SPECIAL_DIRECTORY_NAMES[IMAGE_NUMBEROF_SPECIAL_DIRECTORY_ENTRIES] =
    {
        "IMAGE_DIRECTORY_ENTRY_EXPORT",
        "IMAGE_DIRECTORY_ENTRY_IMPORT",
        "IMAGE_DIRECTORY_ENTRY_RESOURCE",
        "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
        "IMAGE_DIRECTORY_ENTRY_SECURITY",
        "IMAGE_DIRECTORY_ENTRY_BASERELOC",
        "IMAGE_DIRECTORY_ENTRY_DEBUG",
        // "IMAGE_DIRECTORY_ENTRY_COPYRIGHT", // (x86 - specific), otherwise: "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE"
        // "IMAGE_DIRECTORY_ENTRY_GLOBALPTR"
    };

    PIMAGE_OBJECT_HEADER ObjTable = NULL;
    ULONG i;

    /* Get a pointer to the object table; the ObjectTableRVA has been already
     * adjusted so that it systematically points just after the structure. */
    if (NtHeader->ObjectTableRVA)
    {
        ASSERT(NtHeader->NumberOfObjects);
        ObjTable = RVA(NtHeader, NtHeader->ObjectTableRVA);
    }

    printf("DOS_IMAGE_HEADER\n"
           "================\n"
           "    e_magic     = 0x%04X '%c%c'\n"
           "    e_cblp      = 0x%04X\n"
           "    e_cp        = 0x%04X\n"
           "    e_crlc      = 0x%04X\n"
           "    e_cparhdr   = 0x%04X\n"
           "    e_minalloc  = 0x%04X\n"
           "    e_maxalloc  = 0x%04X\n"
           "    e_ss        = 0x%04X\n"
           "    e_sp        = 0x%04X\n"
           "    e_csum      = 0x%04X\n"
           "    e_ip        = 0x%04X\n"
           "    e_cs        = 0x%04X\n"
           "    e_lfarlc    = 0x%04X\n"
           "    e_ovno      = 0x%04X\n"
           "    e_res[4]    = { 0x%04X, 0x%04X, 0x%04X, 0x%04X }\n"
           "    e_oemid     = 0x%04X\n"
           "    e_oeminfo   = 0x%04X\n"
           "    e_res2[10]  = { 0x%04X, 0x%04X, 0x%04X, 0x%04X, 0x%04X,\n"
           "                    0x%04X, 0x%04X, 0x%04X, 0x%04X, 0x%04X }\n"
           "    e_lfanew    = 0x%04X\n"
           "\n",
           DosHeader->e_magic,
           PRINT_VAR_CHAR(DosHeader->e_magic, 0), PRINT_VAR_CHAR(DosHeader->e_magic, 1),
           DosHeader->e_cblp,
           DosHeader->e_cp,
           DosHeader->e_crlc,
           DosHeader->e_cparhdr,
           DosHeader->e_minalloc,
           DosHeader->e_maxalloc,
           DosHeader->e_ss,
           DosHeader->e_sp,
           DosHeader->e_csum,
           DosHeader->e_ip,
           DosHeader->e_cs,
           DosHeader->e_lfarlc,
           DosHeader->e_ovno,
           DosHeader->e_res[0], DosHeader->e_res[1], DosHeader->e_res[2], DosHeader->e_res[3],
           DosHeader->e_oemid,
           DosHeader->e_oeminfo,
           DosHeader->e_res2[0], DosHeader->e_res2[1], DosHeader->e_res2[2], DosHeader->e_res2[3], DosHeader->e_res2[4],
           DosHeader->e_res2[5], DosHeader->e_res2[6], DosHeader->e_res2[7], DosHeader->e_res2[8], DosHeader->e_res2[9],
           DosHeader->e_lfanew);

    printf("IMAGE_HEADER\n"
           "============\n"
           "    SignatureBytes  = 0x%08X '%c%c%c%c'\n"
           "\n"
           "    Endian          = 0x%02X\n"
           "    Reserved1       = 0x%02X\n"
           "\n"
           "    CPUType         = 0x%04X\n"
           "    OSType          = 0x%04X\n"
           "    SubSystem       = 0x%04X\n"
           "    OSMajor         = 0x%04X\n"
           "    OSMinor         = 0x%04X\n"
           "    LinkerMajor     = 0x%04X\n"
           "    LinkerMinor     = 0x%04X\n"
           "    UserMajor       = 0x%04X\n"
           "    UserMinor       = 0x%04X\n"
           "\n"
           "    ModuleFlags         = 0x%08X\n"
           "    Reserved2           = 0x%08X\n"
           "    FileCheckSum        = 0x%08X\n"
           "    EntryPointRVA       = 0x%08X\n"
           "    ImageBase           = 0x%08X\n"
           "    ImageSize           = 0x%08X\n"
           "    HeaderSize          = 0x%08X\n"
           "    FileAlign           = 0x%08X\n"
           "    PageSize            = 0x%08X\n"
           "    TimeStamp           = 0x%08X\n"
           "    StackReserve        = 0x%08X\n"
           "    StackCommit         = 0x%08X\n"
           "    HeapReserve         = 0x%08X\n"
           "    HeapCommit          = 0x%08X\n"
           "    NumberOfObjects     = 0x%08X\n"
           "    ObjectTableRVA      = 0x%08X\n"
           "    NumberOfDirectives  = 0x%08X\n"
           "    DirectiveTableRVA   = 0x%08X\n"
           "    Reserved3           = 0x%08X\n"
           "    Reserved4           = 0x%08X\n"
           "    Reserved5           = 0x%08X\n"
           "    NumberOfSpecialRVAs = 0x%08X\n"
           "\n",
           NtHeader->SignatureBytes,
           PRINT_VAR_CHAR(NtHeader->SignatureBytes, 0), PRINT_VAR_CHAR(NtHeader->SignatureBytes, 1),
           PRINT_VAR_CHAR(NtHeader->SignatureBytes, 2), PRINT_VAR_CHAR(NtHeader->SignatureBytes, 3),
           NtHeader->Endian,
           NtHeader->Reserved1,
           NtHeader->CPUType,
           NtHeader->OSType,
           NtHeader->SubSystem,
           NtHeader->OSMajor,
           NtHeader->OSMinor,
           NtHeader->LinkerMajor,
           NtHeader->LinkerMinor,
           NtHeader->UserMajor,
           NtHeader->UserMinor,
           NtHeader->ModuleFlags,
           NtHeader->Reserved2,
           NtHeader->FileCheckSum,
           NtHeader->EntryPointRVA,
           NtHeader->ImageBase,
           NtHeader->ImageSize,
           NtHeader->HeaderSize,
           NtHeader->FileAlign,
           NtHeader->PageSize,
           NtHeader->TimeStamp,
           NtHeader->StackReserve,
           NtHeader->StackCommit,
           NtHeader->HeapReserve,
           NtHeader->HeapCommit,
           NtHeader->NumberOfObjects,
           NtHeader->ObjectTableRVA,
           NtHeader->NumberOfDirectives,
           NtHeader->DirectiveTableRVA,
           NtHeader->Reserved3,
           NtHeader->Reserved4,
           NtHeader->Reserved5,
           NtHeader->NumberOfSpecialRVAs);

    for (i = 0; i < NtHeader->NumberOfSpecialRVAs; ++i)
    {
        printf("    DataDirectory[%s] =\n"
               "        { RVA: 0x%08X , Size: 0x%08X }\n",
               IMAGE_SPECIAL_DIRECTORY_NAMES[i],
               NtHeader->DataDirectory[i].RVA,
               NtHeader->DataDirectory[i].Size);
    }
    printf("\n");

    if (ObjTable)
    {
        printf("Sections:\n"
               "=========\n");
        for (i = 0; i < NtHeader->NumberOfObjects; ++i)
        {
            printf("[%lu] -->\n"
                   "    RVA         = 0x%08X\n"
                   "    VirtualSize = 0x%08X\n"
                   "    SeekOffset  = 0x%08X\n"
                   "    OnDiskSize  = 0x%08X\n"
                   "    ObjectFlags = 0x%08X\n"
                   "    Reserved    = 0x%08X\n",
                   i,
                   ObjTable[i].RVA,
                   ObjTable[i].VirtualSize,
                   ObjTable[i].SeekOffset,
                   ObjTable[i].OnDiskSize,
                   ObjTable[i].ObjectFlags,
                   ObjTable[i].Reserved);
        }
        printf("\n");
    }
}

/**
 * @brief   Parses an old-style PE image and retrieves its DOS and old-style
 *          PE headers. Validation and sanitization are performed.
 *          Returns TRUE if success, FALSE if failure (validation failed, or
 *          any other error happened).
 *
 * Sanitization includes:
 * 
 * - Making NumberOfObjects and ObjectTableRVA fields consistent.
 *
 * - Making NumberOfDirectives and DirectiveTableRVA fields consistent.
 *   (NOTE: Unimplemented since PE executable images should have these fields
 *   empty, otherwise an error is emitted.)
 **/
static BOOLEAN
ParseOldPEImage(
    IN FILE* pImageFile,
    IN size_t nFileSize,
    OUT PDOS_IMAGE_HEADER* pDosHeader,
    OUT PIMAGE_HEADER* pNtHeader,
    OUT PULONG pNtHeaderSize)
{
    PDOS_IMAGE_HEADER DosHeader = NULL;
    PIMAGE_HEADER NtHeader = NULL;
    PIMAGE_OBJECT_HEADER ObjTable = NULL;
    PVOID ptr;
    ULONG NtHeaderOffset;
    size_t NtHeaderSize;
    size_t TotalHeadersSize = 0;
    size_t DataDirectorySize = 0;
    size_t ObjectsTableSize = 0;

    /* Allocate memory for the DOS image header and load it */
    DosHeader = malloc(sizeof(DOS_IMAGE_HEADER));
    if (!DosHeader)
    {
        PrintError("Failed to allocate %lu bytes\n", (ULONG)sizeof(DOS_IMAGE_HEADER));
        return FALSE;
    }
    if (nFileSize < sizeof(DOS_IMAGE_HEADER))
    {
        PrintErrorReason(ErrorInvalidPE, "File smaller than DOS_IMAGE_HEADER size");
        goto Failure;
    }
    rewind(pImageFile);
    if (!fread(DosHeader, sizeof(DOS_IMAGE_HEADER), 1, pImageFile))
    {
        PrintError("Failed to read %lu bytes from source file\n", (ULONG)sizeof(DOS_IMAGE_HEADER));
        goto Failure;
    }

    /* Ensure it's a PE image */
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        PrintErrorReason(ErrorInvalidPE, "Invalid signature 0x%04X '%c%c'",
                         DosHeader->e_magic,
                         PRINT_VAR_CHAR(DosHeader->e_magic, 0), PRINT_VAR_CHAR(DosHeader->e_magic, 1));
        goto Failure;
    }

    /* Get the offset to the NT header */
    NtHeaderOffset = DosHeader->e_lfanew;

    /*
     * IMPORTANT NOTE!! We only support **VALID** PE files, and NOT
     * broken ones where e.g. the PE header is "merged" within the
     * DOS header, or where the list of objects/sections and directives
     * are not present after the PE header.
     */

     /* It should be aligned on a 8-byte boundary */
    if (ROUND_UP(NtHeaderOffset, sizeof(ULONG64)) != NtHeaderOffset)
    {
        PrintErrorReason(ErrorMalformedPE, "PE header offset not 8-byte aligned");
        goto Failure;
    }

    /* NOT BROKEN: The NT header must be **after** the DOS header */
    if (NtHeaderOffset < sizeof(DOS_IMAGE_HEADER))
    {
        PrintErrorReason(ErrorMalformedPE, "PE header offset in DOS header");
        goto Failure;
    }

    NtHeaderSize = FIELD_OFFSET(IMAGE_HEADER, DataDirectory);

    /* Make sure the old NT PE header fits into the size */
    TotalHeadersSize += NtHeaderOffset + NtHeaderSize;
    if (TotalHeadersSize >= nFileSize)
    {
        PrintErrorReason(ErrorMalformedPE, "NT headers beyond image size");
        goto Failure;
    }

    /* Allocate memory for the old NT PE header (excepting the Data directory)
     * and load it (it will be reallocated later to accomodate for the extra
     * directory array and the object/sections table). */
    NtHeader = malloc(NtHeaderSize);
    if (!NtHeader)
    {
        PrintError("Failed to allocate %lu bytes\n", (ULONG)NtHeaderSize);
        goto Failure;
    }
    if (nFileSize < NtHeaderOffset + NtHeaderSize)
    {
        PrintErrorReason(ErrorInvalidPE, "File smaller than IMAGE_HEADER size");
        goto Failure;
    }
    fseek(pImageFile, NtHeaderOffset, SEEK_SET);
    if (!fread(NtHeader, NtHeaderSize, 1, pImageFile))
    {
        PrintError("Failed to read %lu bytes from source file\n", (ULONG)NtHeaderSize);
        goto Failure;
    }

    /* Verify the PE Signature */
    if (NtHeader->SignatureBytes != IMAGE_NT_SIGNATURE)
    {
        PrintErrorReason(ErrorInvalidPE, "Invalid NT image signature 0x%08X '%c%c%c%c'",
                         NtHeader->SignatureBytes,
                         PRINT_VAR_CHAR(NtHeader->SignatureBytes, 0), PRINT_VAR_CHAR(NtHeader->SignatureBytes, 1),
                         PRINT_VAR_CHAR(NtHeader->SignatureBytes, 2), PRINT_VAR_CHAR(NtHeader->SignatureBytes, 3));
        goto Failure;
    }

#if 0
    /* Ensure this is an executable image */
    if ((NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)
    {
        PrintErrorReason(ErrorInvalidPE, "Invalid executable image!");
        goto Failure;
    }
#endif

    /* Verify that we are not actually looking at a new PE image */
    if (NtHeaderSize >= RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS32, OptionalHeader.Magic))
    {
        /* Overlay a new PE header structure and check some fields */
        PIMAGE_NT_HEADERS32 NewPEHeader = (PIMAGE_NT_HEADERS32)NtHeader;
        C_ASSERT(FIELD_OFFSET(IMAGE_NT_HEADERS32, Signature) == FIELD_OFFSET(IMAGE_HEADER, SignatureBytes));

        if ( (NewPEHeader->FileHeader.SizeOfOptionalHeader >= FIELD_OFFSET(IMAGE_OPTIONAL_HEADER32, DataDirectory)) &&
             ((NewPEHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ||
              (NewPEHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)) )
        {
            PrintError("This is already a new PE image!\n");
            goto Failure;
        }
    }

    /*
     * The total size of headers reported is equal to the combined size of:
     * the original DOS header size (+ its DOS stub), PE header, and section headers.
     * Contrary to the case of the new PE format, the old PE format does not
     * round it up to a multiple of FileAlignment (i.e. NtHeader->FileAlign).
     *
     * I will suppose that the size of the DOS header + its DOS stub is equal
     * to all the space from the beginning of the image up to the offset where
     * the old PE header starts, specified by DosHeader->e_lfanew.
     *
     * Also I suppose for now that the NumberOfXXX members are valid;
     * should they not be, it is most probable this HeaderSize check
     * will fail, and consequently the other checks on the NumberOfXXX
     * done below fail as well.
     */
    TotalHeadersSize = NtHeaderOffset /* DosHeader->e_lfanew */;
    TotalHeadersSize += FIELD_OFFSET(IMAGE_HEADER, DataDirectory) +
                        NtHeader->NumberOfSpecialRVAs * sizeof(IMAGE_SPECIAL_DIRECTORY) +
                        NtHeader->NumberOfObjects * sizeof(IMAGE_OBJECT_HEADER);
    if (NtHeader->HeaderSize != TotalHeadersSize)
    {
        // PrintErrorReason(ErrorInvalidPE, ...);
        PrintWarning("The reported NT header size %lu does not match the calculated size %lu!\n",
                     NtHeader->HeaderSize, (ULONG)TotalHeadersSize);
    }

    /* If any of the reserved fields are non-zero, print a warning but continue */
    if ((NtHeader->Reserved1 != 0) || (NtHeader->Reserved2 != 0) || (NtHeader->Reserved3 != 0) ||
        (NtHeader->Reserved4 != 0) || (NtHeader->Reserved5 != 0))
    {
        PrintWarning("Reserved fields non-zero, the image may be invalid!\n");
    }

    /* Directives are unsupported in PE images (they are object only) */
    if ((NtHeader->NumberOfDirectives != 0) || (NtHeader->DirectiveTableRVA != 0))
    {
        PrintErrorReason(ErrorUnsupportedPE, "Directives present in PE image");
        goto Failure;
    }

    /* Verify that the handled number of special data directories is valid */
    if (NtHeader->NumberOfSpecialRVAs > RTL_NUMBER_OF_FIELD(IMAGE_HEADER, DataDirectory))
    {
        PrintErrorReason(ErrorInvalidPE, "Invalid number of special data directories %lu; expected <= %lu",
                         NtHeader->NumberOfSpecialRVAs, (ULONG)RTL_NUMBER_OF_FIELD(IMAGE_HEADER, DataDirectory));
        goto Failure;
    }

    /* Verify that the objects/sections count and table are valid */
    if ( ((NtHeader->NumberOfObjects == 0) && (NtHeader->ObjectTableRVA != 0)) ||
         ((NtHeader->NumberOfObjects != 0) && (NtHeader->ObjectTableRVA == 0)) ||
         (NtHeader->NumberOfObjects > MAXUSHORT) )
    {
        PrintErrorReason(ErrorInvalidPE, "Invalid number of objects / object table");
        goto Failure;
    }

    /* Normalize for safety */
    if (NtHeader->NumberOfObjects == 0)
        NtHeader->ObjectTableRVA = 0;

    if (NtHeader->NumberOfSpecialRVAs)
    {
        // DataDirectorySize = RTL_FIELD_SIZE(IMAGE_HEADER, DataDirectory);
        DataDirectorySize = NtHeader->NumberOfSpecialRVAs * sizeof(IMAGE_SPECIAL_DIRECTORY);
        NtHeaderSize += DataDirectorySize;
    }
    if (NtHeader->NumberOfObjects)
    {
        ASSERT(NtHeader->ObjectTableRVA);
        ObjectsTableSize = NtHeader->NumberOfObjects * sizeof(IMAGE_OBJECT_HEADER);

        /* Make sure the object table fits into the size */
        if (NtHeader->ObjectTableRVA + ObjectsTableSize >= nFileSize)
        {
            PrintErrorReason(ErrorMalformedPE, "Object table beyond image size");
            goto Failure;
        }

        /* NOT BROKEN: The object table must be **after** the PE header */
        if (NtHeader->ObjectTableRVA < NtHeaderOffset + NtHeaderSize)
        {
            PrintErrorReason(ErrorMalformedPE, "Object table not following the PE header");
            goto Failure;
        }

        NtHeaderSize += ObjectsTableSize;
    }

    /*
     * Perform any necessary re-allocation to accomodate for the Data directory array and objects table.
     */
    if (NtHeaderSize > (size_t)FIELD_OFFSET(IMAGE_HEADER, DataDirectory))
    {
        /* Reallocate the NT PE header to accomodate for the Data directory array and the object table */
        ptr = realloc(NtHeader, NtHeaderSize);
        if (!ptr)
        {
            PrintError("Failed to re-allocate %lu bytes\n", (ULONG)NtHeaderSize);
            goto Failure;
        }
        NtHeader = ptr;

        if (DataDirectorySize)
        {
            /* Load it */
            fseek(pImageFile, NtHeaderOffset + FIELD_OFFSET(IMAGE_HEADER, DataDirectory), SEEK_SET);
            // if (!fread(&NtHeader->DataDirectory, DataDirectorySize, 1, pImageFile))
            if (!fread(&NtHeader->DataDirectory, sizeof(IMAGE_SPECIAL_DIRECTORY),
                       NtHeader->NumberOfSpecialRVAs, pImageFile))
            {
                PrintError("Failed to read %lu bytes from source file\n", (ULONG)DataDirectorySize);
                goto Failure;
            }
        }

        if (ObjectsTableSize)
        {
            /* Get a pointer to the object table */
            ObjTable = RVA(NtHeader, FIELD_OFFSET(IMAGE_HEADER, DataDirectory) + DataDirectorySize);

            /* Load it */
            fseek(pImageFile, NtHeader->ObjectTableRVA, SEEK_SET);
            // if (!fread(ObjTable, ObjectsTableSize, 1, pImageFile))
            if (!fread(ObjTable, sizeof(IMAGE_OBJECT_HEADER), NtHeader->NumberOfObjects, pImageFile))
            {
                PrintError("Failed to read %lu bytes from source file\n", (ULONG)ObjectsTableSize);
                goto Failure;
            }

            /* Fixup the ObjectTableRVA in the NT header so that it systematically points just after the structure */
            NtHeader->ObjectTableRVA = (ULONG)((ULONG_PTR)ObjTable - (ULONG_PTR)NtHeader);
        }
        else
        {
            /* No object table is present */
            NtHeader->ObjectTableRVA  = 0;
            NtHeader->NumberOfObjects = 0;
        }
    }

    /* Return the headers to the caller */
    *pDosHeader = DosHeader;
    *pNtHeader  = NtHeader;
    *pNtHeaderSize = (ULONG)NtHeaderSize;

    return TRUE;

Failure:
    if (NtHeader)
        free(NtHeader);
    if (DosHeader)
        free(DosHeader);
    return FALSE;
}

#if 0

static BOOLEAN
ParseNewPEImage(
    // IN PVOID pData,
    IN FILE* pImageFile,
    IN ULONG nFileSize,
    /**/ OUT PIMAGE_DOS_HEADER* pDosHeader,/**/
    OUT PIMAGE_HEADER* pNtHeader // OUT PIMAGE_NT_HEADERS32* pNtHeaders
    )
{
    PIMAGE_DOS_HEADER DosHeader = NULL;
    PIMAGE_HEADER NtHeader = NULL;
    ULONG NtHeaderOffset;
    ULONG TotalHeadersSize = 0;

    /* Allocate memory for the DOS image header and load it */
    DosHeader = malloc(sizeof(DOS_IMAGE_HEADER));
    if (!DosHeader)
    {
        PrintError("Failed to allocate %lu bytes\n", sizeof(DOS_IMAGE_HEADER));
        return FALSE;
    }
    if (nFileSize < sizeof(DOS_IMAGE_HEADER))
    {
        PrintErrorReason(ErrorInvalidPE, "File smaller than DOS_IMAGE_HEADER size");
        goto Failure;
    }
    rewind(pImageFile);
    if (!fread(DosHeader, sizeof(DOS_IMAGE_HEADER), 1, pImageFile))
    {
        PrintError("Failed to read %lu bytes from source file\n", sizeof(DOS_IMAGE_HEADER));
        goto Failure;
    }

    /* Ensure it's a PE image */
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        PrintErrorReason(ErrorInvalidPE, "Invalid signature 0x%04X '%c%c'",
                         DosHeader->e_magic,
                         PRINT_VAR_CHAR(DosHeader->e_magic, 0), PRINT_VAR_CHAR(DosHeader->e_magic, 1));
        goto Failure;
    }

    /* Get the offset to the NT header */
    NtHeaderOffset = DosHeader->e_lfanew;

    {C_ASSERT(sizeof(DOS_IMAGE_HEADER) < 0x1000); }

    /*
     * IMPORTANT NOTE!! We only support **VALID** PE files, and NOT
     * broken ones where e.g. the PE header is "merged" within the
     * DOS header, or where the list of objects/sections and directives
     * are not present after the PE header.
     */

     /* It should be aligned on a 8-byte boundary */
    if (ROUND_UP(NtHeaderOffset, sizeof(ULONG64)) != NtHeaderOffset)
    {
        PrintErrorReason(ErrorMalformedPE, "PE header offset not 8-byte aligned");
        goto Failure;
    }

    /* NOT BROKEN: The NT header must be **after** the DOS header */
    if (NtHeaderOffset < sizeof(DOS_IMAGE_HEADER))
    {
        PrintErrorReason(ErrorMalformedPE, "PE header offset in DOS header");
        goto Failure;
    }

    /* Make sure the old NT PE header fits into the size */
    TotalHeadersSize += NtHeaderOffset + sizeof(IMAGE_HEADER);
    if (TotalHeadersSize >= nFileSize)
    {
        PrintErrorReason(ErrorMalformedPE, "NT headers beyond image size");
        goto Failure;
    }

    /* Now get a pointer to the old NT PE header */
    // *pNtHeader = (PIMAGE_HEADER)RVA(pData, NtHeaderOffset);

    /* Allocate memory for the old NT PE header and load it (it will be
     * reallocated later to accomodate for the extra object/sections and
     * directive arrays). */
    NtHeader = malloc(sizeof(IMAGE_HEADER));
    if (!NtHeader)
    {
        PrintError("Failed to allocate %lu bytes\n", sizeof(IMAGE_HEADER));
        goto Failure;
    }
    if (nFileSize < NtHeaderOffset + sizeof(IMAGE_HEADER))
    {
        PrintErrorReason(ErrorInvalidPE, "File smaller than IMAGE_HEADER size");
        goto Failure;
    }
    fseek(pImageFile, NtHeaderOffset, SEEK_SET);
    if (!fread(NtHeader, sizeof(IMAGE_HEADER), 1, pImageFile))
    {
        PrintError("Failed to read %lu bytes from source file\n", sizeof(IMAGE_HEADER));
        goto Failure;
    }

    /* Verify the PE Signature */
    if (NtHeader->SignatureBytes != IMAGE_NT_SIGNATURE)
    {
        PrintErrorReason(ErrorInvalidPE, "Invalid NT image signature 0x%08X '%c%c%c%c'",
                         NtHeader->SignatureBytes,
                         PRINT_VAR_CHAR(NtHeader->SignatureBytes, 0), PRINT_VAR_CHAR(NtHeader->SignatureBytes, 1),
                         PRINT_VAR_CHAR(NtHeader->SignatureBytes, 2), PRINT_VAR_CHAR(NtHeader->SignatureBytes, 3));
        goto Failure;
    }

#if 0
    /* Ensure this is an executable image */
    if ((NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)
    {
        PrintErrorReason(ErrorInvalidPE, "Invalid executable image!");
        goto Failure
    }
#endif

#if 0
    /* Get the COFF header */
    * pFileHeader = &(*pNtHeader)->FileHeader;

    /* Check for the presence of the optional header */
    if ((*pFileHeader)->SizeOfOptionalHeader == 0)
    {
        PrintError("Unsupported PE image (no optional header)!\n");
        return FALSE;
    }

    /* Make sure the optional file header fits into the size */
    TotalHeadersSize += (*pFileHeader)->SizeOfOptionalHeader;
    if (TotalHeadersSize >= nFileSize)
    {
        PrintError("NT optional header beyond image size!\n");
        return FALSE;
    }
#endif

    // /* Retrieve the optional header and be sure that its size corresponds to its signature */
    // OptHeader.pHdr = (PVOID)(*pFileHeader + 1);

    /* Return the headers to the caller */
    * pDosHeader = DosHeader;
    *pNtHeader = NtHeader;

    return TRUE;

Failure:
    if (NtHeader)
        free(NtHeader);
    if (DosHeader)
        free(DosHeader);
    return FALSE;
}

#endif


/**
 * @brief   Loads the contents of a section from a file.
 *          The description of the section is passed via SectionHdr.
 *          The function returns a pointer to the allocated section,
 *          or NULL in case of failure. This pointer must be freed
 *          by the caller after usage.
 *          Returns TRUE if success, FALSE otherwise.
 **/
static BOOLEAN
LoadSectionFromFile(
    IN FILE* pImageFile,
    IN PIMAGE_OBJECT_HEADER SectionHdr,
    OUT PVOID* pSection,
    OUT PULONG pSectionSize OPTIONAL)
{
    PVOID Section;     // Allocated section.
    ULONG SectionSize; // The size of the allocated section.

    *pSection = NULL;
    if (pSectionSize)
        *pSectionSize = 0;

    /*
     * NOTE: It sometimes happens for the "old" new PEs that the VirtualSize
     * is zero, while the OnDiskSize is not, and the section contains actual
     * data. Therefore we don't truncate the size but instead take the max.
     */
    SectionSize = max(SectionHdr->VirtualSize, SectionHdr->OnDiskSize);

    /* Allocate the section and load it from the file */
    Section = malloc(SectionSize);
    if (!Section)
    {
        PrintError("Could not load the section!\n");
        return FALSE;
    }

    /* Load it */
    fseek(pImageFile, SectionHdr->SeekOffset, SEEK_SET);
    if (!fread(Section, SectionHdr->OnDiskSize, 1, pImageFile))
    {
        PrintError("Failed to read %lu bytes from source file\n", SectionHdr->OnDiskSize);
        free(Section);
        return FALSE;
    }
    /* Size of data is less than the virtual size: zero out the slack space */
    if (SectionHdr->OnDiskSize < SectionSize)
    {
        RtlZeroMemory(RVA(Section, SectionHdr->OnDiskSize),
                      SectionSize - SectionHdr->OnDiskSize);
    }

    *pSection = Section;
    if (pSectionSize)
        *pSectionSize = SectionSize;
    return TRUE;
}

/**
 * @brief   Retrieves the data of a directory entry, allocating
 *          and loading its corresponding section.
 *          The function returns a pointer to the allocated section,
 *          or NULL in case of failure. This pointer must be freed
 *          by the caller after usage.
 *          Pointers to the directory data, its size, to the section
 *          header in the section table, and the section size, are
 *          returned as well.
 *
 * NOTE: This function is similar to a combined action of
 * RtlImageDirectoryEntryToData() and RtlImageRvaToSection().
 **/
static PVOID
LoadDirectoryEntryAndSection(
    IN FILE* pImageFile,
    IN PIMAGE_HEADER NtHeader,
    IN USHORT Directory,
    OUT PVOID* DirectoryData,
    OUT PULONG Size OPTIONAL,
    OUT PIMAGE_OBJECT_HEADER* pSectionHdr OPTIONAL,
    OUT PULONG pSectionSize OPTIONAL)
{
    PIMAGE_SPECIAL_DIRECTORY DirectoryEntry;
    PIMAGE_OBJECT_HEADER ObjTable = NULL;
    PIMAGE_OBJECT_HEADER SectionHdr;
    PVOID Section;         // Allocated section.
    ULONG SectionSize = 0; // The size of the allocated section.
    ULONG i;

    *DirectoryData = NULL;
    if (Size)
        *Size = 0;

    if (pSectionHdr)
        *pSectionHdr = NULL;
    if (pSectionSize)
        *pSectionSize = 0;

    if (Directory >= NtHeader->NumberOfSpecialRVAs)
        return NULL;

    DirectoryEntry = &NtHeader->DataDirectory[Directory];
    if (DirectoryEntry->RVA == 0)
        return NULL;
    if (DirectoryEntry->Size == 0)
        return NULL;
    
    /* Get a pointer to the object table; the ObjectTableRVA has been already
     * adjusted so that it systematically points just after the structure. */
    if (NtHeader->ObjectTableRVA)
    {
        ASSERT(NtHeader->NumberOfObjects);
        ObjTable = RVA(NtHeader, NtHeader->ObjectTableRVA);
    }
    else
    {
        /* No section available */
        return NULL;
    }

    /* Find its corresponding section */
    SectionHdr = NULL;
    for (i = 0; i < NtHeader->NumberOfObjects; ++i)
    {
        if ((ObjTable[i].RVA <= DirectoryEntry->RVA) &&
            (DirectoryEntry->RVA < ObjTable[i].RVA + ObjTable[i].VirtualSize))
        {
            /* Found it */
            SectionHdr = &ObjTable[i];
            break;
        }
    }

    /* If none found, bail out */
    if (!SectionHdr)
        return NULL;

    if (pSectionHdr)
        *pSectionHdr = SectionHdr;

    /*
     * NOTE: It sometimes happens for the "old" new PEs that the VirtualSize
     * is zero, while the OnDiskSize is not, and the section contains actual
     * data. Therefore we don't truncate the size but instead take the max.
     */
    SectionSize = max(SectionHdr->VirtualSize, SectionHdr->OnDiskSize);

    /* Sanity check: Check that the directory data is
     * fully contained in the section, otherwise bail out. */
    if ( !((SectionHdr->RVA <= DirectoryEntry->RVA) &&
           (DirectoryEntry->RVA + DirectoryEntry->Size < SectionHdr->RVA + SectionSize)) )
    {
        /* Nope */
        return NULL;
    }

    /* Finally load the section */
    if (!LoadSectionFromFile(pImageFile,
                             SectionHdr,
                             &Section,
                             &SectionSize))
    {
        /* Fail - No need to display errors since
         * LoadSectionFromFile() does that already. */
        return NULL;
    }

    /* The directory data points inside the section */
    ASSERT(SectionHdr->RVA <= DirectoryEntry->RVA);
    *DirectoryData = RVA(Section, DirectoryEntry->RVA - SectionHdr->RVA);
    if (Size)
        *Size = DirectoryEntry->Size;

    /* Return a pointer to the allocated section */
    if (pSectionSize)
        *pSectionSize = SectionSize;
    return Section;
}

/**
 * @brief   Flushes the contents of a section to a file.
 *          The description of the section is passed via SectionHdr;
 *          the data of the section is passed in the Section buffer.
 *          Returns TRUE if success, FALSE otherwise.
 * 
 * IMPORTANT NOTE: The section data written to the file is truncated
 * to the value stored in SectionHdr->OnDiskSize.
 **/
static BOOLEAN
FlushSectionToFile(
    IN FILE* pImageFile,
    IN PIMAGE_OBJECT_HEADER SectionHdr,
    IN PVOID Section)
{
    fseek(pImageFile, SectionHdr->SeekOffset, SEEK_SET);
    if (!fwrite(Section, SectionHdr->OnDiskSize, 1, pImageFile))
    {
        PrintError("Failed to write %lu bytes to destination file\n", SectionHdr->OnDiskSize);
        return FALSE;
    }
    fflush(pImageFile);
    return TRUE;
}


/**
 * @brief   Given the sanitzed DOS and old-style PE headers, the PE headers
 *          are converted to the "old" new style and (if pDestFile != NULL)
 *          used to convert the image to the new PE format.
 *          Returns TRUE if success, FALSE if failure.
 **/
static BOOLEAN
ProcessPEImage(
    IN FILE* pImageFile,
    IN size_t nFileSize,
    IN FILE* pDestFile OPTIONAL,
    IN PDOS_IMAGE_HEADER DosHeader,
    IN PIMAGE_HEADER NtHeader,
    IN ULONG NtHeaderSize)
{
    PIMAGE_OBJECT_HEADER ObjTable = NULL;
    PIMAGE_NT_HEADERS32 NtHeaders = NULL;
    PIMAGE_FILE_HEADER FileHeader;
    PIMAGE_OPTIONAL_HEADER32 OptHeader;
    USHORT SizeOfOptionalHeader;
    size_t TotalHeadersSize;
    ULONG FirstSectionVA;

    union
    {
        PIMAGE_EXPORT_DIRECTORY Export;
        PIMAGE_IMPORT_DESCRIPTOR Import;
        PIMAGE_RESOURCE_DATA_ENTRY Resource;
        PCOFF_DEBUG_DIRECTORY Debug;
    } Directory;
    ULONG DirectorySize;
    PIMAGE_OBJECT_HEADER SectionHdr = NULL; // Section header in the sections list.
    PVOID Section;         // Allocated section.
    ULONG SectionSize = 0; // The size of the allocated section.

    C_ASSERT(sizeof(IMAGE_OPTIONAL_HEADER32) == 0xE0);
    C_ASSERT(FIELD_OFFSET(IMAGE_OPTIONAL_HEADER32, DataDirectory) == 0x60);

    /* Get a pointer to the object table; the ObjectTableRVA has been already
     * adjusted so that it systematically points just after the structure. */
    if (NtHeader->ObjectTableRVA)
    {
        ASSERT(NtHeader->NumberOfObjects);
        ObjTable = RVA(NtHeader, NtHeader->ObjectTableRVA);
    }
    else
    {
        NtHeader->NumberOfObjects = 0;
    }

    /*
     * Determine the actual total size of the headers and allocate them.
     */
    /* Here we use the "old" new optional PE header size, with only 9 DataDirectories */
    SizeOfOptionalHeader = FIELD_OFFSET(IMAGE_OPTIONAL_HEADER32, DataDirectory)
                            + 9 * sizeof(IMAGE_DATA_DIRECTORY); // RTL_FIELD_SIZE(IMAGE_OPTIONAL_HEADER32, DataDirectory);

    TotalHeadersSize = FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader) + SizeOfOptionalHeader;
    /* Take the length of the object/section table into account */
    TotalHeadersSize += NtHeader->NumberOfObjects * sizeof(IMAGE_SECTION_HEADER);

    NtHeaders = calloc(1, TotalHeadersSize);
    if (!NtHeaders)
    {
        PrintError("Could not allocate the new PE headers!\n");
        return FALSE;
    }

    FileHeader = &NtHeaders->FileHeader;
    OptHeader  = &NtHeaders->OptionalHeader;

    //
    // TODO!!
    //
    // NtHeader->DirectiveTableRVA;
    // NtHeader->NumberOfDirectives;
    // NtHeader->OSType; --> Seems to be always 4.

    NtHeaders->Signature = IMAGE_NT_SIGNATURE;

    FileHeader->Machine = IMAGE_FILE_MACHINE_UNKNOWN;
    //
    // INVESTIGATE: I am going to assume that CPUType == 1 is for Intel i860,
    // since it is with this CPU that Microsoft historically developed NT.
    // CPUType == 2 is for Intel i386, as shown by the i386 NT PDK PE images.
    // Finally I assume that CPUType == 3 is for MIPS R4000 little endian,
    // as this is the other main platform to support NT.
    // Any other value is presently unknown.
    //
    if (NtHeader->CPUType == 1)
        FileHeader->Machine = IMAGE_FILE_MACHINE_I860;
    else if (NtHeader->CPUType == 2)
        FileHeader->Machine = IMAGE_FILE_MACHINE_I386;
    else if (NtHeader->CPUType == 3)
        FileHeader->Machine = IMAGE_FILE_MACHINE_R4000;

    ASSERT(NtHeader->NumberOfObjects <= MAXUSHORT);
    FileHeader->NumberOfSections = (USHORT)NtHeader->NumberOfObjects;
    FileHeader->TimeDateStamp    = NtHeader->TimeStamp;
    /*
     * The following fields will be determined below, when converting the .debug section.
     * FileHeader->PointerToSymbolTable;
     * FileHeader->NumberOfSymbols;
     */
    FileHeader->SizeOfOptionalHeader = SizeOfOptionalHeader;

    //
    // INVESTIGATE: Are these flags encoded in NtHeader->ModuleFlags ??
    // --> DLLs have 0xA0008300, while EXEs have 0xA0000200 (mostly commandline) or 0xA0000300 (GUI or the subsystems...)
    //
    /* We are definitively an executable image */
    FileHeader->Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
    /* Suppose that Endian != 0 means big endian */
    if (NtHeader->Endian)
        FileHeader->Characteristics |= IMAGE_FILE_BYTES_REVERSED_HI; /* Big endian */
    else
        FileHeader->Characteristics |= IMAGE_FILE_BYTES_REVERSED_LO; /* Little endian */
    //// HACK!!
    if (FileHeader->Machine == IMAGE_FILE_MACHINE_I386)
        FileHeader->Characteristics |= IMAGE_FILE_32BIT_MACHINE;
    //// END HACK!!
    if (NtHeader->ModuleFlags & 0x8000)
        FileHeader->Characteristics |= IMAGE_FILE_DLL;

    /** The old NT COFF/LINKer actually sets both these flags for little endian images:
     ** FileHeader->Characteristics |= IMAGE_FILE_BYTES_REVERSED_LO | IMAGE_FILE_BYTES_REVERSED_HI;
     **/

    OptHeader->Magic              = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    OptHeader->MajorLinkerVersion = LOBYTE(NtHeader->LinkerMajor);
    OptHeader->MinorLinkerVersion = LOBYTE(NtHeader->LinkerMinor);
    /*
     * The following fields will be determined below.
     * OptHeader->SizeOfCode;
     * OptHeader->SizeOfInitializedData;
     * OptHeader->SizeOfUninitializedData;
     */
    OptHeader->AddressOfEntryPoint = NtHeader->EntryPointRVA;
    /*
     * The following fields will be determined below.
     * OptHeader->BaseOfCode;
     * OptHeader->BaseOfData;
     */
    OptHeader->ImageBase                   = NtHeader->ImageBase;
    OptHeader->SectionAlignment            = NtHeader->PageSize;
    OptHeader->FileAlignment               = NtHeader->FileAlign;
    OptHeader->MajorOperatingSystemVersion = NtHeader->OSMajor;
    OptHeader->MinorOperatingSystemVersion = NtHeader->OSMinor;
    OptHeader->MajorImageVersion           = NtHeader->UserMajor;
    OptHeader->MinorImageVersion           = NtHeader->UserMinor;
    OptHeader->MajorSubsystemVersion       = 0; // FIXME!
    OptHeader->MinorSubsystemVersion       = 0; // FIXME!
    OptHeader->Win32VersionValue           = 0;
    OptHeader->SizeOfImage                 = NtHeader->ImageSize; // FIXME!

    /*
     * The new total size of headers reported is equal to the combined size of:
     * the original DOS header size (+ its DOS stub), PE header, and section headers
     * rounded up to a multiple of FileAlignment.
     *
     * I will suppose that the size of the DOS header + its DOS stub is equal
     * to all the space from the beginning of the image up to the offset where
     * the old PE header starts, specified by DosHeader->e_lfanew.
     */
    OptHeader->SizeOfHeaders = ROUND_UP(DosHeader->e_lfanew + TotalHeadersSize, NtHeader->FileAlign);

    // TODO: If original CheckSum == 0 then keep it, otherwise
    // recalculate it once we have completely done the conversion.
    OptHeader->CheckSum = NtHeader->FileCheckSum;

    /* Map the old NT SubSystem field to newer values */
    switch (NtHeader->SubSystem)
    {
    case OLD_IMAGE_SUBSYSTEM_UNKNOWN: OptHeader->Subsystem = IMAGE_SUBSYSTEM_UNKNOWN;   break;
    case OLD_IMAGE_SUBSYSTEM_OS2:     OptHeader->Subsystem = IMAGE_SUBSYSTEM_OS2_CUI;   break;

    case OLD_IMAGE_SUBSYSTEM_WINDOWS:
    {
        /* Proceed as what CONSOLE.dll:ConsoleApp() (called from ConDllInitialization())
         * and NTDLL.dll:RtlImageType() do: check for a specific flag in NtHeader->ModuleFlags. */
        if ((NtHeader->ModuleFlags & 0x0700) == 0x0200)
            OptHeader->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI; // Console subsystem.
        else
            OptHeader->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI; // GUI subsystem.
        break;
    }

    case OLD_IMAGE_SUBSYSTEM_NATIVE:  OptHeader->Subsystem = IMAGE_SUBSYSTEM_NATIVE;    break;
    case OLD_IMAGE_SUBSYSTEM_POSIX:   OptHeader->Subsystem = IMAGE_SUBSYSTEM_POSIX_CUI; break;
    default: PrintWarning("WARNING: Unknown SubSystem value %d\n", NtHeader->SubSystem);
                                      OptHeader->Subsystem = NtHeader->SubSystem;
    }

    OptHeader->DllCharacteristics  = 0; // FIXME?
    OptHeader->SizeOfStackReserve  = NtHeader->StackReserve;
    OptHeader->SizeOfStackCommit   = NtHeader->StackCommit;
    OptHeader->SizeOfHeapReserve   = NtHeader->HeapReserve;
    OptHeader->SizeOfHeapCommit    = NtHeader->HeapCommit;
    OptHeader->LoaderFlags         = 0;
    OptHeader->NumberOfRvaAndSizes = NtHeader->NumberOfSpecialRVAs;

    /* By chance, the older IMAGE_SPECIAL_DIRECTORY structure is identical
     * to the newer IMAGE_DATA_DIRECTORY one, including the size and the
     * order of its members, so we can memcpy it. */
    ASSERT(NtHeader->NumberOfSpecialRVAs <= 9);
    RtlCopyMemory(OptHeader->DataDirectory,
                  NtHeader->DataDirectory,
                  NtHeader->NumberOfSpecialRVAs * sizeof(IMAGE_SPECIAL_DIRECTORY));


    /*
     * Fetch the export table now, as we may need it later,
     * and perform old-PE fixups of the exports directory.
     */
    Section = LoadDirectoryEntryAndSection(pImageFile,
                                           NtHeader,
                                           IMAGE_DIRECTORY_ENTRY_EXPORT,
                                           &Directory.Export,
                                           NULL,
                                           &SectionHdr,
                                           &SectionSize);
#if 0
    if (!SectionHdr)
        PrintWarning("WARNING: Could not load the export directory, ignoring...\n");
    else if (!Section)
        PrintWarning("WARNING: Could not load the export section, ignoring...\n");
#endif
    if (Section && Directory.Export)
    {
        size_t NamesTableSize = Directory.Export->NumberOfNames * sizeof(ULONG);

        ASSERT(SectionHdr);

        /*
         * In later-PE style, the reported size of the export directory counts
         * the size of all the primary data (sizeof(IMAGE_EXPORT_DIRECTORY))
         * **PLUS** the size of all the data from the tables, and not just
         * sizeof(IMAGE_EXPORT_DIRECTORY) as in the old-PE format.
         * The "new"-PE style from October 1991 builds does not do that yet,
         * and therefore some modern tools (e.g. IDA) will complain about the
         * number of reported exports v.s. some "limit" calculated via the
         * reported export directory size.
         */
        //
        // TODO: FIXME!
        //
        // NtHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        // OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        //

        C_ASSERT(sizeof(IMAGE_EXPORT_DIRECTORY) == 0x28);

        /* In old-PE style, these RVAs are from the beginning of the
         * export section. Convert them to RVAs from the base of the image. */
        Directory.Export->Name += SectionHdr->RVA;
        Directory.Export->AddressOfFunctions += SectionHdr->RVA;
        Directory.Export->AddressOfNames += SectionHdr->RVA;
        Directory.Export->AddressOfNameOrdinals += SectionHdr->RVA;

        /* Sanity check: Check that the export function table is
         * fully contained in the section, otherwise bail out. */
        if ( !((SectionHdr->RVA <= Directory.Export->AddressOfNames) &&
               (Directory.Export->AddressOfNames + NamesTableSize < SectionHdr->RVA + SectionSize)) )
        {
            /* Nope */
            PrintWarning("WARNING: Could not load the export table, ignoring...\n");
        }
        else
        {
            PULONG NamesTable;
            ULONG i;

            /* The export table points inside the export section */
            ASSERT(SectionHdr->RVA <= Directory.Export->AddressOfNames);
            NamesTable = RVA(Section, Directory.Export->AddressOfNames - SectionHdr->RVA);

            /* In old-PE style, these RVAs are from the beginning of the
             * export section. Convert them to RVAs from the base of the image. */
            for (i = 0; i < Directory.Export->NumberOfNames; ++i)
            {
                NamesTable[i] += SectionHdr->RVA;
            }
        }
    }


    /*
     * Convert the object/section table and initialize the remaining fields.
     */
    OptHeader->BaseOfCode = ULONG_MAX; // Will be normalized later.
    OptHeader->SizeOfCode = 0;
    OptHeader->BaseOfData = ULONG_MAX; // Will be normalized later.
    OptHeader->SizeOfInitializedData   = 0;
    OptHeader->SizeOfUninitializedData = 0;

    if (ObjTable)
    {
        /* This table comes from https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#special-sections */
        static const struct
        {
            PCSTR SectionName;
            ULONG Characteristics;
        } SectionFlags[] =
        {
            /* Sorted by usual order of appearance in PE images */
            { ".text"   , IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ },
            { ".rdata"  , IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ },
         // { ".srdata" , IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ /* | IMAGE _SCN_GPREL */ },
            { ".data"   , IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE },
         // { ".sdata"  , IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE /* | IMAGE _SCN_GPREL */ },
         // { ".sbss"   , IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE /* | IMAGE _SCN_GPREL */ },
            { ".bss"    , IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE },
            { ".edata"  , IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ },
            { ".idata"  , IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE },
            { ".xdata"  , IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ },
            { ".pdata"  , IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ },
            { ".rsrc"   , IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ },
            { ".reloc"  , IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE },
            { ".debug"  , IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE }
        };
#define SECTION_FLAGS_TEXT   0
#define SECTION_FLAGS_RDATA  1
// #define SECTION_FLAGS_SRDATA 2
#define SECTION_FLAGS_DATA   2
// #define SECTION_FLAGS_SDATA  3
// #define SECTION_FLAGS_SBSS   3
#define SECTION_FLAGS_BSS    3
#define SECTION_FLAGS_EDATA  4
#define SECTION_FLAGS_IDATA  5
#define SECTION_FLAGS_XDATA  6
#define SECTION_FLAGS_PDATA  7
#define SECTION_FLAGS_RSRC   8
#define SECTION_FLAGS_RELOC  9
#define SECTION_FLAGS_DEBUG  10

        PIMAGE_SECTION_HEADER SectionTable;
        PCSTR SectionName;
        ULONG Characteristics;
        ULONG i, j;

        PULONG ExportTable = NULL;

        if (Section && Directory.Export)
        {
            size_t ExportTableSize = Directory.Export->NumberOfFunctions * sizeof(ULONG);

            ASSERT(SectionHdr);

            /* Sanity check: Check that the export function table is
             * fully contained in the section, otherwise bail out. */
            if ( !((SectionHdr->RVA <= Directory.Export->AddressOfFunctions) &&
                   (Directory.Export->AddressOfFunctions + ExportTableSize < SectionHdr->RVA + SectionSize)) )
            {
                /* Nope */
                PrintWarning("WARNING: Could not load the export table, ignoring...\n");
            }
            else
            {
                /* The export table points inside the export section */
                ASSERT(SectionHdr->RVA <= Directory.Export->AddressOfFunctions);
                ExportTable = RVA(Section, Directory.Export->AddressOfFunctions - SectionHdr->RVA);
            }
        }

        printf("Reconstructed Sections:\n"
               "=======================\n");

        SectionTable = RVA(FileHeader + 1, FileHeader->SizeOfOptionalHeader);
        for (i = 0; i < NtHeader->NumberOfObjects; ++i)
        {
            /*
             * Deduce the best section name, based on:
             * - the presence of data, within the current section, pointed by the DataDirectory entries;
             * - the section attributes;
             * - ... ?
             */
            SectionName     = NULL;
            Characteristics = 0;

            // INVESTIGATE: Can we deduce the characteristics
            // from ObjTable[i].ObjectFlags as well?

            /* Is this section a possible .bss section? */
            if (ObjTable[i].VirtualSize == 0 || ObjTable[i].OnDiskSize == 0 /* || ObjTable[i].SeekOffset == 0 */)
            {
                SectionName     = SectionFlags[SECTION_FLAGS_BSS].SectionName;
                Characteristics = SectionFlags[SECTION_FLAGS_BSS].Characteristics;
            }
            /* Or a .text section, if the entry point is in it */
            else if ((ObjTable[i].RVA <= NtHeader->EntryPointRVA) &&
                     (NtHeader->EntryPointRVA < ObjTable[i].RVA + ObjTable[i].VirtualSize))
            {
                SectionName     = SectionFlags[SECTION_FLAGS_TEXT].SectionName;
                Characteristics = SectionFlags[SECTION_FLAGS_TEXT].Characteristics;
            }
            else
            {
                /* Find whether a directory entry is stored within the current section */
                for (j = 0; j < NtHeader->NumberOfSpecialRVAs; ++j)
                {
                    /* Ignore empty directory entries */
                    if ((NtHeader->DataDirectory[j].RVA == 0) ||
                        (NtHeader->DataDirectory[j].Size == 0))
                    {
                        continue;
                    }

                    if ((ObjTable[i].RVA <= NtHeader->DataDirectory[j].RVA) &&
                        (NtHeader->DataDirectory[j].RVA < ObjTable[i].RVA + ObjTable[i].VirtualSize))
                    {
                        /* Found a candidate */
                        break;
                    }
                }

                if (j < NtHeader->NumberOfSpecialRVAs)
                {
                    if (j == IMAGE_DIRECTORY_ENTRY_EXPORT)
                    {
                        // SectionName     = ".EXPORTS";
                        SectionName     = SectionFlags[SECTION_FLAGS_EDATA].SectionName;
                        Characteristics = SectionFlags[SECTION_FLAGS_EDATA].Characteristics;
                    }
                    else if (j == IMAGE_DIRECTORY_ENTRY_IMPORT)
                    {
                        SectionName     = SectionFlags[SECTION_FLAGS_IDATA].SectionName;
                        Characteristics = SectionFlags[SECTION_FLAGS_IDATA].Characteristics;
                    }
                    else if (j == IMAGE_DIRECTORY_ENTRY_RESOURCE)
                    {
                        SectionName     = SectionFlags[SECTION_FLAGS_RSRC].SectionName;
                        Characteristics = SectionFlags[SECTION_FLAGS_RSRC].Characteristics;
                    }
                    else if (j == IMAGE_DIRECTORY_ENTRY_EXCEPTION)
                    {
                        SectionName     = SectionFlags[SECTION_FLAGS_PDATA].SectionName;
                        Characteristics = SectionFlags[SECTION_FLAGS_PDATA].Characteristics;
                    }
                    else if (j == IMAGE_DIRECTORY_ENTRY_SECURITY)
                    {
                        /* Usually in .rdata */
                        SectionName     = SectionFlags[SECTION_FLAGS_RDATA].SectionName;
                        Characteristics = SectionFlags[SECTION_FLAGS_RDATA].Characteristics;
                    }
                    else if (j == IMAGE_DIRECTORY_ENTRY_BASERELOC)
                    {
                        SectionName     = SectionFlags[SECTION_FLAGS_RELOC].SectionName;
                        Characteristics = SectionFlags[SECTION_FLAGS_RELOC].Characteristics;
                    }
                    /* WARNING: The debug directory itself may NOT be in the .debug section!!!! */
                    else if (j == IMAGE_DIRECTORY_ENTRY_DEBUG)
                    {
                        SectionName     = SectionFlags[SECTION_FLAGS_DEBUG].SectionName;
                        Characteristics = SectionFlags[SECTION_FLAGS_DEBUG].Characteristics;
                    }
                    // else if (j == IMAGE_DIRECTORY_ENTRY_ARCHITECTURE) // same as IMAGE_DIRECTORY_ENTRY_COPYRIGHT
                    //     SectionName = NULL;
                    // else if (j == IMAGE_DIRECTORY_ENTRY_GLOBALPTR)
                    //     SectionName = NULL;
                    // else if (j == IMAGE_DIRECTORY_ENTRY_TLS)
                    //     SectionName = ".tls";
                    else
                    {
                        /* Fall back to initialized data characteristics for unknown directory */
                        Characteristics = SectionFlags[SECTION_FLAGS_DATA].Characteristics;
                    }
                }
            }

            if (Characteristics == 0)
            {
                /* Nothing so far */

                /* Enumerate all the exports and check whether any of these are in the section.
                 * If this is so, we have a code section. (**NOTE**: We don't consider data exports!) */
                if (Directory.Export && ExportTable)
                {
                    ULONG Ordinal;
                    for (Ordinal = 0; Ordinal < Directory.Export->NumberOfFunctions; ++Ordinal)
                    {
                        if ((ObjTable[i].RVA <= ExportTable[Ordinal]) &&
                            (ExportTable[Ordinal] < ObjTable[i].RVA + ObjTable[i].VirtualSize))
                        {
                            SectionName     = SectionFlags[SECTION_FLAGS_TEXT].SectionName;
                            Characteristics = SectionFlags[SECTION_FLAGS_TEXT].Characteristics;
                            break;
                        }
                    }
                }
            }
            if (Characteristics == 0)
            {
                /* Still nothing, fall back to data characteristics */
                Characteristics = SectionFlags[SECTION_FLAGS_DATA].Characteristics;
            }


            if (SectionName)
            {
                strncpy((char*)SectionTable[i].Name, SectionName, RTL_NUMBER_OF(SectionTable[i].Name));
            }
            else
            {
                /* If we still haven't determined the section name, give it one based on its index */
                char tmpSectName[RTL_NUMBER_OF(SectionTable[i].Name) + 1];
                snprintf(tmpSectName, RTL_NUMBER_OF(tmpSectName), ".sect%03u", i);
                strncpy((char*)SectionTable[i].Name, tmpSectName, RTL_NUMBER_OF(SectionTable[i].Name));
            }


            if (Characteristics & IMAGE_SCN_CNT_CODE)
            {
                OptHeader->BaseOfCode = min(OptHeader->BaseOfCode, ObjTable[i].RVA);
                /* Sum of all .text-type sections */
                OptHeader->SizeOfCode += ObjTable[i].OnDiskSize;
            }
            else if (Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
            {
                OptHeader->BaseOfData = min(OptHeader->BaseOfData, ObjTable[i].RVA);
                /* Sum of all sections other than .text and .bss */
                OptHeader->SizeOfInitializedData += ObjTable[i].OnDiskSize;
            }
            else if (Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
            {
                OptHeader->BaseOfData = min(OptHeader->BaseOfData, ObjTable[i].RVA);
                /* Sum of all .bss-type sections */
                OptHeader->SizeOfUninitializedData += max(ObjTable[i].VirtualSize, ObjTable[i].OnDiskSize);
            }


            SectionTable[i].Misc.VirtualSize     = ObjTable[i].VirtualSize;
            SectionTable[i].VirtualAddress       = ObjTable[i].RVA;
            SectionTable[i].SizeOfRawData        = ObjTable[i].OnDiskSize;
            SectionTable[i].PointerToRawData     = ObjTable[i].SeekOffset;
            SectionTable[i].PointerToRelocations = 0; // FIXME?
            SectionTable[i].PointerToLinenumbers = 0;
            SectionTable[i].NumberOfRelocations  = 0; // FIXME?
            SectionTable[i].NumberOfLinenumbers  = 0;
            SectionTable[i].Characteristics      = Characteristics;

            printf("[%lu] -->\n"
                   "    Name                 = '%.*s'\n"
                   "    Misc.VirtualSize     = 0x%08X\n"
                   "    VirtualAddress       = 0x%08X\n"
                   "    SizeOfRawData        = 0x%08X\n"
                   "    PointerToRawData     = 0x%08X\n"
                   "    PointerToRelocations = 0x%08X\n"
                   "    PointerToLinenumbers = 0x%08X\n"
                   "    NumberOfRelocations  = 0x%04X\n"
                   "    NumberOfLinenumbers  = 0x%04X\n"
                   "    Characteristics      = 0x%08X\n",
                   i,
                   (ULONG)RTL_NUMBER_OF(SectionTable[i].Name), SectionTable[i].Name,
                   SectionTable[i].Misc.VirtualSize,
                   SectionTable[i].VirtualAddress,
                   SectionTable[i].SizeOfRawData,
                   SectionTable[i].PointerToRawData,
                   SectionTable[i].PointerToRelocations,
                   SectionTable[i].PointerToLinenumbers,
                   SectionTable[i].NumberOfRelocations,
                   SectionTable[i].NumberOfLinenumbers,
                   SectionTable[i].Characteristics);
        }
    }
    /* Normalize the bases if they couldn't have been determined above */
    if (OptHeader->BaseOfCode == ULONG_MAX)
    {
        OptHeader->BaseOfCode = 0;
        OptHeader->SizeOfCode = 0;
    }
    if (OptHeader->BaseOfData == ULONG_MAX)
    {
        OptHeader->BaseOfData = 0;
        OptHeader->SizeOfInitializedData = 0;
    }


    /*
     * Now, do the actual NT PE headers fixups in the file
     * only if a destination file has been provided.
     */
    if (!pDestFile)
    {
        /* Free the allocated export section */
        if (Section)
            free(Section);

        goto Quit;
    }


    /* Create a copy of the image file into the destination file */
    if (!CopyFile(pImageFile, nFileSize, pDestFile))
    {
        PrintError("Could not create a copy of the source file!\n");

        /* Free the allocated export section */
        if (Section)
            free(Section);

        free(NtHeaders);
        return FALSE;
    }


    /*
     * Post-processing: fixup the format of the data
     * pointed by the different data directory entries.
     */

    /* Export directory -- The fixup was already done above, so we just need to flush it into the file */
    if (Section)
    {
        ASSERT(SectionHdr);
        if (!FlushSectionToFile(pDestFile, SectionHdr, Section))
            PrintError("Failed to update the %s section!\n", "Export");

        /* Free the allocated export section */
        free(Section);
    }

    /* Import directory */
    Section = LoadDirectoryEntryAndSection(pImageFile,
                                           NtHeader,
                                           IMAGE_DIRECTORY_ENTRY_IMPORT,
                                           &Directory.Import,
                                           &DirectorySize,
                                           &SectionHdr,
                                           &SectionSize);
#if 0
    if (!SectionHdr)
        PrintWarning("WARNING: Could not load the import directory, ignoring...\n");
    else if (!Section)
        PrintWarning("WARNING: Could not load the import section, ignoring...\n");
#endif
    if (Section)
    {
        PIMAGE_IMPORT_DESCRIPTOR Import = Directory.Import;
        PIMAGE_THUNK_DATA32 Thunk;

        ASSERT(SectionHdr && Directory.Import);

        for (; (/* (Import->Name != 0) && */ (Import->FirstThunk != 0) &&
               ((ULONG_PTR)Import - (ULONG_PTR)Directory.Import < DirectorySize));
             ++Import)
        {
            /* In old-PE style, these RVAs are from the beginning of the
             * export section. Convert them to RVAs from the base of the image. */
            if (Import->Name)
                Import->Name += SectionHdr->RVA;

            /* Loop through the thunks as well */
            Thunk = RVA(Section, Import->FirstThunk - SectionHdr->RVA);
            for (; Thunk->u1.AddressOfData; ++Thunk)
            {
                Thunk->u1.AddressOfData += SectionHdr->RVA;
            }
        }
        /* Strangely enough, FirstThunk is OK, certainly because it points into another section */

        if (!FlushSectionToFile(pDestFile, SectionHdr, Section))
            PrintError("Failed to update the %s section!\n", "Import");

        /* Free the allocated section */
        free(Section);
    }

    /* Resource directory */
    
    /* Exception directory */

    /* Security directory */

    /* Relocations directory */

    /* Debug directory */
    Section = LoadDirectoryEntryAndSection(pImageFile,
                                           NtHeader,
                                           IMAGE_DIRECTORY_ENTRY_DEBUG,
                                           &Directory.Debug,
                                           &DirectorySize,
                                           &SectionHdr,
                                           &SectionSize);
#if 0
    if (!SectionHdr)
        PrintWarning("WARNING: Could not load the debug directory, ignoring...\n");
    else if (!Section)
        PrintWarning("WARNING: Could not load the debug section, ignoring...\n");
#endif

    // FIXME: To be determined when converting the .debug section
    // FileHeader->PointerToSymbolTable = 0;
    // FileHeader->NumberOfSymbols = 0;

    if (Section)
    {
        BOOLEAN IsOldDebug = FALSE;

        /*
         * Here, we should recall again that, while in general the Debug directory
         * is in the .debug section (especially true for the old PE images), it is
         * not always true! It can be anywhere in the image (for example, in .rdata).
         */

        ASSERT(SectionHdr && Directory.Debug);

        /*
         * Heuristically determine whether the debug directory 
         * is of the old format (COFF_DEBUG_DIRECTORY) or the
         * new one (IMAGE_DEBUG_DIRECTORY).
         */
        if (DirectorySize % sizeof(COFF_DEBUG_DIRECTORY) != 0)
        {
            /* Definitively not COFF_DEBUG_DIRECTORY; could be IMAGE_DEBUG_DIRECTORY
             * or something unknown to us; in any case we don't touch it. */
        }
        else // if (DirectorySize % sizeof(COFF_DEBUG_DIRECTORY) == 0)
        {
            if (DirectorySize % sizeof(IMAGE_DEBUG_DIRECTORY) != 0)
            {
                /* Certainly definitively COFF_DEBUG_DIRECTORY */
                IsOldDebug = TRUE;
            }
            else // if (DirectorySize % sizeof(IMAGE_DEBUG_DIRECTORY) == 0)
            {
                /*
                 * We need to dig deeper.
                 * Indeed both conditions can be satisfied when
                 * DirectorySize = some_integer * 42 (hehe, 42 :D), because:
                 * sizeof(COFF_DEBUG_DIRECTORY) == 0x18 == 24 == 8*3,
                 * sizeof(IMAGE_DEBUG_DIRECTORY) == 0x1C == 28 == 7*4.
                 * The condition is equivalent to finding whether there exists
                 * integers a, b, such that:
                 * DirectorySize == a * 24 == b * 28 .
                 * Simplifying, we see that a * 6 == b * 7, so that a and b
                 * should be coprime, and thus, there exists an integer n such
                 * that a == n * 7 and b == n * 6, and therefore,
                 * DirectorySize == n * 6 * 7.
                 */
            }
        }

        if (IsOldDebug)
        {
            // TODO : Do the conversion!
        }

        free(Section);
    }


    /*
     * Determine whether the new PE header can be
     * placed at the same place as the old one.
     */

    /*
     * Iterate through the sections and determine the RVA of the one
     * that actually starts first after the old PE header in the image.
     */
    FirstSectionVA = ULONG_MAX;
    if (FileHeader->NumberOfSections)
    {
        PIMAGE_SECTION_HEADER SectionTable;
        ULONG i;

        SectionTable = RVA(FileHeader + 1, FileHeader->SizeOfOptionalHeader);
        for (i = 0; i < FileHeader->NumberOfSections; ++i)
        {
            if (SectionTable[i].PointerToRawData >= DosHeader->e_lfanew + NtHeaderSize)
                FirstSectionVA = min(FirstSectionVA, SectionTable[i].PointerToRawData);
        }
    }

    /* Check whether we can fit the new PE headers into
     * the image at the same place as the older headers. */
    if (DosHeader->e_lfanew + TotalHeadersSize < FirstSectionVA)
    {
        /* Trick to position the PE header */
        nFileSize = DosHeader->e_lfanew;
    }
    else
    {
        PrintWarning("WARNING: New PE headers cannot fit in original place; putting them at the end of the file.\n"
                     "The file may not be loadable by some programs!\n");

        // /* Grow the reported size of image in the PE header */
        // OptHeader->SizeOfImage;

        /* Patch the DOS header to fix e_lfanew to point to the new PE header at the end of the file */
        DosHeader->e_lfanew = (LONG)nFileSize;
        fseek(pDestFile, 0, SEEK_SET);
        if (!fwrite(DosHeader, sizeof(*DosHeader), 1, pDestFile))
        {
            PrintError("Failed to write %lu bytes to destination file\n", (ULONG)sizeof(*DosHeader));
            free(NtHeaders);
            return FALSE;
        }
    }

    fseek(pDestFile, (long)nFileSize, SEEK_SET);
    if (!fwrite(NtHeaders, TotalHeadersSize, 1, pDestFile))
    {
        PrintError("Failed to write %lu bytes to destination file\n", (ULONG)TotalHeadersSize);
        free(NtHeaders);
        return FALSE;
    }

    fflush(pDestFile);


Quit:
    free(NtHeaders);
    return TRUE;
}


static void
Banner(void)
{
    printf("PE Converter for NT PDK v1.196 (September 1991) and PDK October 1991\n"
           "Version " VERSION "\n"
           "Copyright " COPYRIGHT_YEARS " Hermès Bélusca-Maïto\n"
           "Under GPL-2.0+ license (https://spdx.org/licenses/GPL-2.0+)\n"
           "\n");
}

static void
Usage(void)
{
    Banner();
    printf("Converts executable images from the old PE format used by\n"
           "Microsoft(R) NT PDK v1.196 (September 1991) and PDK October 1991\n"
           "to a newer PE format that can be recognized by modern tools.\n"
           "\n"
           "Usage: " PROGNAME " [options] source_file [dest_file]\n"
           "\n"
           "Options:\n"
           "    -n, --nologo    Remove the banner.\n"
           "    -v, --verbose   Display file information when processing.\n"
           "    -t, --test      Process the source file without actually generating\n"
           "                    an output file.\n"
           "    -?, --help      Display this help message.\n");
}

int main(int argc, char** argv)
{
    int nErrorCode = 0;
    int i;
    bool bLongOpt = false;
    bool bBanner = true;
    bool bDisplayInfo = false;
    bool bTest = false;
    char* pszSourceFile = NULL;
    char* pszDestFile = NULL;

    FILE* pSourceFile = NULL;
    FILE* pDestFile = NULL;
    size_t nFileSize;
    // PVOID pData;
    PDOS_IMAGE_HEADER pDosHeader = NULL;
    PIMAGE_HEADER pNtHeader = NULL;
    ULONG NtHeaderSize;
    USHORT DosHdrMagic;

    /* Enable correct console locale.
     * NOTE: See https://stackoverflow.com/a/44225070/13530036 */
    setlocale(LC_ALL, "");

    /* Check for options */
    for (i = 1; i < argc; ++i)
    {
        if (*argv[i] && strlen(argv[i]) >= 2)
        {
            /* Short option form */
            if ( (argv[i][0] == '-' || argv[i][0] == '/') &&
                !(argv[i][1] == '-' || argv[i][1] == '/') )
            {
                bLongOpt = false;
            }
            /* Long option form */
            else if (argv[i][0] == '-' && argv[i][1] == '-')
            {
                bLongOpt = true;
            }
            else
            {
                /* We are out of options (they come first before
                 * anything else, and cannot come after). */
                break;
            }
        }
        else
        {
            /* We are out of options (they come first before
             * anything else, and cannot come after). */
            break;
        }

        /* Help */
        if ( (!bLongOpt && (_stricmp(&argv[i][1], "?") == 0)) ||
             ( bLongOpt && (strcmp(&argv[i][2], "help") == 0)) )
        {
            /* Set argc to special value case */
            argc = 1;
            break;
        }
        else
        /* Banner */
        if ( (!bLongOpt && (_stricmp(&argv[i][1], "n") == 0)) ||
             ( bLongOpt && (strcmp(&argv[i][2], "nologo") == 0)) )
        {
            bBanner = false;
        }
        else
        /* Display information */
        if ( (!bLongOpt && (_stricmp(&argv[i][1], "v") == 0)) ||
             ( bLongOpt && (strcmp(&argv[i][2], "verbose") == 0)) )
        {
            bDisplayInfo = true;
        }
        else
        /* Test mode */
        if ( (!bLongOpt && (_stricmp(&argv[i][1], "t") == 0)) ||
             ( bLongOpt && (strcmp(&argv[i][2], "test") == 0)) )
        {
            bTest = true;
        }
        else
        /* Unknown option */
        {
            PrintError("Unknown option: \'%s\'\n"
                       "Type \"" PROGNAME " -?\" for usage.\n",
                       argv[i]);
            return -1;
        }
    }
    /* Check for no arguments or for help */
    if (argc <= 1)
    {
        Usage();
        return -1;
    }

    /* Stop now if we don't have any files */
    if (i >= argc)
        return 0;

    /* Get the source and destination files (if any) */
    if (i < argc)
        pszSourceFile = argv[i++];
    if (i < argc)
        pszDestFile = argv[i++];

    /* We display file information if the flag is set,
     * or if we don't do any conversion. */
    bDisplayInfo = (bDisplayInfo || !pszDestFile);

    /* Display banner if necessary */
    if (bBanner)
        Banner();

    /* Open the source file for binary read access */
    pSourceFile = fopen(pszSourceFile, "rb");
    if (!pSourceFile)
    {
        PrintError("Could not open source file '%s'\n", pszSourceFile);
        return -2;
    }

    /* Retrieve the file size */
    fseek(pSourceFile, 0, SEEK_END);
    nFileSize = ftell(pSourceFile);
    rewind(pSourceFile);

#if 0
    /* Allocate memory for the file */
    pData = malloc(nFileSize);
    if (!pData)
    {
        PrintError("Failed to allocate %lu bytes\n", nFileSize);
        nErrorCode = -3;
        goto Quit;
    }
#endif

#if 0
    /* Read the whole source file */
    if (!fread(pData, nFileSize, 1, pSourceFile))
#else
    /* Read the header signature */
    if ((nFileSize < sizeof(DOS_IMAGE_HEADER)) ||
        !fread(&DosHdrMagic, sizeof(DosHdrMagic), 1, pSourceFile))
#endif
    {
        PrintError("Failed to read %lu bytes from source file\n", (ULONG)/* nFileSize */sizeof(DOS_IMAGE_HEADER));
        nErrorCode = -4;
        goto Quit;
    }

    if (bDisplayInfo)
        printf("Image file: %s\n\n", pszSourceFile);
    fflush(stdout);
    fflush(stderr);

    /* Check whether this is a pure COFF file or a PE image */
    // pDosHeader = (PDOS_IMAGE_HEADER)pData;
    if ((nFileSize >= sizeof(DOS_IMAGE_HEADER)) && (DosHdrMagic == IMAGE_DOS_SIGNATURE))
    {
        /* This is a PE image, parse it */
        if (!ParseOldPEImage(/*pData*/ pSourceFile, nFileSize,
                             &pDosHeader, &pNtHeader, &NtHeaderSize))
        {
            PrintError("ParseOldPEImage() failed.\n");
            nErrorCode = -6;
            goto Quit;
        }
    }
#if 0
    else if (nFileSize >= sizeof(IMAGE_FILE_HEADER) /* == IMAGE_SIZEOF_FILE_HEADER */)
    {
        /* Get the COFF header */
        pNtHeader = NULL;
        pFileHeader = (PIMAGE_FILE_HEADER)pData;
    }
#endif
    else
    {
        PrintError("Unrecognized format!\n");
        nErrorCode = -6;
        goto Quit;
    }

    /* We are good, now display the information if necessary */
    if (bDisplayInfo)
        DumpOldPEImage(pDosHeader, pNtHeader);

    /* If we are not in test mode and no destination file is provided, stop here */
    if (!(bTest || pszDestFile))
        goto Quit;

    /* We have a destination file, or we are in test mode, proceed to the conversion */

    if (!bTest)
    {
        /* Open the destination file for binary write access */
        pDestFile = fopen(pszDestFile, "wb");
        if (!pDestFile)
        {
            PrintError("Could not open destination file '%s'\n", pszDestFile);
            nErrorCode = -7;
            goto Quit;
        }
    }

    /* PE image - Either extract only the section specified by the user, or all of them */
    if (!ProcessPEImage(/*pData*/ pSourceFile, nFileSize, pDestFile,
                        pDosHeader, pNtHeader, NtHeaderSize))
    {
        PrintError("ProcessPEImage() failed.\n");
        nErrorCode = -8;
        // goto Quit;
    }

    if (pDestFile)
        fclose(pDestFile);

Quit:
    if (pNtHeader)
        free(pNtHeader);
    if (pDosHeader)
        free(pDosHeader);

    fclose(pSourceFile);
    // free(pData);

    fflush(stdout);
    fflush(stderr);

    return nErrorCode;
}
