/*
 * PROJECT:     PE Converter for NT PDK v1.196 (September 1991) and PDK October 1991
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Converts old-style PE format to newer format
 *              that can be recognized by modern tools.
 * COPYRIGHT:   Copyright 2021-2022 Hermès Bélusca-Maïto
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
// #include <stdlib.h> // For _countof() -- TODO: Make it compiler-independent.
#include <locale.h> // For setlocale().
// #include <io.h>
//#include <fcntl.h>
#include <ctype.h> // For isprint()
#include <string.h>

/* NT types and PE definitions */
#include "typedefs.h"
#include "pecoff.h"
#include "nt196pe.h"

#include "ntpeconv.h"
#include "pehlp.h"


/* Supplemental types */
typedef char bool;
#define false 0
#define true  1

// #define NULL ((void*)0)

// /* Standard page size for i386 */
// #define PAGE_SIZE 0x1000


// #ifdef _PPC_
#define SWAPD(x) ((((x)&0xff)<<24)|(((x)&0xff00)<<8)|(((x)>>8)&0xff00)|(((x)>>24)&0xff))
#define SWAPW(x) ((((x)&0xff)<<8)|(((x)>>8)&0xff))
#define SWAPQ(x) ((SWAPD((x)&0xffffffff) << 32) | (SWAPD((x)>>32)))
// #else
// #define SWAPD(x) (x)
// #define SWAPW(x) (x)
// #define SWAPQ(x) (x)
// #endif


/* For the PrintErrorReason() macro */
PCSTR Errors[ErrorTypeMax + 1] =
{
    "Not a valid PE image!",
    "Malformed PE image!",
    "Unsupported PE image!",
    "Unknown"
};


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
 * @brief   Dumps the DOS header of a PE image.
 **/
static VOID
DumpDOSHeader(
    IN const IMAGE_DOS_HEADER* DosHeader)
{
    printf("IMAGE_DOS_HEADER\n"
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
}

/**
 * @brief   Dumps the data directory of a COFF or an old-PE image.
 *          By chance, the older IMAGE_SPECIAL_DIRECTORY structure is identical
 *          to the newer IMAGE_DATA_DIRECTORY one, including the size and the
 *          order of its members, so we can use the same function to dump both.
 *          Adjustment of member names is controlled with the 'bOldPE' parameter.
 **/
static VOID
DumpCOFFDataDirectory(
    IN const IMAGE_DATA_DIRECTORY* DataDirectory,
    IN ULONG NumberOfDirectories,
    IN BOOLEAN bOldPE,
    IN int PrintIndent)
{
    C_ASSERT(RTL_NUMBER_OF_FIELD(IMAGE_HEADER, DataDirectory) == IMAGE_NUMBEROF_SPECIAL_DIRECTORY_ENTRIES);
    C_ASSERT(RTL_NUMBER_OF_FIELD(IMAGE_OPTIONAL_HEADER32, DataDirectory) == IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

    static PCSTR IMAGE_SPECIAL_DIRECTORY_NAMES[
        max(IMAGE_NUMBEROF_SPECIAL_DIRECTORY_ENTRIES,
            IMAGE_NUMBEROF_DIRECTORY_ENTRIES)] =
    {
        /* COFF/Old/New-PE Directories */
        "IMAGE_DIRECTORY_ENTRY_EXPORT",
        "IMAGE_DIRECTORY_ENTRY_IMPORT",
        "IMAGE_DIRECTORY_ENTRY_RESOURCE",
        "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
        "IMAGE_DIRECTORY_ENTRY_SECURITY",
        "IMAGE_DIRECTORY_ENTRY_BASERELOC",
        "IMAGE_DIRECTORY_ENTRY_DEBUG",

        /* New-PE Directories only */
        "IMAGE_DIRECTORY_ENTRY_COPYRIGHT", // (x86-specific), otherwise: "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE"
        "IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
        "IMAGE_DIRECTORY_ENTRY_TLS",
        "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
        "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
        "IMAGE_DIRECTORY_ENTRY_IAT",
        "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
        "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",

        /* Not defined */
        "\"n/a\"",
    };

    ULONG MaxNumberOfDirectories;
    ULONG i;

    if (bOldPE)
        MaxNumberOfDirectories = IMAGE_NUMBEROF_SPECIAL_DIRECTORY_ENTRIES;
    else
        MaxNumberOfDirectories = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    /* Verify that the handled number of special data directories is valid */
    if (NumberOfDirectories > MaxNumberOfDirectories)
    {
        PrintWarning("Invalid number of special data directories %lu; expected <= %lu\n",
                     NumberOfDirectories, MaxNumberOfDirectories);
        NumberOfDirectories = MaxNumberOfDirectories;
    }

    for (i = 0; i < NumberOfDirectories; ++i)
    {
        printf("%*sDataDirectory[%s] =\n"
               "%*s    { %s: 0x%08X , Size: 0x%08X }\n",
               PrintIndent, "", // Indentation
               IMAGE_SPECIAL_DIRECTORY_NAMES[i],
               PrintIndent, "", // Indentation
               (bOldPE ? "RVA" : "VirtualAddress"),
               DataDirectory[i].VirtualAddress,
               DataDirectory[i].Size);
    }
    printf("\n");
}

/**
 * @brief   Dumps the COFF headers of a COFF image.
 **/
static VOID
DumpCOFFImage(
    IN const IMAGE_FILE_HEADER* FileHeader)
{
    PIMAGE_OPTIONAL_HEADER32 OptHeader = NULL;
    PIMAGE_SECTION_HEADER ObjTable = NULL; // SectionTable
    ULONG i;

    /* Get a pointer to the optional header; the ObjectTableRVA has been already
     * adjusted so that it systematically points just after the structure. */
    if (FileHeader->SizeOfOptionalHeader)
    {
        OptHeader = (PVOID)(FileHeader + 1);
    }

    /* In the COFF format, it is understood that, as soon as NumberOfSections
     * is non zero, there is an object/section table that is present just
     * after the optional header. */
    if (FileHeader->NumberOfSections)
    {
        // SectionTable
        ObjTable = RVA(FileHeader + 1, FileHeader->SizeOfOptionalHeader);
    }

    printf("IMAGE_FILE_HEADER\n"
           "=================\n"
           "    Machine                 = 0x%04X\n"
           "    NumberOfSections        = 0x%04X\n"
           "    TimeDateStamp           = 0x%08X\n"
           "    PointerToSymbolTable    = 0x%08X\n"
           "    NumberOfSymbols         = 0x%08X\n"
           "    SizeOfOptionalHeader    = 0x%04X\n"
           "    Characteristics         = 0x%04X\n"
           "\n",
           FileHeader->Machine,
           FileHeader->NumberOfSections,
           FileHeader->TimeDateStamp,
           FileHeader->PointerToSymbolTable,
           FileHeader->NumberOfSymbols,
           FileHeader->SizeOfOptionalHeader,
           FileHeader->Characteristics);

    if (OptHeader)
    {
        printf("IMAGE_OPTIONAL_HEADER32\n"
               "=======================\n"
               "    Magic                       = 0x%04X\n"
               "    MajorLinkerVersion          = 0x%02X\n"
               "    MinorLinkerVersion          = 0x%02X\n"
               "    SizeOfCode                  = 0x%08X\n"
               "    SizeOfInitializedData       = 0x%08X\n"
               "    SizeOfUninitializedData     = 0x%08X\n"
               "    AddressOfEntryPoint         = 0x%08X\n"
               "    BaseOfCode                  = 0x%08X\n"
               "    BaseOfData                  = 0x%08X\n"
               "    ImageBase                   = 0x%08X\n"
               "    SectionAlignment            = 0x%08X\n"
               "    FileAlignment               = 0x%08X\n"
               "    MajorOperatingSystemVersion = 0x%04X\n"
               "    MinorOperatingSystemVersion = 0x%04X\n"
               "    MajorImageVersion           = 0x%04X\n"
               "    MinorImageVersion           = 0x%04X\n"
               "    MajorSubsystemVersion       = 0x%04X\n"
               "    MinorSubsystemVersion       = 0x%04X\n"
               "    Win32VersionValue           = 0x%08X\n"
               "    SizeOfImage                 = 0x%08X\n"
               "    SizeOfHeaders               = 0x%08X\n"
               "    CheckSum                    = 0x%08X\n"
               "    Subsystem                   = 0x%04X\n"
               "    DllCharacteristics          = 0x%04X\n"
               "    SizeOfStackReserve          = 0x%08X\n"
               "    SizeOfStackCommit           = 0x%08X\n"
               "    SizeOfHeapReserve           = 0x%08X\n"
               "    SizeOfHeapCommit            = 0x%08X\n"
               "    LoaderFlags                 = 0x%08X\n"
               "    NumberOfRvaAndSizes         = 0x%08X\n"
               "\n",
               OptHeader->Magic,
               OptHeader->MajorLinkerVersion,
               OptHeader->MinorLinkerVersion,
               OptHeader->SizeOfCode,
               OptHeader->SizeOfInitializedData,
               OptHeader->SizeOfUninitializedData,
               OptHeader->AddressOfEntryPoint,
               OptHeader->BaseOfCode,
               OptHeader->BaseOfData,
               OptHeader->ImageBase,
               OptHeader->SectionAlignment,
               OptHeader->FileAlignment,
               OptHeader->MajorOperatingSystemVersion,
               OptHeader->MinorOperatingSystemVersion,
               OptHeader->MajorImageVersion,
               OptHeader->MinorImageVersion,
               OptHeader->MajorSubsystemVersion,
               OptHeader->MinorSubsystemVersion,
               OptHeader->Win32VersionValue,
               OptHeader->SizeOfImage,
               OptHeader->SizeOfHeaders,
               OptHeader->CheckSum,
               OptHeader->Subsystem,
               OptHeader->DllCharacteristics,
               OptHeader->SizeOfStackReserve,
               OptHeader->SizeOfStackCommit,
               OptHeader->SizeOfHeapReserve,
               OptHeader->SizeOfHeapCommit,
               OptHeader->LoaderFlags,
               OptHeader->NumberOfRvaAndSizes);

        DumpCOFFDataDirectory(OptHeader->DataDirectory,
                              OptHeader->NumberOfRvaAndSizes,
                              FALSE,
                              4);
    }

    if (ObjTable)
    {
        printf("Sections:\n"
               "=========\n");
        for (i = 0; i < FileHeader->NumberOfSections; ++i)
        {
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
                   (ULONG)RTL_NUMBER_OF(ObjTable[i].Name), ObjTable[i].Name,
                   ObjTable[i].Misc.VirtualSize,
                   ObjTable[i].VirtualAddress,
                   ObjTable[i].SizeOfRawData,
                   ObjTable[i].PointerToRawData,
                   ObjTable[i].PointerToRelocations,
                   ObjTable[i].PointerToLinenumbers,
                   ObjTable[i].NumberOfRelocations,
                   ObjTable[i].NumberOfLinenumbers,
                   ObjTable[i].Characteristics);
        }
        printf("\n");
    }
}

/**
 * @brief   Dumps the DOS and old-style PE headers of a PE image.
 **/
static VOID
DumpOldPEImage(
    IN const DOS_IMAGE_HEADER* DosHeader,
    IN const IMAGE_HEADER* NtHeader)
{
    PIMAGE_OBJECT_HEADER ObjTable = NULL;
    ULONG i;

    /* Get a pointer to the object table; the ObjectTableRVA has been already
     * adjusted so that it systematically points just after the structure. */
    if (NtHeader->ObjectTableRVA)
    {
        ASSERT(NtHeader->NumberOfObjects);
        ObjTable = RVA(NtHeader, NtHeader->ObjectTableRVA);
    }

    DumpDOSHeader(DosHeader);

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

    DumpCOFFDataDirectory((PIMAGE_DATA_DIRECTORY)NtHeader->DataDirectory,
                          NtHeader->NumberOfSpecialRVAs,
                          TRUE,
                          4);

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
 * @brief   Dumps the DOS and new-style PE headers of a PE image.
 **/
static VOID
DumpNewPEImage(
    IN const IMAGE_DOS_HEADER* DosHeader,
    IN const IMAGE_NT_HEADERS32* NtHeaders)
{
    DumpDOSHeader(DosHeader);

    printf("IMAGE_NT_HEADERS32\n"
           "==================\n"
           "    Signature   = 0x%08X '%c%c%c%c'\n"
           "\n",
           NtHeaders->Signature,
           PRINT_VAR_CHAR(NtHeaders->Signature, 0), PRINT_VAR_CHAR(NtHeaders->Signature, 1),
           PRINT_VAR_CHAR(NtHeaders->Signature, 2), PRINT_VAR_CHAR(NtHeaders->Signature, 3));

    DumpCOFFImage(&NtHeaders->FileHeader);
}


/**
 * @brief   Parses an COFF32 image and retrieves its headers. Validation and
 *          sanitization are performed.
 *          Returns TRUE if success, FALSE if failure (validation failed, or
 *          any other error happened).
 *          Please note that, for ease of re-use in the new-PE parser, this
 *          function always returns a pointer to an allocated IMAGE_NT_HEADERS32
 *          buffer, even if the image is **NOT** a PE, but is only a COFF.
 *          This is done so that any optional header is automatically allocated
 *          contiguously to the file header.
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
ParseCOFF32Image(
    IN FILE* pImageFile,
    IN size_t nFileSize,
    IN ULONG nFileOffset OPTIONAL,
    OUT PIMAGE_NT_HEADERS32* pNtHeaders,
    OUT PULONG pNtHeadersSize)
{
    PIMAGE_NT_HEADERS32 NtHeaders = NULL;
    PIMAGE_FILE_HEADER FileHeader;
    PIMAGE_OPTIONAL_HEADER32 OptHeader = NULL;
    PIMAGE_SECTION_HEADER ObjTable = NULL; // SectionTable
    size_t NtHeadersSize;
    size_t TotalHeadersSize;
    size_t DataDirectorySize = 0;
    size_t ObjectsTableSize = 0;

    /* Make sure the image header fits into the size */
    if (nFileOffset + sizeof(IMAGE_FILE_HEADER) > nFileSize)
    {
        PrintErrorReason(ErrorInvalidPE, "File smaller than IMAGE_FILE_HEADER size");
        // PrintErrorReason(ErrorMalformedPE, "COFF file header beyond image size");
        return FALSE;
    }

    /* Allocate memory for the image file header (+ the extra signature field)
     * and load it. It will be re-allocated later to accomodate for the extra
     * optional header (and its directory array) and the object/sections table. */
    NtHeadersSize = RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS32, FileHeader);
    NtHeaders = malloc(NtHeadersSize);
    if (!NtHeaders)
    {
        PrintError("Failed to allocate %lu bytes\n", (ULONG)NtHeadersSize);
        return FALSE;
    }
    fseek(pImageFile, nFileOffset, SEEK_SET);
    if (!fread(&NtHeaders->FileHeader, sizeof(IMAGE_FILE_HEADER), 1, pImageFile))
    {
        PrintError("Failed to read %lu bytes from source file\n", (ULONG)sizeof(IMAGE_FILE_HEADER));
        goto Failure;
    }

    FileHeader = &NtHeaders->FileHeader;

    /* Ensure this is an executable image */
    if ((NtHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)
    {
        PrintErrorReason(ErrorInvalidPE, "Invalid executable image!");
        goto Failure;
    }

    /* Stamp the signature with 'COFF', to distinguish with new PE files */
    NtHeaders->Signature = 'FFOC';


    /* Symbols are not currently supported */
    if ((FileHeader->NumberOfSymbols != 0) || (FileHeader->PointerToSymbolTable != 0))
    {
        PrintErrorReason(ErrorUnsupportedPE, "Symbols present in PE image, currently not supported (ignored)");
        // goto Failure;
    }


    //
    // TODO: Validate FileHeader->SizeOfOptionalHeader value ??
    //

    /* Check for the presence of the optional header */
    if (FileHeader->SizeOfOptionalHeader == 0)
    {
        PrintWarning("Unsupported PE image (no optional header)!\n");
    }

    /* Make sure the optional file header fits into the size */
    TotalHeadersSize = nFileOffset + sizeof(IMAGE_FILE_HEADER);
    TotalHeadersSize += FileHeader->SizeOfOptionalHeader;
    if (TotalHeadersSize >= nFileSize)
    {
        PrintError("NT optional header beyond image size!\n");
        goto Failure;
    }

    NtHeadersSize += FileHeader->SizeOfOptionalHeader;

    /*
     * Perform any necessary re-allocation to accomodate for the optional header,
     * the Data directory array and objects table.
     */
    // if (NtHeadersSize > (size_t)FIELD_OFFSET(IMAGE_HEADER, DataDirectory))
    if (FileHeader->SizeOfOptionalHeader > 0)
    {
        /* Re-allocate the NT PE header to accomodate for the optional header,
         * the Data directory array and the object table. */
        PVOID ptr = realloc(NtHeaders, NtHeadersSize);
        if (!ptr)
        {
            PrintError("Failed to re-allocate %lu bytes\n", (ULONG)NtHeadersSize);
            goto Failure;
        }
        NtHeaders = ptr;
        FileHeader = &NtHeaders->FileHeader;
        OptHeader  = &NtHeaders->OptionalHeader;

        /* Load the optional header */
        fseek(pImageFile,
           // nFileOffset + sizeof(IMAGE_FILE_HEADER),
              nFileOffset + FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader)
                          - FIELD_OFFSET(IMAGE_NT_HEADERS32, FileHeader),
              SEEK_SET);
        if (!fread(OptHeader, FileHeader->SizeOfOptionalHeader, 1, pImageFile))
        {
            PrintError("Failed to read %lu bytes from source file\n", (ULONG)FileHeader->SizeOfOptionalHeader);
            goto Failure;
        }


        /* Retrieve the optional header and be sure that its size corresponds to its signature */
        // OptHeader->pHdr = (PVOID)(*pFileHeader + 1);
        if (!(FileHeader->SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32) &&
              OptHeader/*->p32*/->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) &&
            !(/* FileHeader->SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64) && */
              OptHeader/*->p64*/->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC))
        {
            /* Fail */
            PrintError("Invalid or unrecognized NT optional header!\n");
            goto Failure;
        }


        /*
         * The total size of headers reported is equal to the combined size of:
         * the offset from the beginning of the file (in the case of PE images,
         * this corresponds to the original DOS header size + its DOS stub),
         * the NT PE file header and optional header, and the section headers.
         * Contrary to the case of the old PE format, the new PE format rounds
         * the size up to a multiple of FileAlignment (given in the optional header).
         *
         * Also I suppose for now that the NumberOfXXX members are valid;
         * should they not be, it is most probable this HeaderSize check
         * will fail, and consequently the other checks on the NumberOfXXX
         * done below fail as well.
         */
        TotalHeadersSize = nFileOffset;
        TotalHeadersSize += sizeof(IMAGE_FILE_HEADER) + FileHeader->SizeOfOptionalHeader +
                            // OptHeader->NumberOfRvaAndSizes * sizeof(IMAGE_DATA_DIRECTORY) + // It's counted in the size of optional header
                            FileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER)
                       /* + FileHeader->NumberOfSymbols * ??? */ ;
        TotalHeadersSize = ROUND_UP(TotalHeadersSize, (size_t)OptHeader->FileAlignment);
        if (OptHeader->SizeOfHeaders != TotalHeadersSize)
        {
            // PrintErrorReason(ErrorInvalidPE, ...);
            PrintWarning("The reported NT header size %lu does not match the calculated size %lu!\n",
                         OptHeader->SizeOfHeaders, (ULONG)TotalHeadersSize);
        }

        /* Verify that the handled number of special data directories is valid */
        if (OptHeader->NumberOfRvaAndSizes > RTL_NUMBER_OF_FIELD(IMAGE_OPTIONAL_HEADER32, DataDirectory))
        {
            PrintErrorReason(ErrorInvalidPE, "Invalid number of special data directories %lu; expected <= %lu",
                             OptHeader->NumberOfRvaAndSizes, (ULONG)RTL_NUMBER_OF_FIELD(IMAGE_OPTIONAL_HEADER32, DataDirectory));
            goto Failure;
        }

#if 0 // It's counted in the size of optional header
        if (OptHeader->NumberOfRvaAndSizes)
        {
            // DataDirectorySize = RTL_FIELD_SIZE(IMAGE_OPTIONAL_HEADER32, DataDirectory);
            DataDirectorySize = OptHeader->NumberOfRvaAndSizes * sizeof(IMAGE_DATA_DIRECTORY);
            NtHeadersSize += DataDirectorySize;
        }
#endif
    }

    if (FileHeader->NumberOfSections)
    {
        ObjectsTableSize = FileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

        /* Make sure the object table fits into the size */
        if (nFileOffset + sizeof(IMAGE_FILE_HEADER) + FileHeader->SizeOfOptionalHeader
            /* + DataDirectorySize */ + ObjectsTableSize >= nFileSize)
        {
            PrintErrorReason(ErrorMalformedPE, "Object table beyond image size");
            goto Failure;
        }

        /* NOTE: Contrary to the old-PE format, in the COFF format the
         * object/section table is by construction automatically after
         * the PE header (it follows the optional header). */

        NtHeadersSize += ObjectsTableSize;
    }


    /*
     * Perform any necessary re-allocation to accomodate for the Data directory array and objects table.
     */
    // if (NtHeadersSize > (size_t)FIELD_OFFSET(IMAGE_HEADER, DataDirectory))
    if (/* DataDirectorySize + */ ObjectsTableSize > 0)
    {
        /* Re-allocate the NT PE header to accomodate for the optional header,
         * the Data directory array and the object table. */
        PVOID ptr = realloc(NtHeaders, NtHeadersSize);
        if (!ptr)
        {
            PrintError("Failed to re-allocate %lu bytes\n", (ULONG)NtHeadersSize);
            goto Failure;
        }
        NtHeaders = ptr;
        FileHeader = &NtHeaders->FileHeader;
        if (OptHeader)
            OptHeader = &NtHeaders->OptionalHeader;

#if 0 // It's counted in the size of optional header
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
#endif

        if (ObjectsTableSize)
        {
            /* Get a pointer to the object table */
            // ObjTable = RVA(NtHeader, FIELD_OFFSET(IMAGE_HEADER, DataDirectory) + DataDirectorySize);
            ObjTable = RVA(FileHeader + 1, FileHeader->SizeOfOptionalHeader);

            /* Load it */
            fseek(pImageFile,
                  nFileOffset + sizeof(IMAGE_FILE_HEADER) + FileHeader->SizeOfOptionalHeader
                  /* + DataDirectorySize */,
                  SEEK_SET);
            // if (!fread(ObjTable, ObjectsTableSize, 1, pImageFile))
            if (!fread(ObjTable, sizeof(IMAGE_SECTION_HEADER), FileHeader->NumberOfSections, pImageFile))
            {
                PrintError("Failed to read %lu bytes from source file\n", (ULONG)ObjectsTableSize);
                goto Failure;
            }
        }
        else
        {
            /* No object table is present */
            FileHeader->NumberOfSections = 0;
        }
    }

    /* Return the headers to the caller */
    *pNtHeaders = NtHeaders;
    *pNtHeadersSize = (ULONG)NtHeadersSize;

    return TRUE;

Failure:
    if (NtHeaders)
        free(NtHeaders);
    return FALSE;
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
    IN ULONG nFileOffset,
    IN PDOS_IMAGE_HEADER DosHeader,
    OUT PIMAGE_HEADER* pNtHeader,
    OUT PULONG pNtHeaderSize)
{
    PIMAGE_HEADER NtHeader = NULL;
    PIMAGE_OBJECT_HEADER ObjTable = NULL;
    size_t NtHeaderSize;
    size_t TotalHeadersSize;
    size_t DataDirectorySize = 0;
    size_t ObjectsTableSize = 0;

    NtHeaderSize = FIELD_OFFSET(IMAGE_HEADER, DataDirectory);

    /* Make sure the old NT PE header fits into the size */
    if (nFileOffset + NtHeaderSize >= nFileSize)
    {
        PrintErrorReason(ErrorMalformedPE, "NT headers beyond image size");
        return FALSE;
    }
#if 0
    if (nFileOffset + NtHeaderSize > nFileSize)
    {
        PrintErrorReason(ErrorInvalidPE, "File smaller than IMAGE_HEADER size");
        return FALSE;
    }
#endif

    /* Allocate memory for the old NT PE header (excepting the Data directory)
     * and load it (it will be re-allocated later to accomodate for the extra
     * directory array and the object/sections table). */
    NtHeader = malloc(NtHeaderSize);
    if (!NtHeader)
    {
        PrintError("Failed to allocate %lu bytes\n", (ULONG)NtHeaderSize);
        return FALSE;
    }
    fseek(pImageFile, nFileOffset, SEEK_SET);
    if (!fread(NtHeader, NtHeaderSize, 1, pImageFile))
    {
        PrintError("Failed to read %lu bytes from source file\n", (ULONG)NtHeaderSize);
        goto Failure;
    }

    /* Verify the PE Signature (Note: this has been verified before) */
    ASSERT(NtHeader->SignatureBytes == IMAGE_NT_SIGNATURE);

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
    TotalHeadersSize = nFileOffset;
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
        if (NtHeader->ObjectTableRVA < nFileOffset + NtHeaderSize)
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
        /* Re-allocate the NT PE header to accomodate for the Data directory array and the object table */
        PVOID ptr = realloc(NtHeader, NtHeaderSize);
        if (!ptr)
        {
            PrintError("Failed to re-allocate %lu bytes\n", (ULONG)NtHeaderSize);
            goto Failure;
        }
        NtHeader = ptr;

        if (DataDirectorySize)
        {
            /* Load it */
            fseek(pImageFile, nFileOffset + FIELD_OFFSET(IMAGE_HEADER, DataDirectory), SEEK_SET);
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
    *pNtHeader  = NtHeader;
    *pNtHeaderSize = (ULONG)NtHeaderSize;

    return TRUE;

Failure:
    if (NtHeader)
        free(NtHeader);
    return FALSE;
}

/**
 * @brief   Parses an new-style PE image and retrieves its DOS and new-style
 *          PE headers. Validation and sanitization are performed.
 *          Returns TRUE if success, FALSE if failure (validation failed, or
 *          any other error happened).
 **/
static BOOLEAN
ParseNewPEImage(
    IN FILE* pImageFile,
    IN size_t nFileSize,
    IN ULONG nFileOffset,
    IN PIMAGE_DOS_HEADER DosHeader,
    OUT PIMAGE_NT_HEADERS32* pNtHeaders,
    OUT PULONG pNtHeadersSize)
{
    PIMAGE_NT_HEADERS32 NtHeaders = NULL;
    ULONG NtHeadersSize;
    // ULONG PEHdrSignature;

    /* Make sure the NT PE header fits into the size */
    if (nFileOffset + RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS32, FileHeader) >= nFileSize)
    {
        PrintErrorReason(ErrorMalformedPE, "NT headers beyond image size");
        return FALSE;
    }

    /* Actually load the NT PE headers, in COFF format */
    if (!ParseCOFF32Image(pImageFile, nFileSize,
                          // nFileOffset + RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS32, Signature),
                          nFileOffset + FIELD_OFFSET(IMAGE_NT_HEADERS32, FileHeader),
                          &NtHeaders, &NtHeadersSize))
    {
        PrintError("ParseCOFF32Image() failed.\n");
        return FALSE;
    }

    /* Check for the presence of the optional header */
    if (NtHeaders->FileHeader.SizeOfOptionalHeader == 0)
    {
        PrintErrorReason(ErrorUnsupportedPE, "Unsupported PE image (no optional header)!");
        goto Failure;
    }

    /* Restore the original PE signature */
    NtHeaders->Signature = IMAGE_NT_SIGNATURE; // PEHdrSignature;

    /* Return the headers to the caller */
    *pNtHeaders = NtHeaders;
    *pNtHeadersSize = (ULONG)NtHeadersSize;

    return TRUE;

Failure:
    if (NtHeaders)
        free(NtHeaders);
    return FALSE;
}


typedef struct _IMAGE_PARSE_DATA
{
    enum
    {
        IMAGE_Unknown = 0,
        IMAGE_Coff32,
        IMAGE_OldPE,
        IMAGE_NewPE
    } ImageType;

    /* Heap-allocated */
    PIMAGE_DOS_HEADER DosHeader;

    union
    {
        /* Any of these are heap-allocated; it is
         * therefore sufficient to just free one. */
        PIMAGE_HEADER NtHeader;
        PIMAGE_NT_HEADERS32 NtHeaders32;
    } u;
    ULONG NtHeadersSize;
} IMAGE_PARSE_DATA, *PIMAGE_PARSE_DATA;


static BOOLEAN
DetermineImageType(
    IN FILE* pImageFile,
    IN size_t nFileSize,
    IN OUT PIMAGE_PARSE_DATA ImageData)
{
    USHORT DosHdrMagic;

    RtlZeroMemory(ImageData, sizeof(*ImageData));
    ImageData->ImageType = IMAGE_Unknown;

    /* The file size must be greater than the minimum of
     * the IMAGE_DOS_HEADER and IMAGE_FILE_HEADER sizes. */
    if (min(sizeof(IMAGE_DOS_HEADER), sizeof(IMAGE_FILE_HEADER)) > nFileSize)
    {
        PrintErrorReason(ErrorInvalidPE, "File smaller than DOS or COFF header size");
        return FALSE;
    }

    /* Read the header signature, if any */
    rewind(pImageFile);
    if (!fread(&DosHdrMagic, sizeof(DosHdrMagic), 1, pImageFile))
    {
        PrintError("Failed to read %lu bytes from source file\n", (ULONG)sizeof(DosHdrMagic));
        return FALSE;
    }

    /* Check whether this is an MZ/PE image or a pure COFF file */
    // pDosHeader = (IMAGE_DOS_HEADER)pData;
    if ((DosHdrMagic == IMAGE_DOS_SIGNATURE) && (nFileSize >= sizeof(IMAGE_DOS_HEADER)))
    {
        /*
         * The image must be MZ/PE
         */

        /* New-PE header structure overlay, part of IMAGE_NT_HEADERS32 */
#include <pshpack4.h>
        typedef struct _IMAGE_OVERLAY
        {
            ULONG Signature;
            IMAGE_FILE_HEADER FileHeader;
            USHORT OptionalHeader_Magic;
            USHORT Padding;
        } IMAGE_OVERLAY;
/* Size of the useful portion of IMAGE_OVERLAY without the padding */
#define SIZEOF_IMAGE_OVERLAY    RTL_SIZEOF_THROUGH_FIELD(IMAGE_OVERLAY, OptionalHeader_Magic)
#include <poppack.h>
        C_ASSERT(SIZEOF_IMAGE_OVERLAY == RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS32, OptionalHeader.Magic));
        C_ASSERT(FIELD_OFFSET(IMAGE_OVERLAY, Signature) == FIELD_OFFSET(IMAGE_NT_HEADERS32, Signature));
        C_ASSERT(FIELD_OFFSET(IMAGE_HEADER, SignatureBytes) == FIELD_OFFSET(IMAGE_NT_HEADERS32, Signature));
        C_ASSERT(FIELD_OFFSET(IMAGE_HEADER, DataDirectory) > RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS32, OptionalHeader.Magic));

        PIMAGE_DOS_HEADER DosHeader;
        IMAGE_OVERLAY PETestBuffer = { 0 };
        ULONG NtHeaderOffset;

#if 0
        /* Make sure the DOS header fits into the size */
        if (sizeof(IMAGE_DOS_HEADER) > nFileSize)
        {
            PrintErrorReason(ErrorInvalidPE, "File smaller than IMAGE_DOS_HEADER size");
            return FALSE;
        }
#endif

        /* Allocate memory for the DOS image header and load it */
        DosHeader = malloc(sizeof(IMAGE_DOS_HEADER));
        if (!DosHeader)
        {
            PrintError("Failed to allocate %lu bytes\n", (ULONG)sizeof(IMAGE_DOS_HEADER));
            return FALSE;
        }
        rewind(pImageFile);
        if (!fread(DosHeader, sizeof(IMAGE_DOS_HEADER), 1, pImageFile))
        {
            PrintError("Failed to read %lu bytes from source file\n", (ULONG)sizeof(IMAGE_DOS_HEADER));
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

        //
        // TODO: Ensure we are quite certainly going to deal with MZ/PE
        // and not with an exclusively MZ DOS executable. Should check
        // for some values to be zero, especially in the reserved fields
        // e_res[] and beyond...
        //
        // If it turns out they aren't zero, we may still try to check
        // what's at e_lfanew, but we should not be convinced this will be
        // a valid MZ/PE at the end of the day.
        //

        /* Get the offset to the NT header */
        NtHeaderOffset = DosHeader->e_lfanew;

        /*
         * IMPORTANT NOTE!! We only support **VALID** PE files, and NOT
         * broken ones where e.g. the PE header is "merged" within the
         * DOS header, or where the list of objects/sections and directives
         * are not present after the PE header.
         */

        /* It should be aligned on a 8-byte boundary */
        // if (ROUND_UP(NtHeaderOffset, sizeof(ULONG64)) != NtHeaderOffset)
        if (!IS_ALIGNED(NtHeaderOffset, sizeof(ULONG64)))
        {
            PrintErrorReason(ErrorMalformedPE, "PE header offset not 8-byte aligned");
            goto Failure;
        }

        /* NOT BROKEN: The NT header must be **after** the DOS header */
        if (NtHeaderOffset < sizeof(IMAGE_DOS_HEADER))
        {
            PrintErrorReason(ErrorMalformedPE, "PE header offset in DOS header");
            goto Failure;
        }

        //
        // TODO: Now check for PE
        //

        /* Read the header signature */
        fseek(pImageFile, NtHeaderOffset, SEEK_SET);
        if (!fread(&PETestBuffer.Signature, sizeof(PETestBuffer.Signature), 1, pImageFile))
        {
            PrintError("Failed to read %lu bytes from source file\n", (ULONG)sizeof(PETestBuffer.Signature));
            goto Failure;
        }

        /* Verify the PE Signature */
        if (PETestBuffer.Signature != IMAGE_NT_SIGNATURE)
        {
            PrintErrorReason(ErrorInvalidPE, "Invalid NT image signature 0x%08X '%c%c%c%c'",
                             PETestBuffer.Signature,
                             PRINT_VAR_CHAR(PETestBuffer.Signature, 0), PRINT_VAR_CHAR(PETestBuffer.Signature, 1),
                             PRINT_VAR_CHAR(PETestBuffer.Signature, 2), PRINT_VAR_CHAR(PETestBuffer.Signature, 3));
            goto Failure;
        }


        /* Make sure the NT PE header fits into the size */
        // TotalHeadersSize += NtHeaderOffset + RTL_SIZEOF_THROUGH_FIELD(IMAGE_NT_HEADERS32, FileHeader);
        // if (TotalHeadersSize >= nFileSize)
        if (NtHeaderOffset + SIZEOF_IMAGE_OVERLAY >= nFileSize)
        {
            PrintErrorReason(ErrorMalformedPE, "NT headers beyond image size");
            goto Failure;
        }

        /* Read the whole overlay (including the header signature) */
        fseek(pImageFile, NtHeaderOffset, SEEK_SET);
        if (!fread(&PETestBuffer, SIZEOF_IMAGE_OVERLAY, 1, pImageFile))
        {
            PrintError("Failed to read %lu bytes from source file\n", (ULONG)SIZEOF_IMAGE_OVERLAY);
            goto Failure;
        }

        /* Verify that we are not actually looking at a new-PE image */
        if ( (PETestBuffer.FileHeader.SizeOfOptionalHeader >= FIELD_OFFSET(IMAGE_OPTIONAL_HEADER32, DataDirectory)) &&
             ((PETestBuffer.OptionalHeader_Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ||
              (PETestBuffer.OptionalHeader_Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)) )
        {
            /* This should be a new-PE image */
            if (!ParseNewPEImage(pImageFile, nFileSize,
                                 NtHeaderOffset,
                                 DosHeader,
                                 &ImageData->u.NtHeaders32,
                                 &ImageData->NtHeadersSize))
            {
                PrintError("ParseNewPEImage() failed.\n");
                goto Failure;
            }
            ImageData->ImageType = IMAGE_NewPE;
        }
        else
        {
            /* This should be an old-PE image */
            if (!ParseOldPEImage(pImageFile, nFileSize,
                                 NtHeaderOffset,
                                 DosHeader,
                                 &ImageData->u.NtHeader,
                                 &ImageData->NtHeadersSize))
            {
                PrintError("ParseOldPEImage() failed.\n");
                goto Failure;
            }
            ImageData->ImageType = IMAGE_OldPE;
        }

        /* Return the headers to the caller */
        ImageData->DosHeader = DosHeader;
        return TRUE;

    Failure:
        if (DosHeader)
            free(DosHeader);
        return FALSE;
    }
    else if (nFileSize >= sizeof(IMAGE_FILE_HEADER) /* == IMAGE_SIZEOF_FILE_HEADER */)
    {
        /*
         * The image must be COFF
         */
        if (!ParseCOFF32Image(pImageFile, nFileSize,
                              0,
                              &ImageData->u.NtHeaders32,
                              &ImageData->NtHeadersSize))
        {
            PrintError("ParseCOFF32Image() failed.\n");
            return FALSE;
        }
        ImageData->ImageType = IMAGE_Coff32;

        ImageData->DosHeader = NULL;
        return TRUE;
    }
    else
    {
        PrintError("Unrecognized image format!\n");
        return FALSE;
    }
}


bool
IsZeroMemory(
    IN const void UNALIGNED *Buffer,
    IN size_t Size)
{
/*
#pragma intrinsic(_BitScanForward)
i = 0; _BitScanForward(&i, addr); i = 1 << i; i = min(i, sizeof(uint64_t));
 */
#define GET_ALIGNMENT(addr) \
    !((ULONG_PTR)(addr) & (sizeof(uint64_t) - 1)) ? sizeof(uint64_t) : \
    !((ULONG_PTR)(addr) & (sizeof(uint32_t) - 1)) ? sizeof(uint32_t) : \
    !((ULONG_PTR)(addr) & (sizeof(uint16_t) - 1)) ? sizeof(uint16_t) : sizeof(uint8_t)
 // !((ULONG_PTR)(addr) & (sizeof(uint8_t)  - 1)) ? sizeof(uint8_t)  : 0

#if 0

    // size_t align;
    while (Size)
    {
        switch (/*align =*/ GET_ALIGNMENT(Buffer))
        {
        case sizeof(uint64_t) :
            while (Size >= sizeof(uint64_t))
            {
                if (*(uint64_t*)Buffer != 0ULL)
                    return false;
                Buffer = (void*)((size_t)Buffer + sizeof(uint64_t));
                Size -= sizeof(uint64_t);
            }
            // break;
        case sizeof(uint32_t) :
            // if (Size >= sizeof(uint32_t))
            if (Size >> 2) // Size / sizeof(uint32_t)
            {
                if (*(uint32_t*)Buffer != 0UL)
                    return false;
                Buffer = (void*)((size_t)Buffer + sizeof(uint32_t));
                Size -= sizeof(uint32_t);
                // break;
            }
            /* Fallback */
        case sizeof(uint16_t) :
            // if (Size >= sizeof(uint16_t))
            if (Size >> 1) // Size / sizeof(uint16_t)
            {
                if (*(uint16_t*)Buffer != 0)
                    return false;
                Buffer = (void*)((size_t)Buffer + sizeof(uint16_t));
                Size -= sizeof(uint16_t);
                // break;
            }
            /* Fallback */
        case sizeof(uint8_t) :
            if (Size >= sizeof(uint8_t))
            {
                if (*(uint8_t*)Buffer != 0)
                    return false;
                Buffer = (void*)((size_t)Buffer + sizeof(uint8_t));
                Size -= sizeof(uint8_t);
                // break;
            }
        }
    }

#else

    while (Size)
    {
        if ((Size >= sizeof(uint64_t)) && IS_ALIGNED(Buffer, sizeof(uint64_t)))
        {
            if (*(uint64_t*)Buffer != 0ULL)
                return false;
            Buffer = (void*)((size_t)Buffer + sizeof(uint64_t));
            Size -= sizeof(uint64_t);
        }
        else if ((Size >= sizeof(uint32_t)) && IS_ALIGNED(Buffer, sizeof(uint32_t)))
        {
            if (*(uint32_t*)Buffer != 0UL)
                return false;
            Buffer = (void*)((size_t)Buffer + sizeof(uint32_t));
            Size -= sizeof(uint32_t);
        }
        else if ((Size >= sizeof(uint16_t)) && IS_ALIGNED(Buffer, sizeof(uint16_t)))
        {
            if (*(uint16_t*)Buffer != 0)
                return false;
            Buffer = (void*)((size_t)Buffer + sizeof(uint16_t));
            Size -= sizeof(uint16_t);
        }
        else if (Size >= sizeof(uint8_t)) // && IS_ALIGNED(Buffer, sizeof(uint8_t)))
        {
            if (*(uint8_t*)Buffer != 0)
                return false;
            Buffer = (void*)((size_t)Buffer + sizeof(uint8_t));
            Size -= sizeof(uint8_t);
        }
    }

#endif

    return true;

#undef GET_ALIGNMENT
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
    PIMAGE_SECTION_HEADER SectionTable = NULL; // The converted object/section table.
    PIMAGE_NT_HEADERS32 NtHeaders;
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
    PULONG ExportTable = NULL;

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

    TotalHeadersSize = FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader) + (size_t)SizeOfOptionalHeader;
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

    /* Directives are unsupported in PE images (they are object only) */
    ASSERT(NtHeader->NumberOfDirectives == 0);
    ASSERT(NtHeader->DirectiveTableRVA == 0);

    // INVESTIGATE: NtHeader->OSType seems to be always 4.
    if (NtHeader->OSType != 4)
        PrintWarning("WARNING: Unknown OSType value %d\n", NtHeader->OSType);

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
    // INVESTIGATE: Examples of flags encoded in NtHeader->ModuleFlags:
    // --> DLLs have 0xA0008300, while EXEs have 0xA0000200 (mostly commandline) or 0xA0000300 (GUI or the subsystems).
    // --> NtHeader->ModuleFlags & 0x0700) == 0x0200 means the module is Windows CUI subsystem (see below).
    //
    /* We are definitively an executable image */
    FileHeader->Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
    /* Suppose that Endian != 0 means big endian */
    if (NtHeader->Endian)
        FileHeader->Characteristics |= IMAGE_FILE_BYTES_REVERSED_HI; /* Big endian */
    else
        FileHeader->Characteristics |= IMAGE_FILE_BYTES_REVERSED_LO; /* Little endian */
    // HACK: Force 32-bit machine when it's for an i386 processor.
    if (FileHeader->Machine == IMAGE_FILE_MACHINE_I386)
        FileHeader->Characteristics |= IMAGE_FILE_32BIT_MACHINE;
    // END HACK!!
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
    OptHeader->MajorSubsystemVersion       = 0;
    OptHeader->MinorSubsystemVersion       = 0;
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
    OptHeader->SizeOfHeaders = ROUND_UP((size_t)DosHeader->e_lfanew + TotalHeadersSize, (size_t)NtHeader->FileAlign);

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

    OptHeader->DllCharacteristics  = 0;
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
    Section = LoadOldPEDirectoryEntryAndSection(pImageFile,
                                                NtHeader,
                                                IMAGE_DIRECTORY_ENTRY_EXPORT,
                                                &Directory.Export,
                                                &DirectorySize,
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
        ULONG_PTR EndDirectory;
        size_t ExportTableSize;

        ASSERT(SectionHdr);

        FixupExportsSectionWorker(Directory.Export,
                                  DirectorySize,
                                  SectionHdr->RVA,
                                  SectionSize,
                                  Section,
                                  &EndDirectory);

        //
        // TODO: Find a nice way to move the code below into the worker as PE-independent format.
        //
        /* Compute the new directory size and modify the directory entry */
        EndDirectory  = ROUND_UP(EndDirectory, sizeof(ULONG));
        DirectorySize = (ULONG)(EndDirectory - NtHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].RVA);
        DirectorySize = max(DirectorySize, sizeof(IMAGE_EXPORT_DIRECTORY)); // Sanitization.

        OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size =
         NtHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = DirectorySize;


        ExportTableSize = Directory.Export->NumberOfFunctions * sizeof(ULONG);

        /* Sanity check: Check that the export function table is
         * fully contained in the section, otherwise bail out. */
        if (!REGION_IN_REGION(Directory.Export->AddressOfFunctions,
                              ExportTableSize,
                              SectionHdr->RVA,
                              SectionSize))
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

    /* Convert the object/section table and initialize the remaining fields */
    if (!ReconstructSections(NtHeader,
                             ObjTable,
                             Directory.Export,
                             ExportTable,
                             /* These two could be replaced by a single "IN PIMAGE_NT_HEADERS32 NtHeader" */
                             FileHeader,
                             OptHeader,
                             &SectionTable))
    {
        OptHeader->BaseOfCode = 0;
        OptHeader->SizeOfCode = 0;
        OptHeader->BaseOfData = 0;
        OptHeader->SizeOfInitializedData   = 0;
        OptHeader->SizeOfUninitializedData = 0;
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
        if (!FlushOldPESectionToFile(pDestFile, SectionHdr, Section))
            PrintError("Failed to update the %s section!\n", "Export");

        /* Free the allocated export section */
        free(Section);
    }

    /* Import directory */
    Section = LoadOldPEDirectoryEntryAndSection(pImageFile,
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
        ASSERT(SectionHdr);

        FixupImportsSection(Directory.Import,
                            DirectorySize,
                            SectionHdr->RVA,
                            SectionSize,
                            Section);

        if (!FlushOldPESectionToFile(pDestFile, SectionHdr, Section))
            PrintError("Failed to update the %s section!\n", "Import");

        /* Free the allocated section */
        free(Section);
    }

    /* Resource directory */

    /* Exception directory */

    /* Security directory */

    /* Relocations directory */

    /* Debug directory */
    Section = LoadOldPEDirectoryEntryAndSection(pImageFile,
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

    /*
     * Convert the debug directory data and initialize the PE COFF-specific debug fields.
     */
    FileHeader->PointerToSymbolTable = 0;
    FileHeader->NumberOfSymbols      = 0;

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
        if ((DirectorySize == 0) || (DirectorySize % sizeof(COFF_DEBUG_DIRECTORY) != 0))
        {
            /* Definitively not COFF_DEBUG_DIRECTORY; could be IMAGE_DEBUG_DIRECTORY
             * or something unknown to us; in any case we don't touch it. */
        }
        else // if ((DirectorySize > 0) && (DirectorySize % sizeof(COFF_DEBUG_DIRECTORY) == 0))
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
                 * sizeof(COFF_DEBUG_DIRECTORY) == 24 == 8*3,
                 * sizeof(IMAGE_DEBUG_DIRECTORY) == 28 == 7*4.
                 * The condition is equivalent to finding whether there exists
                 * integers a, b, such that:
                 * DirectorySize == a * 24 == b * 28 .
                 * Simplifying, we see that a * 6 == b * 7, so that a and b
                 * should be coprime, and thus, there exists an integer n such
                 * that a == n * 7 and b == n * 6, and therefore,
                 * DirectorySize == n * 6 * 7.
                 */

                /*
                 * Suppose that the directory data indeed is of the old format.
                 * Since AddressOfRawData and PointerToRawData are not at the same
                 * position wrt. the new format (they are 1 ULONG before), use these
                 * as the comparison criterium.
                 */
                if (Directory.Debug->PointerToRawData != 0)
                {
                    /* The debug data must be within the debug directory's section */
                    if (/* ADDRESS_IN_REGION(Directory.Debug->PointerToRawData,
                                             SectionHdr->SeekOffset,
                                             SectionHdr->OnDiskSize) && */
                        REGION_IN_REGION(Directory.Debug->PointerToRawData,
                                         Directory.Debug->SizeOfData,
                                         SectionHdr->SeekOffset,
                                         SectionHdr->OnDiskSize))
                    {
                        /*
                         * The RAW debug data appears to be in the section the debug information belongs.
                         * Check also the validity of AddressOfRawData.
                         * NOTE: The RVA address can be zero if the debug data is not loaded in memory.
                         */
                        if ((Directory.Debug->AddressOfRawData == 0) ||
                            (Directory.Debug->AddressOfRawData == SectionHdr->RVA + (Directory.Debug->PointerToRawData - SectionHdr->SeekOffset)))
                        {
                            /* The reported RVA address is valid, so this is indeed a correct old debug directory */
                            IsOldDebug = TRUE;
                        }
                    }
                }
            }
        }

        /*
         * Perform extra sanity checks.
         */
        if (IsOldDebug)
        {
            // C_ASSERT(FIELD_OFFSET(IMAGE_DEBUG_DIRECTORY, Characteristics) == FIELD_OFFSET(COFF_DEBUG_DIRECTORY, Characteristics));
            if (Directory.Debug->Characteristics != 0)
            {
                PrintWarning("WARNING: Non-zero Characteristics %d (reserved)\n",
                             Directory.Debug->Characteristics);
            }

            /* In all real-life examples, the version stamp appears to always be zero */
            if (Directory.Debug->VersionStamp != 0)
            {
                PrintWarning("WARNING: Non-zero VersionStamp %d (reserved)\n",
                             Directory.Debug->VersionStamp);
            }

            /* The debug data must be within the debug directory's section */
            if (/* !ADDRESS_IN_REGION(Directory.Debug->PointerToRawData,
                                      SectionHdr->SeekOffset,
                                      SectionHdr->OnDiskSize) || */
                !REGION_IN_REGION(Directory.Debug->PointerToRawData,
                                  Directory.Debug->SizeOfData,
                                  SectionHdr->SeekOffset,
                                  SectionHdr->OnDiskSize))
            {
                PrintError("Debug data is not within the debug directory's section!\n");
                IsOldDebug = FALSE; // Reset so that we don't do the conversion below.
            }

            /*
             * The RAW debug data appears to be in the section the debug information belongs.
             * Check also the validity of AddressOfRawData.
             * NOTE: The RVA address can be zero if the debug data is not loaded in memory.
             */
            if ( !((Directory.Debug->AddressOfRawData == 0) ||
                   (Directory.Debug->AddressOfRawData == SectionHdr->RVA + (Directory.Debug->PointerToRawData - SectionHdr->SeekOffset))) )
            {
                PrintError("Debug data address is invalid!\n");
                IsOldDebug = FALSE; // Reset so that we don't do the conversion below.
            }

            /* Check for a possible valid debug type field.
             * NT PDK v1.196 only supports COFF debug symbols. */
            if (Directory.Debug->Type > IMAGE_DEBUG_TYPE_COFF)
            {
                PrintWarning("WARNING: Unrecognized image debug type %d\n",
                             Directory.Debug->Type);
            }
        }
        else // if ((DirectorySize > 0) && (DirectorySize % sizeof(IMAGE_DEBUG_DIRECTORY) == 0))
        {
            /*
             * Keep this code as reference for validation, but disabled, as we
             * don't actually assume that this is a new-format debug directory data.
             */
#if 0
            /* Suppose first that the data is of the new format and verify its consistency */
            PIMAGE_DEBUG_DIRECTORY DebugDirectory = (PIMAGE_DEBUG_DIRECTORY)Directory.Debug;

            C_ASSERT(FIELD_OFFSET(IMAGE_DEBUG_DIRECTORY, Characteristics) == FIELD_OFFSET(COFF_DEBUG_DIRECTORY, Characteristics));
            if (DebugDirectory->Characteristics != 0)
            {
                PrintWarning("WARNING: Non-zero Characteristics %d (reserved)\n",
                             DebugDirectory->Characteristics);
            }

            /* In all real-life examples, these two version numbers appear to always be zero */
            if ((DebugDirectory->MajorVersion != 0) || (DebugDirectory->MinorVersion != 0))
            {
                PrintWarning("WARNING: Debug data version %d.%d is not zero\n",
                             DebugDirectory->MajorVersion, DebugDirectory->MinorVersion);
            }

            /* Check for a possible valid debug type field, which
             * should definitively be smaller than UCHAR_MAX. */
            C_ASSERT(FIELD_OFFSET(IMAGE_DEBUG_DIRECTORY, Type) == FIELD_OFFSET(COFF_DEBUG_DIRECTORY, Type));
            if (DebugDirectory->Type < UCHAR_MAX)
            {
                /* Just an optional sanity check: I use the maximum value
                 * defined in Windows Server 2003, knowing that later values
                 * definitively did not exist in older Windows NT versions. */
                if (DebugDirectory->Type > IMAGE_DEBUG_TYPE_CLSID
                    /* IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS == 20 */)
                {
                    PrintWarning("WARNING: Unrecognized image debug type %d\n", DebugDirectory->Type);
                }
            }

            /* The debug data must be within the debug directory's section */
            if (/* !ADDRESS_IN_REGION(DebugDirectory->PointerToRawData,
                                      SectionHdr->SeekOffset,
                                      SectionHdr->OnDiskSize) || */
                !REGION_IN_REGION(DebugDirectory->PointerToRawData,
                                  DebugDirectory->SizeOfData,
                                  SectionHdr->SeekOffset,
                                  SectionHdr->OnDiskSize))
            {
                PrintError("Debug data is not within the debug directory's section!\n");
            }

            /*
             * The RAW debug data appears to be in the section the debug information belongs.
             * Check also the validity of AddressOfRawData.
             * NOTE: The RVA address can be zero if the debug data is not loaded in memory.
             */
            if ( !((DebugDirectory->AddressOfRawData == 0) ||
                   (DebugDirectory->AddressOfRawData == SectionHdr->RVA + (DebugDirectory->PointerToRawData - SectionHdr->SeekOffset))) )
            {
                PrintError("Debug data address is invalid!\n");
            }
#endif
        }

        /*
         * Do the conversion.
         */
        if (IsOldDebug)
        {
            ULONG NumberOfDebugDirectories = DirectorySize / sizeof(COFF_DEBUG_DIRECTORY);
            ULONG NewDirectorySize = ROUND_UP(NumberOfDebugDirectories * sizeof(IMAGE_DEBUG_DIRECTORY), sizeof(ULONG));

            /*
             * The algorithm works as follows:
             *
             * 0. Localize the actual beginning of the debug data (that follows
             *    the debug directories) and see whether there exists enough
             *    padding between it and the end of the directories. If so we
             *    may be able to fit the new debug directories directly.
             *
             * 1. Check whether we can move the data within the .debug section.
             *    This is done by looking at the presence of a certain number of
             *    trailing zero bytes (as many needed for fitting the extra data
             *    from the conversion of the debug directory) at the very end of
             *    the debug data.
             *    If these are present, we are ensured that these are padding
             *    bytes (and not e.g. actual debug data, like an ULONG, that
             *    may need to be NULL).
             *    If found, then we can move the data, and upgrade the COFF_DEBUG_DIRECTORY
             *    data to the newer IMAGE_DEBUG_DIRECTORY.
             *
             * 2. If we cannot move the data, search for at least "NewDirectorySize"
             *    bytes of slack space at the end of any existing initialized data
             *    section (i.e. NOT .bss) or text section, excepting the .debug section
             *    (since we could not already find enough slack space for step 1).
             *    If found, then write the newer IMAGE_DEBUG_DIRECTORY.
             *
             * 3. If this is still not possible, try extending any last section
             *    (usually the .debug section, but can be any other one) and write
             *    the newer IMAGE_DEBUG_DIRECTORY.
             */
            PIMAGE_DEBUG_DIRECTORY DebugDirectory;
            PVOID TmpSection;         // Allocated section.
            ULONG TmpSectionSize = 0; // The size of the allocated section.
            ULONG i;
            BOOLEAN bConversionDone = FALSE;

            C_ASSERT(sizeof(IMAGE_DEBUG_DIRECTORY) <= sizeof(COFF_DEBUG_DIRECTORY) + sizeof(ULONG));



            /* Step 0: Localize the actual beginning and end of the debug data */






            /* Step 1: Can we move the data within the .debug section? */

            ULONG EndData = max(Directory.Debug->PointerToRawData + Directory.Debug->SizeOfData,
                                SectionHdr->SeekOffset + SectionHdr->OnDiskSize);
            PUCHAR Padding;

            if (EndData - SectionHdr->SeekOffset > NewDirectorySize - DirectorySize + 1)
            {
                Padding = (PUCHAR)RVA(Section, (EndData - (NewDirectorySize - DirectorySize + 1)) - SectionHdr->SeekOffset);

                if (IsZeroMemory(Padding, NewDirectorySize - DirectorySize + 1))
                {
                    COFF_DEBUG_DIRECTORY OrgDebugDirectory = *Directory.Debug;

                    //
                    // FIXME: Reduce the size of the data for only the debug directory
                    // whose data has been actually reduced (data that is at the end).
                    //
                    OrgDebugDirectory.SizeOfData -= NewDirectorySize - DirectorySize;

                    /* Move the debug data, without the last bytes */
                    RtlMoveMemory(RVA(Section, (Directory.Debug->PointerToRawData + NewDirectorySize - DirectorySize) - SectionHdr->SeekOffset),
                                  RVA(Section, Directory.Debug->PointerToRawData - SectionHdr->SeekOffset),
                                  OrgDebugDirectory.SizeOfData);

                    /* Convert the debug directories in place */
                    // for (i = 0; i < NumberOfDebugDirectories; ++i)
                    {
                        DebugDirectory = (PIMAGE_DEBUG_DIRECTORY)Directory.Debug;
                        DebugDirectory->Characteristics  = OrgDebugDirectory.Characteristics;
                        DebugDirectory->TimeDateStamp    = FileHeader->TimeDateStamp;
                        DebugDirectory->MajorVersion     = LOWORD(OrgDebugDirectory.VersionStamp);
                        DebugDirectory->MinorVersion     = HIWORD(OrgDebugDirectory.VersionStamp);
                        DebugDirectory->Type             = OrgDebugDirectory.Type;
                        DebugDirectory->SizeOfData       = OrgDebugDirectory.SizeOfData;
                        DebugDirectory->AddressOfRawData = OrgDebugDirectory.AddressOfRawData + NewDirectorySize - DirectorySize;
                        DebugDirectory->PointerToRawData = OrgDebugDirectory.PointerToRawData + NewDirectorySize - DirectorySize;
                    }

                    if (!FlushOldPESectionToFile(pDestFile, SectionHdr, Section))
                    {
                        // /* Use the new PE converted section for the name */
                        // PrintError("Failed to update the '%.*s' section!\n",
                        //            (ULONG)RTL_NUMBER_OF(SectionTable[i].Name), SectionTable[i].Name);
                        PrintError("Failed to update the '%s' section!\n", ".debug");
                    }
                    else
                    {
                        /* Modify the directory entry */
                        OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size =
                         NtHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = NewDirectorySize;

                        bConversionDone = TRUE;
                    }
                }
            }

            /* Step 2: Search for slack space in other sections.
             * We need to have a section table for this. */
            if (!bConversionDone && ObjTable)
            {
                ASSERT(NtHeader->NumberOfObjects);
                ASSERT(SectionTable);

                /* Loop over the sections to find some slack space */
                for (i = 0; i < NtHeader->NumberOfObjects; ++i)
                {
                    /* Skip the .debug section */
                    // if (SectionHdr == &ObjTable[i])
                    if (SectionHdr->SeekOffset == ObjTable[i].SeekOffset)
                        continue;

                    /* Skip the .bss section */
                    // Use the new PE converted section characteristics.
                    // if (SectionTable[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
                    if (ObjTable[i].VirtualSize == 0 || ObjTable[i].OnDiskSize == 0)
                        continue;

                    /* Load the section */
                    if (!LoadOldPESectionFromFile(pImageFile,
                                                  &ObjTable[i],
                                                  &TmpSection,
                                                  NULL))
                    {
                        /* Just skip this section. No need to display errors
                         * since LoadOldPESectionFromFile() does that already. */
                        continue;
                    }
                    ASSERT(TmpSection);

                    /*
                     * Heuristics:
                     * Search for sizeof(IMAGE_DEBUG_DIRECTORY) + 2 bytes slack space.
                     * The "+ 2 bytes" ensures that if there is some extra data before
                     * e.g. a string that needs to be NULL-terminated, this data remains fine.
                     */
                    EndData = ObjTable[i].SeekOffset + ObjTable[i].OnDiskSize;

                    if (EndData - ObjTable[i].SeekOffset >= sizeof(IMAGE_DEBUG_DIRECTORY) + 2)
                    {
                        Padding = (PUCHAR)RVA(TmpSection, (EndData - sizeof(IMAGE_DEBUG_DIRECTORY) - 2) - ObjTable[i].SeekOffset);

                        if (IsZeroMemory(Padding, sizeof(IMAGE_DEBUG_DIRECTORY) + 2))
                        {
                            /* Add the debug directory */
                            DebugDirectory = (PIMAGE_DEBUG_DIRECTORY)&Padding[2];
                            DebugDirectory->Characteristics  = Directory.Debug->Characteristics;
                            DebugDirectory->TimeDateStamp    = FileHeader->TimeDateStamp;
                            DebugDirectory->MajorVersion     = LOWORD(Directory.Debug->VersionStamp);
                            DebugDirectory->MinorVersion     = HIWORD(Directory.Debug->VersionStamp);
                            DebugDirectory->Type             = Directory.Debug->Type;
                            DebugDirectory->SizeOfData       = Directory.Debug->SizeOfData;
                            DebugDirectory->AddressOfRawData = Directory.Debug->AddressOfRawData;  // FIXME!
                            DebugDirectory->PointerToRawData = Directory.Debug->PointerToRawData;  // FIXME!

                            if (!FlushOldPESectionToFile(pDestFile, &ObjTable[i], TmpSection))
                            {
                                /* Use the new PE converted section for the name */
                                PrintError("Failed to update the '%.*s' section!\n",
                                           (ULONG)RTL_NUMBER_OF(SectionTable[i].Name), SectionTable[i].Name);
                            }
                            else
                            {
                                /* Modify the directory entry */
                                OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress =
                                 NtHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].RVA =
                                    (ULONG)(ULONG_PTR)RVA(ObjTable[i].RVA, (ULONG_PTR)DebugDirectory - (ULONG_PTR)TmpSection);

                                OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size =
                                 NtHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = sizeof(*DebugDirectory);

                                bConversionDone = TRUE;
                            }
                        }
                    }

                    /* Free the allocated section */
                    free(TmpSection);

                    /* Break if we are done */
                    if (bConversionDone)
                        break;
                }
            }

            /* Step 3: Extend the last section.
             * We need to have a section table for this. */
            if (!bConversionDone && ObjTable)
            {
                PIMAGE_OBJECT_HEADER LastSectionHdr;
                size_t NewSectionSize;

                ASSERT(NtHeader->NumberOfObjects);
                ASSERT(SectionTable);

                /* Find the last section in the file; we do not rely on whether
                 * or not they are already sorted in the section table. */
                LastSectionHdr = &ObjTable[0];
                for (i = 0; i < NtHeader->NumberOfObjects; ++i)
                {
                    if (LastSectionHdr->SeekOffset < ObjTable[i].SeekOffset)
                        LastSectionHdr = &ObjTable[i];
                }
                /* Recalculate the index corresponding to LastSectionHdr for later purposes */
                i = (ULONG)(LastSectionHdr - ObjTable);

                /* If this is the .bss section, skip it */
                // Use the new PE converted section characteristics.
                // if (SectionTable[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
                if (LastSectionHdr->VirtualSize == 0 || LastSectionHdr->OnDiskSize == 0)
                    goto StopStep3;

                /* Load the last section */
                if (!LoadOldPESectionFromFile(pImageFile,
                                              LastSectionHdr,
                                              &TmpSection,
                                              &TmpSectionSize))
                {
                    /* Just skip this section. No need to display errors
                        * since LoadOldPESectionFromFile() does that already. */
                    goto StopStep3;
                }
                ASSERT(TmpSection);


                /*
                 * LoadOldPESectionFromFile() allocated a section buffer, of size equals to the
                 * max(VirtualSize, OnDiskSize) (size returned in TmpSectionSize), so we will
                 * need to re-allocate it only if OnDiskSize + sizeof(IMAGE_DEBUG_DIRECTORY)
                 * is > TmpSectionSize.
                 */
                if (LastSectionHdr->OnDiskSize + sizeof(IMAGE_DEBUG_DIRECTORY) > TmpSectionSize)
                {
                    PVOID ptr;

                    /* Enlarge the section buffer */
                    NewSectionSize = ROUND_UP(TmpSectionSize + sizeof(IMAGE_DEBUG_DIRECTORY), NtHeader->FileAlign);
                    ptr = realloc(TmpSection, NewSectionSize);
                    if (!ptr)
                    {
                        PrintError("Failed to re-allocate %lu bytes for the '%.*s' section\n",
                                   (ULONG)NewSectionSize,
                                   (ULONG)RTL_NUMBER_OF(SectionTable[i].Name), SectionTable[i].Name);

                        free(TmpSection);
                        goto StopStep3;
                    }
                    TmpSection = ptr;

                    /* Zero out the slack space */
                    RtlZeroMemory(RVA(TmpSection, TmpSectionSize),
                                  NewSectionSize - TmpSectionSize);
                }

                /* Add the debug directory */
                DebugDirectory = (PIMAGE_DEBUG_DIRECTORY)RVA(TmpSection, LastSectionHdr->OnDiskSize);

                LastSectionHdr->OnDiskSize = ROUND_UP(LastSectionHdr->OnDiskSize + sizeof(IMAGE_DEBUG_DIRECTORY), NtHeader->FileAlign);
                // LastSectionHdr->VirtualSize; // FIXME??

                DebugDirectory->Characteristics  = Directory.Debug->Characteristics;
                DebugDirectory->TimeDateStamp    = FileHeader->TimeDateStamp;
                DebugDirectory->MajorVersion     = LOWORD(Directory.Debug->VersionStamp);
                DebugDirectory->MinorVersion     = HIWORD(Directory.Debug->VersionStamp);
                DebugDirectory->Type             = Directory.Debug->Type;
                DebugDirectory->SizeOfData       = Directory.Debug->SizeOfData;
                DebugDirectory->AddressOfRawData = Directory.Debug->AddressOfRawData;
                DebugDirectory->PointerToRawData = Directory.Debug->PointerToRawData;

                if (!FlushOldPESectionToFile(pDestFile, LastSectionHdr, TmpSection))
                {
                    /* Use the new PE converted section for the name */
                    PrintError("Failed to update the '%.*s' section!\n",
                               (ULONG)RTL_NUMBER_OF(SectionTable[i].Name), SectionTable[i].Name);
                }
                else
                {
                    /* Modify the directory entry */
                    OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress =
                     NtHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].RVA =
                        (ULONG)(ULONG_PTR)RVA(LastSectionHdr->RVA, (ULONG_PTR)DebugDirectory - (ULONG_PTR)TmpSection);

                    OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size =
                     NtHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = sizeof(*DebugDirectory);

                    bConversionDone = TRUE;
                }

                /* Free the allocated section */
                free(TmpSection);

            StopStep3:
                ;
            }

            if (!bConversionDone)
            {
                PrintError("Failed to convert the debug directory!\n");
            }
            else
            {
                if (Directory.Debug->Type == IMAGE_DEBUG_TYPE_COFF)
                {
                    // TODO!
                    FileHeader->PointerToSymbolTable = 0;
                    FileHeader->NumberOfSymbols = 0;
                }
            }
        }

        /* Free the allocated section */
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
        ULONG i;

        ASSERT(SectionTable);
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

    IMAGE_PARSE_DATA Headers = { IMAGE_Unknown, NULL, {NULL}, 0 };

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

    /* Read the whole source file */
    fread(pData, nFileSize, 1, pSourceFile);
#endif

    if (bDisplayInfo)
        printf("Image file: %s\n\n", pszSourceFile);
    fflush(stdout);
    fflush(stderr);

    /* Check whether this is a pure COFF file or a PE image */
    if (!DetermineImageType(/*pData*/ pSourceFile, nFileSize, &Headers))
    {
        PrintError("Unrecognized image format!\n");
        nErrorCode = -4;
        goto Quit;
    }

    /* We are good, now display the information if necessary */
    if (bDisplayInfo)
    {
        switch (Headers.ImageType)
        {
        case IMAGE_Coff32:
            DumpCOFFImage(&Headers.u.NtHeaders32->FileHeader);
            break;

        case IMAGE_OldPE:
            ASSERT(Headers.DosHeader);
            DumpOldPEImage(Headers.DosHeader, Headers.u.NtHeader);
            break;

        case IMAGE_NewPE:
            ASSERT(Headers.DosHeader);
            DumpNewPEImage(Headers.DosHeader, Headers.u.NtHeaders32);
            break;

        default:
            ASSERT(FALSE);
            PrintError("Unrecognized image format!\n");
        }
    }

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
            nErrorCode = -5;
            goto Quit;
        }
    }

    if (Headers.ImageType == IMAGE_OldPE)
    {
        /* PE image - Either extract only the section specified by the user, or all of them */
        ASSERT(Headers.DosHeader);
        if (!ProcessPEImage(/*pData*/ pSourceFile, nFileSize, pDestFile,
                            Headers.DosHeader, Headers.u.NtHeader, Headers.NtHeadersSize))
        {
            PrintError("ProcessPEImage() failed.\n");
            nErrorCode = -6;
            // goto Quit;
        }
    }
    else
    {
        PrintError("Conversion of non-old-PE images is currently unimplemented.\n");
    }

    if (pDestFile)
        fclose(pDestFile);

Quit:
    if (Headers.u.NtHeader)
        free(Headers.u.NtHeader);
    if (Headers.DosHeader)
        free(Headers.DosHeader);

    fclose(pSourceFile);
    // free(pData);

    fflush(stdout);
    fflush(stderr);

    return nErrorCode;
}
