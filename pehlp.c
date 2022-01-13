/*
 * PROJECT:     PE Converter for NT PDK v1.196 (September 1991) and PDK October 1991
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Helper functions for the old and new PE formats.
 * COPYRIGHT:   Copyright 2021-2022 Hermès Bélusca-Maïto
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
// #include <stdlib.h> // For _countof() -- TODO: Make it compiler-independent.
// // #include <io.h>
//#include <fcntl.h>
#include <string.h>

/* NT types and PE definitions */
#include "typedefs.h"
#include "pecoff.h"
#include "nt196pe.h"

#include "ntpeconv.h"
#include "pehlp.h"


/**
 * @brief   Loads the contents of a section from a file.
 *          The description of the section is passed via SectionHdr.
 *          The function returns a pointer to the allocated section,
 *          or NULL in case of failure. This pointer must be freed
 *          by the caller after usage.
 *          Returns TRUE if success, FALSE otherwise.
 **/
static BOOLEAN
LoadSectionFromFileEx(
    IN FILE* pImageFile,
    IN ULONG Offset,
    IN ULONG RawSize,
    IN ULONG VirtualSize,
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
    SectionSize = max(VirtualSize, RawSize);

    /* Allocate the section and load it from the file */
    Section = malloc(SectionSize);
    if (!Section)
    {
        PrintError("Could not load the section!\n");
        return FALSE;
    }

    /* Load it */
    fseek(pImageFile, Offset, SEEK_SET);
    if (!fread(Section, RawSize, 1, pImageFile))
    {
        PrintError("Failed to read %lu bytes from source file\n", RawSize);
        free(Section);
        return FALSE;
    }
    /* Size of data is less than the virtual size: zero out the slack space */
    if (RawSize < SectionSize)
    {
        RtlZeroMemory(RVA(Section, RawSize),
                      SectionSize - RawSize);
    }

    *pSection = Section;
    if (pSectionSize)
        *pSectionSize = SectionSize;
    return TRUE;
}

BOOLEAN
LoadOldPESectionFromFile(
    IN FILE* pImageFile,
    IN PIMAGE_OBJECT_HEADER SectionHdr,
    OUT PVOID* pSection,
    OUT PULONG pSectionSize OPTIONAL)
{
#if 0
    /*
     * NOTE: It sometimes happens for the "old" new PEs that the VirtualSize
     * is zero, while the OnDiskSize is not, and the section contains actual
     * data. Therefore we don't truncate the size but instead take the max.
     */
    ULONG SectionSize;
    SectionSize = max(SectionHdr->VirtualSize, SectionHdr->OnDiskSize);
#endif
    return LoadSectionFromFileEx(pImageFile,
                                 SectionHdr->SeekOffset,
                                 SectionHdr->OnDiskSize,
                                 SectionHdr->VirtualSize,
                                 pSection,
                                 pSectionSize);
}

BOOLEAN
LoadNewPESectionFromFile(
    IN FILE* pImageFile,
    IN PIMAGE_SECTION_HEADER SectionHdr,
    OUT PVOID* pSection,
    OUT PULONG pSectionSize OPTIONAL)
{
    return LoadSectionFromFileEx(pImageFile,
                                 SectionHdr->PointerToRawData,
                                 SectionHdr->SizeOfRawData,
                                 SectionHdr->Misc.VirtualSize,
                                 pSection,
                                 pSectionSize);
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
PVOID
LoadOldPEDirectoryEntryAndSection(
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
        if (ADDRESS_IN_REGION(DirectoryEntry->RVA,
                              ObjTable[i].RVA,
                              ObjTable[i].VirtualSize))
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
    if (!REGION_IN_REGION(DirectoryEntry->RVA,
                          DirectoryEntry->Size,
                          SectionHdr->RVA,
                          SectionSize))
    {
        /* Nope */
        return NULL;
    }

    /* Finally load the section */
    if (!LoadOldPESectionFromFile(pImageFile,
                                  SectionHdr,
                                  &Section,
                                  &SectionSize))
    {
        /* Fail - No need to display errors since
         * LoadOldPESectionFromFile() does that already. */
        return NULL;
    }
    ASSERT(Section);

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

PVOID
LoadNewPEDirectoryEntryAndSection(
    IN FILE* pImageFile,
    IN PIMAGE_NT_HEADERS32 NtHeader,
    IN USHORT Directory,
    OUT PVOID* DirectoryData,
    OUT PULONG Size OPTIONAL,
    OUT PIMAGE_SECTION_HEADER* pSectionHdr OPTIONAL,
    OUT PULONG pSectionSize OPTIONAL)
{
    PIMAGE_DATA_DIRECTORY DirectoryEntry;
    PIMAGE_SECTION_HEADER ObjTable = NULL;
    PIMAGE_SECTION_HEADER SectionHdr;
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

    if (Directory >= NtHeader->OptionalHeader.NumberOfRvaAndSizes)
        return NULL;

    DirectoryEntry = &NtHeader->OptionalHeader.DataDirectory[Directory];
    if (DirectoryEntry->VirtualAddress == 0)
        return NULL;
    if (DirectoryEntry->Size == 0)
        return NULL;

    /* Contrary to the old PE image header, the new PE header does not contain
     * an explicit ObjectTableRVA pointer; instead it is understood that, as soon
     * as NumberOfSections is non zero, there is an object/section table, that is
     * present just after the optional header. */
    if (NtHeader->FileHeader.NumberOfSections)
    {
        // ObjTable = IMAGE_FIRST_SECTION(NtHeader);
        ObjTable /*SectionTable*/ = RVA(&NtHeader->FileHeader + 1, NtHeader->FileHeader.SizeOfOptionalHeader);
    }
    else
    {
        /* No section available */
        return NULL;
    }

    /* Find its corresponding section */
    SectionHdr = NULL;
    for (i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i)
    {
        if (ADDRESS_IN_REGION(DirectoryEntry->VirtualAddress,
                              ObjTable[i].VirtualAddress,
                              ObjTable[i].Misc.VirtualSize))
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
    SectionSize = max(SectionHdr->Misc.VirtualSize, SectionHdr->SizeOfRawData);

    /* Sanity check: Check that the directory data is
     * fully contained in the section, otherwise bail out. */
    if (!REGION_IN_REGION(DirectoryEntry->VirtualAddress,
                          DirectoryEntry->Size,
                          SectionHdr->VirtualAddress,
                          SectionSize))
    {
        /* Nope */
        return NULL;
    }

    /* Finally load the section */
    if (!LoadNewPESectionFromFile(pImageFile,
                                  SectionHdr,
                                  &Section,
                                  &SectionSize))
    {
        /* Fail - No need to display errors since
         * LoadNewPESectionFromFile() does that already. */
        return NULL;
    }
    ASSERT(Section);

    /* The directory data points inside the section */
    ASSERT(SectionHdr->VirtualAddress <= DirectoryEntry->VirtualAddress);
    *DirectoryData = RVA(Section, DirectoryEntry->VirtualAddress - SectionHdr->VirtualAddress);
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
FlushSectionToFileEx(
    IN FILE* pImageFile,
    IN ULONG Offset,
    IN ULONG RawSize,
    IN PVOID Section)
{
    fseek(pImageFile, Offset, SEEK_SET);
    if (!fwrite(Section, RawSize, 1, pImageFile))
    {
        PrintError("Failed to write %lu bytes to destination file\n", RawSize);
        return FALSE;
    }
    fflush(pImageFile);
    return TRUE;
}

BOOLEAN
FlushOldPESectionToFile(
    IN FILE* pImageFile,
    IN PIMAGE_OBJECT_HEADER SectionHdr,
    IN PVOID Section)
{
    return FlushSectionToFileEx(pImageFile,
                                SectionHdr->SeekOffset,
                                SectionHdr->OnDiskSize,
                                Section);
}

BOOLEAN
FlushNewPESectionToFile(
    IN FILE* pImageFile,
    IN PIMAGE_SECTION_HEADER SectionHdr,
    IN PVOID Section)
{
    return FlushSectionToFileEx(pImageFile,
                                SectionHdr->PointerToRawData,
                                SectionHdr->SizeOfRawData,
                                Section);
}


BOOLEAN
FixupExportsSectionWorker(
    IN OUT PIMAGE_EXPORT_DIRECTORY ExportDirectory,
    IN ULONG DirectorySize,
    IN ULONG SectionRVA,
    IN ULONG SectionSize,
    IN PVOID Section,
    OUT PULONG_PTR pEndDirectory)
{
    PULONG NamesTable = NULL;
    size_t TableSize;
    ULONG_PTR EndData, EndDirectory;
    PSTR StringPtr;
    ULONG i;

    /* In old-PE style, these RVAs are from the beginning of the
     * export section. Convert them to RVAs from the base of the image. */
    ExportDirectory->Name += SectionRVA;
    ExportDirectory->AddressOfFunctions += SectionRVA;
    ExportDirectory->AddressOfNames += SectionRVA;
    ExportDirectory->AddressOfNameOrdinals += SectionRVA;

    TableSize = ExportDirectory->NumberOfNames * sizeof(ULONG);

    /* Sanity check: Check that the export function table is
     * fully contained in the section, otherwise bail out. */
    if (!REGION_IN_REGION(ExportDirectory->AddressOfNames,
                          TableSize,
                          SectionRVA,
                          SectionSize))
    {
        /* Nope */
        PrintWarning("WARNING: Could not load the export names table, ignoring...\n");
    }
    else
    {
        /* The export table points inside the export section */
        ASSERT(SectionRVA <= ExportDirectory->AddressOfNames);
        NamesTable = RVA(Section, ExportDirectory->AddressOfNames - SectionRVA);

        /* In old-PE style, these RVAs are from the beginning of the
         * export section. Convert them to RVAs from the base of the image. */
        for (i = 0; i < ExportDirectory->NumberOfNames; ++i)
        {
            NamesTable[i] += SectionRVA;
        }
    }

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
    if (DirectorySize != sizeof(IMAGE_EXPORT_DIRECTORY))
    {
        PrintWarning("WARNING: Unexpected old-PE EXPORT directory size %ld, expected %ld\n",
                     DirectorySize, (ULONG)sizeof(IMAGE_EXPORT_DIRECTORY));
    }
    /*
     * Re-calculate the size of the directory.
     * To do this we find/calculate the maximum possible RVA value
     * from all the data pointed by the directory.
     */
    EndDirectory = 0;

    /* AddressOfFunctions table */
    TableSize = ExportDirectory->NumberOfFunctions * sizeof(ULONG);
    EndData = ExportDirectory->AddressOfFunctions + TableSize;
    EndDirectory = max(EndDirectory, EndData);

    /* AddressOfNames table */
    TableSize = ExportDirectory->NumberOfNames * sizeof(ULONG);
    EndData = ExportDirectory->AddressOfNames + TableSize;
    EndDirectory = max(EndDirectory, EndData);

    /* AddressOfNameOrdinals table */
    EndData = ExportDirectory->AddressOfNameOrdinals + TableSize;
    EndDirectory = max(EndDirectory, EndData);

    /* Name string */
    StringPtr = RVA(Section, ExportDirectory->Name - SectionRVA);
    // strnlen(StringPtr, SectionSize - (ExportDirectory->Name - SectionRVA));
    EndData = ExportDirectory->Name + (strlen(StringPtr) + 1) * sizeof(CHAR);
    EndDirectory = max(EndDirectory, EndData);

    /* Browse the Names table */
    if (NamesTable)
    {
        for (i = 0; i < ExportDirectory->NumberOfNames; ++i)
        {
            StringPtr = RVA(Section, NamesTable[i] - SectionRVA);
            // strnlen(StringPtr, SectionSize - (NamesTable[i] - SectionRVA));
            EndData = NamesTable[i] + (strlen(StringPtr) + 1) * sizeof(CHAR);
            EndDirectory = max(EndDirectory, EndData);
        }
    }

    *pEndDirectory = EndDirectory;
    return TRUE;
}

BOOLEAN
FixupImportsSection(
    IN OUT PIMAGE_IMPORT_DESCRIPTOR ImportDirectory,
    IN ULONG DirectorySize,
    IN ULONG SectionRVA,
    IN ULONG SectionSize,
    IN PVOID Section)
{
    PIMAGE_IMPORT_DESCRIPTOR Import = ImportDirectory;
    PIMAGE_THUNK_DATA32 Thunk;

    for (; (/* (Import->Name != 0) && */ (Import->FirstThunk != 0) &&
           ((ULONG_PTR)Import - (ULONG_PTR)ImportDirectory < DirectorySize));
         ++Import)
    {
        /* In old-PE style, these RVAs are from the beginning of the
         * export section. Convert them to RVAs from the base of the image. */
        if (Import->Name)
            Import->Name += SectionRVA;

        /* Loop through the thunks as well */
        Thunk = RVA(Section, Import->FirstThunk - SectionRVA);
        for (; Thunk->u1.AddressOfData; ++Thunk)
        {
            Thunk->u1.AddressOfData += SectionRVA;
        }
    }
    /* Strangely enough, FirstThunk is OK, perhaps because it points into another section */

    return TRUE;
}

BOOLEAN
ReconstructSections(
    IN PIMAGE_HEADER NtHeader,
    IN PIMAGE_OBJECT_HEADER ObjTable, // Obtained from caller via the NtHeader.
    IN PIMAGE_EXPORT_DIRECTORY ExportDirectory OPTIONAL,
    IN PULONG ExportTable OPTIONAL,
    /* These two could be replaced by a single "IN PIMAGE_NT_HEADERS32 NtHeader" */
    IN PIMAGE_FILE_HEADER FileHeader,
    IN OUT PIMAGE_OPTIONAL_HEADER32 OptHeader,
    OUT PIMAGE_SECTION_HEADER* pSectionTable)
{
    /*
     * ObjTable[i].ObjectFlags:
     * 0x00000001: SCN_MEM_READ
     * 0x00000002: SCN_MEM_WRITE
     * 0x00000004: SCN_MEM_EXECUTE
     * 0x00020000: SCN_MEM_DISCARDABLE == IMAGE_SCN_MEM_PURGEABLE
     */

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

    *pSectionTable = NULL;

    OptHeader->BaseOfCode = ULONG_MAX; // Will be normalized later.
    OptHeader->SizeOfCode = 0;
    OptHeader->BaseOfData = ULONG_MAX; // Will be normalized later.
    OptHeader->SizeOfInitializedData   = 0;
    OptHeader->SizeOfUninitializedData = 0;

    if (!ObjTable)
        goto Quit;

    printf("Reconstructed Sections:\n"
           "=======================\n");

    SectionTable = RVA(FileHeader + 1, FileHeader->SizeOfOptionalHeader);
    *pSectionTable = SectionTable;

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
        // from ObjTable[i].ObjectFlags as well? --> See above.

        /* Is this section a possible .bss section? */
        if (ObjTable[i].VirtualSize == 0 || ObjTable[i].OnDiskSize == 0 /* || ObjTable[i].SeekOffset == 0 */)
        {
            SectionName     = SectionFlags[SECTION_FLAGS_BSS].SectionName;
            Characteristics = SectionFlags[SECTION_FLAGS_BSS].Characteristics;
        }
        /* Or a .text section, if the entry point is in it */
        else if (ADDRESS_IN_REGION(NtHeader->EntryPointRVA,
                                   ObjTable[i].RVA,
                                   ObjTable[i].VirtualSize))
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

                if (ADDRESS_IN_REGION(NtHeader->DataDirectory[j].RVA,
                                      ObjTable[i].RVA,
                                      ObjTable[i].VirtualSize))
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
            if (ExportDirectory && ExportTable)
            {
                ULONG Ordinal;
                for (Ordinal = 0; Ordinal < ExportDirectory->NumberOfFunctions; ++Ordinal)
                {
                    if (ADDRESS_IN_REGION(ExportTable[Ordinal],
                                          ObjTable[i].RVA,
                                          ObjTable[i].VirtualSize))
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

Quit:
    /* Normalize the bases if they couldn't have been determined above */
    if (OptHeader->BaseOfCode == ULONG_MAX)
    {
        OptHeader->BaseOfCode = 0;
        OptHeader->SizeOfCode = 0;
    }
    if (OptHeader->BaseOfData == ULONG_MAX)
    {
        OptHeader->BaseOfData = 0;
        OptHeader->SizeOfInitializedData   = 0;
        OptHeader->SizeOfUninitializedData = 0;
    }

    return TRUE;
}


VOID
PECheckSum()
{
    /*
     * TODO
     * See:
     * https://git.reactos.org/?p=reactos.git;a=blob;f=dll/win32/imagehlp/modify.c;h=66ab07e745b35986b3ab723b030924d6eb390ca7;hb=HEAD#l158
     * https://bytepointer.com/resources/microsoft_pe_checksum_algo_distilled.htm
     * https://www.codeproject.com/Articles/19326/An-Analysis-of-the-Windows-PE-Checksum-Algorithm
     * https://practicalsecurityanalytics.com/pe-checksum/
     * https://github.com/mrexodia/portable-executable-library/blob/master/pe_lib/pe_checksum.cpp
     */
}
