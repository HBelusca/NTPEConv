/*
 * PROJECT:     PE Converter for NT PDK v1.196 (September 1991) and PDK October 1991
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Helper functions for the old and new PE formats.
 * COPYRIGHT:   Copyright 2021-2022 Hermès Bélusca-Maïto
 */

#ifndef _PEHLP_H_
#define _PEHLP_H_

#pragma once

#define RVA(b, m) ((PVOID)((ULONG_PTR)(b) + (ULONG_PTR)(m)))

/**
 * @brief   Checks whether Value is in the range [Start; End[.
 **/
#define VALUE_IN_RANGE(Value, Start, End) \
    ( ((Start) <= (Value)) && ((Value) < (End)) )

 /**
  * @brief   Checks whether the region [RgnStart; RgnStart + RgnSize]
  *          is fully contained in the range [Start; End].
  **/
#define REGION_IN_RANGE(RgnStart, RgnSize, Start, End) \
    ( ((Start) <= (RgnStart)) && ((RgnStart) + (RgnSize) <= (End)) )

/**
 * @brief   Checks whether Addr is in the range [Start; End[.
 **/
#define ADDRESS_IN_RANGE(Addr, Start, End) \
    VALUE_IN_RANGE((ULONG_PTR)(Addr), (ULONG_PTR)(Start), (ULONG_PTR)(End))

/**
 * @brief   Checks whether Addr is in the range [Start; Start + Size[.
 **/
#define ADDRESS_IN_REGION(Addr, Start, Size) \
    VALUE_IN_RANGE((ULONG_PTR)(Addr), (ULONG_PTR)(Start), (ULONG_PTR)(Start) + (Size))

/**
 * @brief   Checks whether the region [RgnAddr; RgnAddr + RgnSize]
 *          is fully contained in the region [Start; Start + Size].
 **/
#define REGION_IN_REGION(RgnAddr, RgnSize, Start, Size) \
    REGION_IN_RANGE((ULONG_PTR)(RgnAddr), RgnSize, \
                    (ULONG_PTR)(Start), (ULONG_PTR)(Start) + (Size))


BOOLEAN
LoadOldPESectionFromFile(
    IN FILE* pImageFile,
    IN PIMAGE_OBJECT_HEADER SectionHdr,
    OUT PVOID* pSection,
    OUT PULONG pSectionSize OPTIONAL);

BOOLEAN
LoadNewPESectionFromFile(
    IN FILE* pImageFile,
    IN PIMAGE_SECTION_HEADER SectionHdr,
    OUT PVOID* pSection,
    OUT PULONG pSectionSize OPTIONAL);

PVOID
LoadOldPEDirectoryEntryAndSection(
    IN FILE* pImageFile,
    IN PIMAGE_HEADER NtHeader,
    IN USHORT Directory,
    OUT PVOID* DirectoryData,
    OUT PULONG Size OPTIONAL,
    OUT PIMAGE_OBJECT_HEADER* pSectionHdr OPTIONAL,
    OUT PULONG pSectionSize OPTIONAL);

PVOID
LoadNewPEDirectoryEntryAndSection(
    IN FILE* pImageFile,
    IN PIMAGE_NT_HEADERS32 NtHeader,
    IN USHORT Directory,
    OUT PVOID* DirectoryData,
    OUT PULONG Size OPTIONAL,
    OUT PIMAGE_SECTION_HEADER* pSectionHdr OPTIONAL,
    OUT PULONG pSectionSize OPTIONAL);

BOOLEAN
FlushOldPESectionToFile(
    IN FILE* pImageFile,
    IN PIMAGE_OBJECT_HEADER SectionHdr,
    IN PVOID Section);

BOOLEAN
FlushNewPESectionToFile(
    IN FILE* pImageFile,
    IN PIMAGE_SECTION_HEADER SectionHdr,
    IN PVOID Section);


BOOLEAN
FixupExportsSectionWorker(
    IN OUT PIMAGE_EXPORT_DIRECTORY ExportDirectory,
    IN ULONG DirectorySize,
    IN ULONG SectionRVA,
    IN ULONG SectionSize,
    IN PVOID Section,
    OUT PULONG_PTR pEndDirectory);

BOOLEAN
FixupImportsSection(
    IN OUT PIMAGE_IMPORT_DESCRIPTOR ImportDirectory,
    IN ULONG DirectorySize,
    IN ULONG SectionRVA,
    IN ULONG SectionSize,
    IN PVOID Section);

BOOLEAN
ReconstructSections(
    IN PIMAGE_HEADER NtHeader,
    IN PIMAGE_OBJECT_HEADER ObjTable, // Obtained from caller via the NtHeader.
    IN PIMAGE_EXPORT_DIRECTORY ExportDirectory OPTIONAL,
    IN PULONG ExportTable OPTIONAL,
    /* These two could be replaced by a single "IN PIMAGE_NT_HEADERS32 NtHeader" */
    IN PIMAGE_FILE_HEADER FileHeader,
    IN OUT PIMAGE_OPTIONAL_HEADER32 OptHeader,
    OUT PIMAGE_SECTION_HEADER* pSectionTable);

#endif /* _PEHLP_H_ */
