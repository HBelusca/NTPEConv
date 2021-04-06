# The "Old" PE Executable Format of NT PDK v1.196 (September 1991)

Revision 0.8 &ndash; 6th April 2021 \
_Copyright 2021 Hermès Bélusca-Maïto_

---

<!-- ## Table of Contents -->
<details open="open">
<summary>
<h2 style="display:inline">Table of Contents</h2>
</summary>

1. [DOS_IMAGE_HEADER](#dos_image_header)
2. [IMAGE_HEADER](#image_header)
   - [Members](#image_header-members)
3. [IMAGE_SPECIAL_DIRECTORY](#image_special_directory)
   - [Members](#image_special_directory-members)
4. [IMAGE_OBJECT_HEADER](#image_object_header)
   - [Members](#image_object_header-members)
5. [The PE Data Directories and Its Sections](#pe_data_directories_sections)
   1. [The .edata Section, and the Export Directory](#.edata_export)
   2. [The .idata Section, and the Import Directory](#.idata_import)
   3. [The .rsrc Section, and the Resource Directory](#.rsrc_resource)
   4. [The .pdata Section, and the Exception Directory](#.pdata_exception)
   5. [The Security Directory](#.security)
   6. [The .reloc Section, and the Base Relocations Directory](#.reloc_relocation)
   7. [The .debug Section, and the Debug Data Directory](#.debug_debugdata)

</details>

---

The definitions of the following structures have been extracted from the
embedded debug symbols in the OS/2 build of the
<img align="middle" alt="I386KD.ICO" src="doc/images/I386KD_32.bmp">
`\I386\DEBUG\I386KD.EXE` executable of the NT PDK v1.196 release.
They can also be found in the `\MSTOOLS\BIN\OS2\COFF.EXE` executable
of the same release.

_<u>TODO:</u> Write a paragraph about comparison of COFF.EXE symbols from
I386, MIPS and OS2 subrepos. In particular, only the OS2 version has this
old-school PE stuff (and not the new-PE format with `IMAGE_OPTIONAL_HEADER`
etc.), while the MIPS has only the new-PE format stuff (and not the old-PE one).
The I386 COFF.EXE doesn't have any symbols with which to compare._

## DOS_IMAGE_HEADER

This corresponds to the usual [`IMAGE_DOS_HEADER`][image_dos_header.link],
but using its "legacy" name.

```c
typedef struct _IMAGE_DOS_HEADER
               _DOS_IMAGE_HEADER, DOS_IMAGE_HEADER, *PDOS_IMAGE_HEADER;
```

The DOS header's `e_lfanew` field is the offset from the beginning of the file
to the image's [PE header](#image_header).
The usual [MS-DOS stub](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#ms-dos-stub-image-only)
follows the DOS header.


## IMAGE_HEADER

This is the old PE header used in the earliest builds of Microsoft(R) NT, that
has been replaced around the [PDK October 1991](https://betawiki.net/wiki/Windows_NT_3.1_October_1991_build)
with the newer customary PE headers.
_(This can be observed by the fact the provided MS build tools are compiled
using this newer format.)_
The contents of this header roughly covers a combination of
[`IMAGE_NT_HEADERS`][image_nt_headers.msdn.link],
[`IMAGE_FILE_HEADER`][image_file_header.msdn.link]
and
[`IMAGE_OPTIONAL_HEADER`][image_optional_header.msdn.link].

```c
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

#define IMAGE_NUMBEROF_SPECIAL_DIRECTORY_ENTRIES 7
    IMAGE_SPECIAL_DIRECTORY
           DataDirectory[IMAGE_NUMBEROF_SPECIAL_DIRECTORY_ENTRIES];
} IMAGE_HEADER, *PIMAGE_HEADER;
```

The object/section table is stored usually just following this structure (and
the data directories), and the number of sections is given by `NumberOfbjects`.
It is also referenced by the `ObjectTableRVA` member.
_Note that in the new PE format, this table is systematically stored just after
the PE optional header and therefore, does not need an explicit RVA pointer._

<!-- ### Members -->
<details open="open">
<summary>
<h3 style="display:inline" id="image_header-members">
Members
</h3>
</summary>

`SignatureBytes`

A 4-byte signature identifying the file as a PE image. The bytes are `'PE\0\0'`.

`Endian`

A 1-byte value indicating the endianness of the CPU expected by this image.

Since the only publicly available PE images using the old PE format are for
the Intel x86 CPU, **it is supposed that 0 means little endian, while any
other value (or 1) means big endian**.
PE images for other CPUs are available only in later public builds, e.g. the
October 1991, but only use the newer PE format.

`Reserved1`

Reserved field.

`CPUType`

A 2-byte value indicating the expected CPU type for this image.

Since the only publicly available PE images using the old PE format are for
the Intel x86 CPU, **it is supposed that 1 means Intel i860, 2 means Intel i386
and 3 means MIPS R4000, while any other value is presently unknown**.
PE images for other CPUs are available only in later public builds, e.g. the
October 1991, but only use the newer PE format.

`OSType`

A 2-byte value supposedly indicating the expected OS type for this image.
It appears to be always equal to 4.

`SubSystem`

A 2-byte value indicating which NT subsystem is required to run this image.

These values match those mapped from the `SubSystemType=` option in the
CSRSS command line (and stored in the `CsrSubSystemType` variable).
Compare them with the `IMAGE_SUBSYSTEM_xxx` values of the newer
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

Note also that there is no distinction in this value between Windows GUI and
CUI subsystems; the difference is made via flags set in the `ModuleFlags` value.

The following values are defined.

<table>
<thead>
<tr>
<th align="left">Value</th>
<th align="left">Meaning</th>
</tr>
</thead>
<tbody>

<tr>
<td align="left" valign="top">
<b><code>OLD_IMAGE_SUBSYSTEM_UNKNOWN</code></b><br>
0
</td>
<td align="left" valign="top">
Unknown subsystem.
</td>
</tr>

<tr>
<td align="left" valign="top">
<b><code>OLD_IMAGE_SUBSYSTEM_OS2</code></b><br>
1
</td>
<td align="left" valign="top">
OS/2 CUI subsystem.
</td>
</tr>

<tr>
<td align="left" valign="top">
<b><code>OLD_IMAGE_SUBSYSTEM_WINDOWS</code></b><br>
2
</td>
<td align="left" valign="top">
Windows subsystem (GUI or CUI).
</td>
</tr>

<tr>
<td colspan="2">
<i>Value 3 is undefined.</i>
</td>
</tr>

<tr>
<td align="left" valign="top">
<b><code>OLD_IMAGE_SUBSYSTEM_NATIVE</code></b><br>
4
</td>
<td align="left" valign="top">
No subsystem required (device drivers and native system processes).
</td>
</tr>

<tr>
<td align="left" valign="top">
<b><code>OLD_IMAGE_SUBSYSTEM_POSIX</code></b><br>
5
</td>
<td align="left" valign="top">
POSIX CUI subsystem.
</td>
</tr>

</tbody>
</table>


`OSMajor`

The major version number of the required operating system.

Corresponds to the `MajorOperatingSystemVersion` field of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

`OSMinor`

The minor version number of the required operating system.

Corresponds to the `MinorOperatingSystemVersion` field of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

`LinkerMajor`

The major version number of the linker. Only the low byte of this value is used.

Corresponds to the `MajorLinkerVersion` field of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

`LinkerMinor`

The minor version number of the linker. Only the low byte of this value is used.

Corresponds to the `MinorLinkerVersion` field of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

`UserMajor`

The major version number of the image.

Corresponds to the `MajorImageVersion` field of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

`UserMinor`

The minor version number of the image.

Corresponds to the `MinorImageVersion` field of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

`ModuleFlags`

A 4-byte field containing flags describing some aspects of the image file.
Known values are defined below.

<table>
<thead>
<tr>
<th align="left">Value</th>
<th align="left">Meaning</th>
</tr>
</thead>
<tbody>

<tr>
<td align="left" valign="top">
0x0100
</td>
<td align="left" valign="top">
Unknown. Must <b>not</b> be set if the image runs with the Windows CUI subsystem.
This flag is set, together with the flag 0x0200, when the image runs with the
Windows GUI subsystem.
</td>
</tr>

<tr>
<td align="left" valign="top">
0x0200
</td>
<td align="left" valign="top">
When set alone without flags 0x0100 and 0x0400, the image runs with the
Windows CUI subsystem:
this is what <code>CONSOLE.dll:ConsoleApp()</code> (called from
<code>CONSOLE.dll:ConDllInitialization()</code>)
and <code>NTDLL.dll:RtlImageType()</code> check for.
Otherwise, when the flag 0x0100 is set, the image runs with the
Windows GUI subsystem.
</td>
</tr>

<tr>
<td align="left" valign="top">
0x0400
</td>
<td align="left" valign="top">
Unknown. Must <b>not</b> be set if the image runs with the Windows CUI subsystem.
</td>
</tr>

<tr>
<td align="left" valign="top">
0x8000
</td>
<td align="left" valign="top">

The image is a DLL file. While it is an executable file,
it cannot be run directly.\
Corresponds to the `IMAGE_FILE_DLL` flag in the `Characteristics` field of the
[`IMAGE_FILE_HEADER`][image_file_header.msdn.link] structure.

</td>
</tr>

<tr>
<td align="left" valign="top">
0x20000000
</td>
<td align="left" valign="top">
Unknown; always set in NT PDK images.
</td>
</tr>

<tr>
<td align="left" valign="top">
0x80000000
</td>
<td align="left" valign="top">
Unknown; always set in NT PDK images.
</td>
</tr>

</tbody>
</table>


`Reserved2`

Reserved field.

`FileCheckSum`

The PE image file checksum.
Images from the old NT PDK builds always have this value set to zero.

`EntryPointRVA`

The address of the entry point function, relative to the image base address,
when the executable file is loaded into memory.
For executable files, this is the starting address. For device drivers, this
is the address of the initialization function. The entry point function is
optional for DLLs. When no entry point is present, this member is zero.

Corresponds to the `AddressOfEntryPoint` field of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

`ImageBase`

The preferred address of the first byte of the image when it is loaded in memory.
This value is a multiple of 64K bytes.

`ImageSize`

The size (in bytes) of the image, including all headers, as the image is loaded in memory.
It must be a multiple of `PageSize`.

Corresponds to the `SizeOfImage` field of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

`HeaderSize`

The combined size of the MS-DOS header and MS-DOS stub, the PE header,
and the section headers:
- the `e_lfanew` member of [`DOS_IMAGE_HEADER`](#dos_image_header),
- the size of [`IMAGE_HEADER`](#image_header) up to (but excluding)
  `DataDirectory`,
- the actual size of all the directory entries, whose number is specified
  by `NumberOfSpecialRVAs`,
- and the actual size of all the section headers, whose number is specified
  by `NumberOfObjects`.

Contrary to the case of the new PE format, the old PE format does not
round it up to a multiple of `FileAlign`.

Corresponds to the `SizeOfHeaders` field of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

`FileAlign`

The alignment (in bytes) of the raw data of sections in the image file.
The value should be a power of 2 between 512 and 64K (inclusive).
The default is 512. If the `PageSize` member is less than the system
page size, this member must be the same as `PageSize`.

Corresponds to the `FileAlignment` field of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

`PageSize`

The alignment (in bytes) of sections loaded in memory. This value must be
greater than or equal to the `FileAlign` member. The default value is the
page size for the system.

Corresponds to the `SectionAlignment` field of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

`TimeStamp`

The low 32 bits of the time stamp of the image. This represents the date and
time the image was created by the linker. The value is represented in the
number of seconds elapsed since midnight (00:00:00), January 1, 1970,
Universal Coordinated Time, according to the system clock.

Corresponds to the `TimeDateStamp` field of the
[`IMAGE_FILE_HEADER`][image_file_header.msdn.link] structure.

`StackReserve`

The size (in bytes) of the stack to reserve. Only the memory specified by the
`StackCommit` member is committed at load time; the rest is made available
one page at a time until this reserve size is reached.

Corresponds to the `SizeOfStackReserve` field of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

`StackCommit`

The size (in bytes) of the stack to commit.

Corresponds to the `SizeOfStackCommit` field of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

`HeapReserve`

The size (in bytes) of the local heap space to reserve. Only the memory specified
by the `HeapCommit` member is committed at load time; the rest is made available
one page at a time until this reserve size is reached.

Corresponds to the `SizeOfHeapReserve` field of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

`HeapCommit`

The size (in bytes) of the local heap space to commit.

Corresponds to the `SizeOfHeapCommit` field of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

`NumberOfObjects`

The number of sections, stored as a 4-byte value, but whose lower 16 bits
only are valid.
This indicates the size of the section table, pointed at by `ObjectTableRVA`
but that usually immediately follows the headers.
Note that the Windows loader limits the number of sections to 96.

Corresponds to the 2-byte `NumberOfSections` field of the
[`IMAGE_FILE_HEADER`][image_file_header.msdn.link] structure.

`ObjectTableRVA`

The address of the section headers table, relative to the image base address,
when the executable file is loaded into memory.

Contrary to the old PE image format, there is no equivalent of the `ObjectTableRVA`
member in the new PE format. Instead, when the number of sections is non zero,
the object/section table is stored just after the PE optional header.

`NumberOfDirectives`

Reserved; for PE images, this value must be zero.

`DirectiveTableRVA`

Reserved; for PE images, this value must be zero.

`Reserved3`\
`Reserved4`\
`Reserved5`

Reserved fields.

`NumberOfSpecialRVAs`

The number of directory entries in the remainder of the PE image header.
Each entry describes a location and size.

A maximum of 7 `IMAGE_NUMBEROF_SPECIAL_DIRECTORY_ENTRIES` entries is supported.

Corresponds to the `NumberOfRvaAndSizes` field of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

`DataDirectory`

An array of [`IMAGE_SPECIAL_DIRECTORY`](#image_special_directory) structures, whose actual number
is given by the `NumberOfSpecialRVAs` member.

Corresponds to the `DataDirectory` array of the
[`IMAGE_OPTIONAL_HEADER`][image_optional_header_members.msdn.link]
structure.

These data directory entries are all loaded into memory so that the system
can use them at run time. A data directory is an 8-byte field that has the
following declaration, fully compatible with the newer
[`IMAGE_DATA_DIRECTORY`][image_data_directory.msdn.link] structure:
```c
typedef struct _IMAGE_SPECIAL_DIRECTORY
{
    ULONG RVA;
    ULONG Size;
} IMAGE_SPECIAL_DIRECTORY, *PIMAGE_SPECIAL_DIRECTORY;
```

The first field, `RVA`, is the relative virtual address (RVA) of the table.
The RVA is the address of the table relative to the base address of the image
when the table is loaded.

The second field, `Size`, gives the size (in bytes) of the table.

The data directories are indexed in the following order.

<table>
<thead>
<tr>
<th align="left">Value</th>
<th align="left">Meaning</th>
</tr>
</thead>
<tbody>

<tr>
<td align="left" valign="top">
<b><code>IMAGE_DIRECTORY_ENTRY_EXPORT</code></b><br>
0
</td>
<td align="left" valign="top">

The Export directory. For more information see
[`The .edata Section`](#.edata_export).

</td>
</tr>

<tr>
<td align="left" valign="top">
<b><code>IMAGE_DIRECTORY_ENTRY_IMPORT</code></b><br>
1
</td>
<td align="left" valign="top">

The Import directory. For more information see
[`The .idata Section`](#.idata_import).

</td>
</tr>

<tr>
<td align="left" valign="top">
<b><code>IMAGE_DIRECTORY_ENTRY_RESOURCE</code></b><br>
2
</td>
<td align="left" valign="top">

The Resource directory. For more information see
[`The .rsrc Section`](#.rsrc_resource).

</td>
</tr>

<tr>
<td align="left" valign="top">
<b><code>IMAGE_DIRECTORY_ENTRY_EXCEPTION</code></b><br>
3
</td>
<td align="left" valign="top">

The Exception directory. Unused for Intel x86 images.
For more information see
[`The .pdata Section`](#.pdata_exception).

</td>
</tr>

<tr>
<td align="left" valign="top">
<b><code>IMAGE_DIRECTORY_ENTRY_SECURITY</code></b><br>
4
</td>
<td align="left" valign="top">

The Security directory,containing the attribute certificate table.
For more information see <!-- (#.security) -->
[`The Attribute Certificate Table (Image Only)`](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only).

</td>
</tr>

<tr>
<td align="left" valign="top">
<b><code>IMAGE_DIRECTORY_ENTRY_BASERELOC</code></b><br>
5
</td>
<td align="left" valign="top">

The Base Relocations directory. For more information see
[`The .reloc Section`](#.reloc_relocation).

</td>
</tr>

<tr>
<td align="left" valign="top">
<b><code>IMAGE_DIRECTORY_ENTRY_DEBUG</code></b><br>
6
</td>
<td align="left" valign="top">

The Debug data directory. For more information see
[`The .debug Section`](#.debug_debugdata).

</td>
</tr>

</tbody>
</table>

<!-- Members -->
</details>


## IMAGE_SPECIAL_DIRECTORY

These data directory entries are all loaded into memory so that the system
can use them at run time. A data directory is an 8-byte field that has the
following declaration, fully compatible with the newer
[`IMAGE_DATA_DIRECTORY`][image_data_directory.msdn.link] structure:

```c
typedef struct _IMAGE_SPECIAL_DIRECTORY
{
    ULONG RVA;
    ULONG Size;
} IMAGE_SPECIAL_DIRECTORY, *PIMAGE_SPECIAL_DIRECTORY;
```

<!-- ### Members -->
<details open="open">
<summary>
<h3 style="display:inline" id="image_special_directory-members">
Members
</h3>
</summary>

`RVA`

The relative virtual address (RVA) of the table.
The RVA is the address of the table relative to the base address of the image
when the table is loaded.

`Size`

The size (in bytes) of the table.

<!-- Members -->
</details>


## IMAGE_OBJECT_HEADER

This structure is an old version of the newer
[`IMAGE_SECTION_HEADER`][image_section_header.msdn.link].
One of the main differences, is the absence of the section `Name` field.
Therefore, all the sections of an old PE image are stored nameless, and
the only way to find a given section is through its characteristics,
and/or assuming a pre-determined ordering in the image.

```c
typedef struct _IMAGE_OBJECT_HEADER
{
    ULONG RVA;
    ULONG VirtualSize;
    ULONG SeekOffset;
    ULONG OnDiskSize;
    ULONG ObjectFlags;
    ULONG Reserved;
} IMAGE_OBJECT_HEADER, *PIMAGE_OBJECT_HEADER;
```

<!-- ### Members -->
<details open="open">
<summary>
<h3 style="display:inline" id="image_object_header-members">
Members
</h3>
</summary>

`RVA`

The address of the first byte of the section, relative to the image base,
when the executable file is loaded into memory.

Corresponds to the `VirtualAddress` field of the
[`IMAGE_SECTION_HEADER`][image_section_header.msdn.link]
structure.

`VirtualSize`

The total size (in bytes) of the section when loaded into memory. If this
value is greater than the `OnDiskSize` member, the section is filled
with zeroes.

Corresponds to the `Misc.VirtualSize` field of the
[`IMAGE_SECTION_HEADER`][image_section_header.msdn.link]
structure.

`SeekOffset`

A file pointer to the first page within the executable image. This value
must be a multiple of the `FileAlign` member of the [`IMAGE_HEADER`](#image_header)
structure.
If a section contains only uninitialized data, set this member is zero.

Corresponds to the `PointerToRawData` field of the
[`IMAGE_SECTION_HEADER`][image_section_header.msdn.link]
structure.

`OnDiskSize`

The size (in bytes) of the initialized data on disk. This value must be 
a multiple of the `FileAlign` member of the [`IMAGE_HEADER`](#image_header)
structure.
If this value is less than the `VirtualSize` member, the remainder of the
section is filled with zeroes. If the section contains only uninitialized
data, the member is zero.

Corresponds to the `SizeOfRawData` field of the
[`IMAGE_SECTION_HEADER`][image_section_header.msdn.link]
structure.

`ObjectFlags`

The characteristics of the section.
Roughly corresponds to the `Characteristics` field of the
[`IMAGE_SECTION_HEADER`][image_section_header.msdn.link]
structure, but with different values.

The following values are defined.

<table>
<thead>
<tr>
<th align="left">Value</th>
<th align="left">Meaning</th>
</tr>
</thead>
<tbody>

<tr>
<td align="left" valign="top">
<b><code>SCN_MEM_READ</code></b><br>
0x00000001
</td>
<td align="left" valign="top">
The section can be read.
Similar in meaning to the newer <code>IMAGE_SCN_MEM_READ</code>.
</td>
</tr>

<tr>
<td align="left" valign="top">
<b><code>SCN_MEM_WRITE</code></b><br>
0x00000002
</td>
<td align="left" valign="top">
The section can be written to.
Similar in meaning to the newer <code>IMAGE_SCN_MEM_WRITE</code>.
</td>
</tr>

<tr>
<td align="left" valign="top">
<b><code>SCN_MEM_EXECUTE</code></b><br>
0x00000004
</td>
<td align="left" valign="top">
The section can be executed as code.
Similar in meaning to the newer <code>IMAGE_SCN_MEM_EXECUTE</code>.
</td>
</tr>

<tr>
<td align="left" valign="top">
<b><code>SCN_MEM_DISCARDABLE</code></b><br>
0x00020000
</td>
<td align="left" valign="top">
The section can be discarded as needed.
Similar in meaning to the newer <code>IMAGE_SCN_MEM_DISCARDABLE</code>,
but uses the same value as <code>IMAGE_SCN_MEM_PURGEABLE</code>.
</td>
</tr>

</tbody>
</table>


`Reserved`

Reserved field.

<!-- Members -->
</details>


## The PE Data Directories and Its Sections<a id="pe_data_directories_sections"></a>

As a generic observation, the format of the different data directories in the
old PE format is mostly the same as in the newer PE format, however with some
subtle exceptions.

### The .edata Section, and the Export Directory<a id=".edata_export"></a>

The .edata section contains information about the symbols the PE image
exports, that can be accessed with dynamic linking by other PE images.

For more information see
[`The .edata Section (Image Only)`](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-edata-section-image-only).

The exports information is described by the Export Directory table,
described by the
[`IMAGE_EXPORT_DIRECTORY`](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table)
structure, and has the very same format as in the newer PE format, with the
exception of how some of its elements are encoded, see below.

```c
typedef struct _IMAGE_EXPORT_DIRECTORY
{
    ULONG  Characteristics;
    ULONG  TimeDateStamp;
    USHORT MajorVersion;
    USHORT MinorVersion;
    ULONG  Name;                   // RVA from base of image (newer PE format)
    ULONG  Base;
    ULONG  NumberOfFunctions;
    ULONG  NumberOfNames;
    ULONG  AddressOfFunctions;     // RVA from base of image (newer PE format)
    ULONG  AddressOfNames;         // RVA from base of image (newer PE format)
    ULONG  AddressOfNameOrdinals;  // RVA from base of image (newer PE format)
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

The differences in the storing of some of the data, between the old PE format
and the newer PE format, are as follows.

- In the old PE format, the `Name`, `AddressOfFunctions`, `AddressOfNames`
  and `AddressOfNameOrdinals` members are _offsets_ from the beginning of
  the Export section. In the newer PE format, they become _relative virtual
  addresses (RVA)_, relative to the base address of the image.

- In the old PE format, the values stored in the exports Names table are also
  _offsets_ from the beginning of the Export section. In the newer PE format,
  they become _RVA_'s, relative to the base address of the image.
  The other tables remain unchanged.

- In the old PE format, the reported size of the export directory (in
  `DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size`) is only the size
  of the directory itself, i.e. `sizeof(IMAGE_EXPORT_DIRECTORY)`.
  The newer PE format still reports such size; however, between NT versions
  1.340 (October 1992) and 1.404 (March 1993), this has changed and the
  reported size now counts the size of the directory `IMAGE_EXPORT_DIRECTORY`,
  **plus** the size of all the data from the tables, including the contents
  of the `Names` table and the `Name` string, aligned to 4 bytes.

  It should be noted that without the new size, some modern tools (e.g. IDA)
  will complain about the number of reported exports _versus_ some "limit"
  calculated via the reported export directory size.

### The .idata Section, and the Import Directory<a id=".idata_import"></a>

The .idata section contains information about the symbols the PE image imports
from other PE images.

For more information see
[`The .idata Section`](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-idata-section).

The imports information is described by the Import Directory table,
described by an array of
[`IMAGE_IMPORT_DESCRIPTOR`](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table)
structures, whose number is determined from the reported size of the
import directory (in `DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size`),
and have the very same format as in the newer PE format, with the exception
of how some of its elements are encoded, see below.

```c
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
    ULONG FirstThunk;   // RVA of the first IMAGE_THUNK_DATA
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_THUNK_DATA
{
    union
    {
        ULONG ForwarderString;
        ULONG Function;
        ULONG Ordinal;
        ULONG AddressOfData;
    } u1;
} IMAGE_THUNK_DATA, *PIMAGE_THUNK_DATA;
```

The differences in the storing of some of the data, between the old PE format
and the newer PE format, are as follows.

- In the old PE format, the `Name` member is an _offset_ from the beginning of
  the Import section. In the newer PE format, it becomes a _relative virtual
  address (RVA)_, relative to the base address of the image.

  Note that the `FirstThunk` member is always an RVA in any PE format.

- In the old PE format, the data stored in the `IMAGE_THUNK_DATA` union,
  e.g. the `AddressOfData` member, are _offsets_ from the beginning of
  the Export section. In the newer PE format, they become _relative virtual
  addresses (RVA)_, relative to the base address of the image.

### The .rsrc Section, and the Resource Directory<a id=".rsrc_resource"></a>

The Resource directory. For more information see
[`The .rsrc Section`](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section).

_n/a_

### The .pdata Section, and the Exception Directory<a id=".pdata_exception"></a>

The Exception directory. Unused for Intel x86 images.
For more information see
[`The .pdata Section`](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-pdata-section).

_n/a_

### The Security Directory<a id=".security"></a>

The Security directory,containing the attribute certificate table.
For more information see
[`The Attribute Certificate Table (Image Only)`](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only).

_n/a_

### The .reloc Section, and the Base Relocations Directory<a id=".reloc_relocation"></a>

The Base Relocations directory. For more information see
[`The .reloc Section (Image Only)`](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only).

_n/a_

### The .debug Section, and the Debug Data Directory<a id=".debug_debugdata"></a>

The .debug section is used in image files to contain all of the debug
information that is generated by the compiler and the linker.
A .debug section exists only when debug information needs to be mapped
in the address space; this is determined by the linker. (The default
for the linker is that debug information is not mapped in the image's
address space.)

Image files contain an optional debug directory that indicates what form of
debug information is present and where it is. This directory consists of an
array of debug directory entries whose location and size are indicated by
the `DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]` entry.

Contrary to the other data directories, the debug directory can be anywhere
in the image: it can be in a discardable .debug section (if one exists), or
it can be included in any other section in the image file, or not be in a
section at all.

For more information see
[`The .debug Section`](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-debug-section).

In the old PE format
**_as well as in the newer PE format of some next NT builds &ndash; which ones exactly??_**,
the format of the debug directory is not the one used in the newer PE format
(i.e. a
[`IMAGE_DEBUG_DIRECTORY`](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_debug_directory)
structure), that contains the actual type of debug information, but instead,
this debug information is assumed to always be of COFF type, and thus an
older `COFF_DEBUG_DIRECTORY` structure is used instead.

```c
typedef struct _COFF_DEBUG_DIRECTORY
{
    ULONG Characteristics;
    ULONG VersionStamp;
    ULONG SizeOfData;
    ULONG Type;
    ULONG AddressOfRawData;
    ULONG PointerToRawData;
} COFF_DEBUG_DIRECTORY, *PCOFF_DEBUG_DIRECTORY;
```

This structure differs from the newer `IMAGE_DEBUG_DIRECTORY` by the omission
of the `MajorVersion` and `MinorVersion` fields, and the `SizeOfData` and
`Type` members have been exchanged.


<!--
 --- External links
 -->

[image_dos_header.link]:            https://www.nirsoft.net/kernel_struct/vista/IMAGE_DOS_HEADER.html
[ms-dos_stub.msdn.link]:            https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#ms-dos-stub-image-only
[image_nt_headers.msdn.link]:       https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32
[image_file_header.msdn.link]:      https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
[image_optional_header.msdn.link]:  https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
[image_optional_header_members.msdn.link]:  https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32#members
[image_data_directory.msdn.link]:   https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory
[image_section_header.msdn.link]:   https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header

<!-- Others that may be of interest for later...
 ---

http://bytepointer.com/resources/kath_pe_top_to_bottom.htm
http://bytepointer.com/resources/plachy_pe_file_format.htm

-->
