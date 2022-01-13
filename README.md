<img align="left" alt="NT OS/2" src="doc/images/NTOS2.bmp">

# NTPEConv

Copyright 2021-2022 Hermès Bélusca-Maïto, under the [GPL-2.0+](https://spdx.org/licenses/GPL-2.0+) license.

<!--
<p align="center">
<img alt="NT OS/2" src="doc/images/NTOS2.bmp">
</p>
-->

Converts executable images from the old PE format used by
Microsoft(R) [NT PDK v1.196 (September 1991)](https://betawiki.net/wiki/Windows_NT_3.1_build_196)
and [PDK October 1991](https://betawiki.net/wiki/Windows_NT_3.1_October_1991_build)
to a newer PE format that can be recognized by modern tools.

Please consult the [documentation](doc_format.md) for a detailed description of this old PE format.

## Usage

```
Usage: NTPECONV [options] source_file [dest_file]

Options:
    -n, --nologo    Remove the banner.
    -v, --verbose   Display file information when processing.
    -t, --test      Process the source file without actually generating
                    an output file.
    -?, --help      Display this help message.
```
