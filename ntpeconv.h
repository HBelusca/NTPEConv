/*
 * PROJECT:     PE Converter for NT PDK v1.196 (September 1991) and PDK October 1991
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Old PE Format Type definitions used in NT PDK v1.196.
 * COPYRIGHT:   Copyright 2021 Hermès Bélusca-Maïto
 *
 * These definitions have been extracted from the
 * embedded debug symbols in the \I386\DEBUG\I386KD.EXE
 * executable of the NT PDK v1.196 release.
 */

#ifndef _NTPECONV_H_
#define _NTPECONV_H_

#pragma once

/* Copyright information */
#define PROGNAME        "NTPECONV"
#define VERSION         "0.9a2"
#define COPYRIGHT_YEARS "2021"


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

extern PCSTR Errors[ErrorTypeMax + 1];

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

#endif /* _NTPECONV_H_ */
