/*******************************************************************************
 *
 * Module Name: utstring - Common functions for strings and characters
 *
 ******************************************************************************/

/*
 * Copyright (C) 2000 - 2013, Intel Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 */

#include <acpi/acpi.h>
#include "accommon.h"
#include "acnamesp.h"

#define _COMPONENT          ACPI_UTILITIES
ACPI_MODULE_NAME("utstring")

/*
 * Non-ANSI C library functions - strlwr, strupr, stricmp, and "safe"
 * string functions.
 */
#ifdef ACPI_ASL_COMPILER
/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_strlwr (strlwr)
 *
 * PARAMETERS:  src_string      - The source string to convert
 *
 * RETURN:      None
 *
 * DESCRIPTION: Convert string to lowercase
 *
 * NOTE: This is not a POSIX function, so it appears here, not in utclib.c
 *
 ******************************************************************************/
void acpi_ut_strlwr(char *src_string)
{
	char *string;

	ACPI_FUNCTION_ENTRY();

	if (!src_string) {
		return;
	}

	/* Walk entire string, lowercasing the letters */

	for (string = src_string; *string; string++) {
		*string = (char)tolower((int)*string);
	}

	return;
}

/******************************************************************************
 *
 * FUNCTION:    acpi_ut_stricmp (stricmp)
 *
 * PARAMETERS:  string1             - first string to compare
 *              string2             - second string to compare
 *
 * RETURN:      int that signifies string relationship. Zero means strings
 *              are equal.
 *
 * DESCRIPTION: Implementation of the non-ANSI stricmp function (compare
 *              strings with no case sensitivity)
 *
 ******************************************************************************/

int acpi_ut_stricmp(char *string1, char *string2)
{
	int c1;
	int c2;

	do {
		c1 = tolower((int)*string1);
		c2 = tolower((int)*string2);

		string1++;
		string2++;
	}
	while ((c1 == c2) && (c1));

	return (c1 - c2);
}
#endif

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_strupr (strupr)
 *
 * PARAMETERS:  src_string      - The source string to convert
 *
 * RETURN:      None
 *
 * DESCRIPTION: Convert string to uppercase
 *
 * NOTE: This is not a POSIX function, so it appears here, not in utclib.c
 *
 ******************************************************************************/

void acpi_ut_strupr(char *src_string)
{
	char *string;

	ACPI_FUNCTION_ENTRY();

	if (!src_string) {
		return;
	}

	/* Walk entire string, uppercasing the letters */

	for (string = src_string; *string; string++) {
		*string = (char)toupper((int)*string);
	}

	return;
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_print_string
 *
 * PARAMETERS:  string          - Null terminated ASCII string
 *              max_length      - Maximum output length
 *
 * RETURN:      None
 *
 * DESCRIPTION: Dump an ASCII string with support for ACPI-defined escape
 *              sequences.
 *
 ******************************************************************************/

void acpi_ut_print_string(char *string, u8 max_length)
{
	u32 i;

	if (!string) {
		acpi_os_printf("<\"NULL STRING PTR\">");
		return;
	}

	acpi_os_printf("\"");
	for (i = 0; (i < max_length) && string[i]; i++) {

		/* Escape sequences */

		switch (string[i]) {
		case 0x07:

			acpi_os_printf("\\a");	/* BELL */
			break;

		case 0x08:

			acpi_os_printf("\\b");	/* BACKSPACE */
			break;

		case 0x0C:

			acpi_os_printf("\\f");	/* FORMFEED */
			break;

		case 0x0A:

			acpi_os_printf("\\n");	/* LINEFEED */
			break;

		case 0x0D:

			acpi_os_printf("\\r");	/* CARRIAGE RETURN */
			break;

		case 0x09:

			acpi_os_printf("\\t");	/* HORIZONTAL TAB */
			break;

		case 0x0B:

			acpi_os_printf("\\v");	/* VERTICAL TAB */
			break;

		case '\'':	/* Single Quote */
		case '\"':	/* Double Quote */
		case '\\':	/* Backslash */

			acpi_os_printf("\\%c", (int)string[i]);
			break;

		default:

			/* Check for printable character or hex escape */

			if (isprint((int)string[i])) {
				/* This is a normal character */

				acpi_os_printf("%c", (int)string[i]);
			} else {
				/* All others will be Hex escapes */

				acpi_os_printf("\\x%2.2X", (s32) string[i]);
			}
			break;
		}
	}
	acpi_os_printf("\"");

	if (i == max_length && string[i]) {
		acpi_os_printf("...");
	}
}

/*******************************************************************************
 *
 * FUNCTION:    acpi_ut_repair_name
 *
 * PARAMETERS:  name            - The ACPI name to be repaired
 *
 * RETURN:      Repaired version of the name
 *
 * DESCRIPTION: Repair an ACPI name: Change invalid characters to '*' and
 *              return the new name. NOTE: the Name parameter must reside in
 *              read/write memory, cannot be a const.
 *
 * An ACPI Name must consist of valid ACPI characters. We will repair the name
 * if necessary because we don't want to abort because of this, but we want
 * all namespace names to be printable. A warning message is appropriate.
 *
 * This issue came up because there are in fact machines that exhibit
 * this problem, and we want to be able to enable ACPI support for them,
 * even though there are a few bad names.
 *
 ******************************************************************************/

void acpi_ut_repair_name(char *name)
{
	u32 i;
	u8 found_bad_char = FALSE;
	u32 original_name;

	ACPI_FUNCTION_NAME(ut_repair_name);

	ACPI_MOVE_NAME(&original_name, name);

	/* Check each character in the name */

	for (i = 0; i < ACPI_NAME_SIZE; i++) {
		if (acpi_ut_valid_name_char(name[i], i)) {
			continue;
		}

		/*
		 * Replace a bad character with something printable, yet technically
		 * still invalid. This prevents any collisions with existing "good"
		 * names in the namespace.
		 */
		name[i] = '*';
		found_bad_char = TRUE;
	}

	if (found_bad_char) {

		/* Report warning only if in strict mode or debug mode */

		if (!acpi_gbl_enable_interpreter_slack) {
			ACPI_WARNING((AE_INFO,
				      "Invalid character(s) in name (0x%.8X), repaired: [%4.4s]",
				      original_name, name));
		} else {
			ACPI_DEBUG_PRINT((ACPI_DB_INFO,
					  "Invalid character(s) in name (0x%.8X), repaired: [%4.4s]",
					  original_name, name));
		}
	}
}

#if defined ACPI_ASL_COMPILER || defined ACPI_EXEC_APP
/*******************************************************************************
 *
 * FUNCTION:    ut_convert_backslashes
 *
 * PARAMETERS:  pathname        - File pathname string to be converted
 *
 * RETURN:      Modifies the input Pathname
 *
 * DESCRIPTION: Convert all backslashes (0x5C) to forward slashes (0x2F) within
 *              the entire input file pathname string.
 *
 ******************************************************************************/

void ut_convert_backslashes(char *pathname)
{

	if (!pathname) {
		return;
	}

	while (*pathname) {
		if (*pathname == '\\') {
			*pathname = '/';
		}

		pathname++;
	}
}
#endif
