/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats
Copyright (C) 2010 Gomspace ApS (gomspace.com)
Copyright (C) 2010 AAUSAT3 Project (aausat3.space.aau.dk) 

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* CSP includes */
#include <csp/csp.h>
#include <csp/csp_config.h>

static uint8_t levels_enable[6] = {
		1,	// Info
		1,	// Error
		1,	// Warn
		1,	// Buffer
		1,	// Packet
		0	// Protocol
};

void csp_debug(csp_debug_level_t level, const char * format, ...) {

	const char * color;

	switch(level) {
	case CSP_INFO: 		if (!levels_enable[CSP_INFO]) return; 		color = ""; break;
	case CSP_ERROR: 	if (!levels_enable[CSP_ERROR]) return; 		color = "\E[1;91m"; break;
	case CSP_WARN: 		if (!levels_enable[CSP_WARN]) return; 		color = "\E[0;93m"; break;
	case CSP_BUFFER: 	if (!levels_enable[CSP_BUFFER]) return; 	color = "\E[0;33m"; break;
	case CSP_PACKET: 	if (!levels_enable[CSP_PACKET]) return; 	color = "\E[0;32m"; break;
	case CSP_PROTOCOL:  if (!levels_enable[CSP_PROTOCOL]) return; 	color = "\E[0;94m"; break;
	}

	printf("%s", color);

	va_list args;
    printf("CSP: ");
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    printf("\E[0m");


}

void csp_debug_toggle_level(csp_debug_level_t level) {
	if (level >= 6) {
		printf("Max level is 5\r\n");
		return;
	}
	levels_enable[level] = (levels_enable[level]) ? 0 : 1;
	printf("Level %u: value %u\r\n", level, levels_enable[level]);
}
