/*
Cubesat Space Protocol - A small network-layer protocol designed for Cubesats
Copyright (C) 2010 GomSpace ApS (gomspace.com)
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

/* CSP includes */
#include <csp/csp.h>

#include "arch/csp_semaphore.h"
#include "arch/csp_queue.h"

#include "csp_route.h"

#define CSP_LO_USE_TASK	1

static csp_queue_handle_t lo_queue = NULL;

int csp_lo_tx(csp_id_t idout, csp_packet_t * packet, unsigned int timeout) {

	/* Store outgoing id */
	packet->id.ext = idout.ext;

#if CSP_LO_USE_TASK==1
	/* Ensure local queue is created */
	if (lo_queue != NULL)
		if (csp_queue_enqueue(lo_queue, &packet, timeout) != CSP_QUEUE_OK)
			return 0;
#else
	/* Send back into CSP, notice calling from task so last argument must be NULL! */
	csp_new_packet(packet, csp_lo_tx, NULL);
#endif

	return 1;

}

void * vTaskLo(void * pvParameters) {

	csp_packet_t * packet;
	lo_queue = csp_queue_create(10, sizeof(csp_packet_t *));

	while(1) {

		csp_queue_dequeue(lo_queue, &packet, CSP_MAX_DELAY);

		if (packet == NULL)
			continue;

		/* Send back into CSP, notice calling from task so last argument must be NULL! */
		csp_new_packet(packet, csp_lo_tx, NULL);

	}

}


