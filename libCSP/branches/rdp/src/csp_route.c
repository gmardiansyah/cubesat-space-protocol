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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* CSP includes */
#include <csp/csp.h>
#include <csp/csp_platform.h>

#include "arch/csp_thread.h"
#include "arch/csp_queue.h"
#include "arch/csp_semaphore.h"
#include "arch/csp_malloc.h"
#include "arch/csp_time.h"

#include "csp_port.h"
#include "csp_route.h"
#include "csp_conn.h"
#include "csp_io.h"
#include "transport/csp_transport.h"

/* Static allocation of interfaces */
csp_iface_t iface[17];

/** Routing input Queue
 * This queue is used each time a packet is received from an IF.
 * It holds the csp_route_queue_t complex datatype
 */
static csp_queue_handle_t router_input_fifo = NULL;
typedef struct csp_route_queue_s {
	void * interface;
	csp_packet_t * packet;
} csp_route_queue_t;

/** csp_route_table_init
 * Initialises the storage for the routing table
 */
void csp_route_table_init(void) {

	/* Clear table */
	memset(iface, 0, sizeof(csp_iface_t) * 17);

}

/** Router Task
 * This task received any non-local connection and collects the data
 * on the connection. All data is forwarded out of the router
 * using the csp_send call 
 */
csp_thread_return_t vTaskCSPRouter(void * pvParameters) {

	csp_route_queue_t input;
	csp_packet_t * packet;
	csp_conn_t * conn;
	
	csp_queue_handle_t queue = NULL;
	csp_iface_t * dst;

	/* Create fallback socket  */
	router_input_fifo = csp_queue_create(20, sizeof(csp_route_queue_t));

    /* Here there be routing */
	while (1) {

		/* Check connection timeouts */
		csp_conn_check_timeouts();

		/* Receive input */
		if (csp_queue_dequeue(router_input_fifo, &input, 10) != CSP_QUEUE_OK)
			continue;

		/* Discard invalid */
		if (input.packet == NULL) {
			csp_debug(CSP_ERROR, "Invalid packet in router queue\r\n");
			continue;
		}

#if 1
#if defined(_CSP_POSIX_)
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
		/* random pause */
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		srand(ts.tv_nsec);
		usleep(rand() % 1000);

		if (rand() % 1000 > 500) {
			csp_debug(CSP_WARN, "Dropping packet, MUAHAHA\r\n");
			csp_buffer_free(input.packet);
			continue;
		}
#endif
#endif

		packet = input.packet;

		csp_debug(CSP_PACKET, "Router input: P 0x%02X, S 0x%02X, D 0x%02X, Dp 0x%02X, Sp 0x%02X, T 0x%02X\r\n",
				packet->id.pri, packet->id.src, packet->id.dst, packet->id.dport,
				packet->id.sport, packet->id.type);

		/* If the message is not to me, route the message to the correct iface */
		if (packet->id.dst != my_address) {

			/* If both sender and receiver resides on same segment
			 * don't route the frame. */
			dst = csp_route_if(packet->id.dst);

			if (dst == NULL) {
				csp_buffer_free(packet);
				continue;
			}

			if (dst->nexthop == input.interface) {
				csp_buffer_free(packet);
				continue;
			}

			/* Actually send the message */
			if (!csp_send_direct(packet->id, packet, 0))
				csp_buffer_free(packet);

		}

		/* Now, the message is to me:
		 * search for an existing connection */
		conn = csp_conn_find(packet->id.ext, CSP_ID_CONN_MASK);

		/* If a conneciton was found */
		if (conn != NULL) {

			/* Check the close_wait state */
			if (conn->state == CONN_CLOSE_WAIT) {
				csp_debug(CSP_WARN, "Router discarded packet: CLOSE_WAIT\r\n");
				csp_buffer_free(packet);
				continue;
			}

		/* Okay, this is a new connection attempt,
		 * check if a port is listening and open a conn.
		 */
		} else {

			/* Try to deliver to incoming port number */
			if (ports[packet->id.dport].state == PORT_OPEN) {
				queue = ports[packet->id.dport].socket->conn_queue;

			/* Otherwise, try local "catch all" port number */
			} else if (ports[CSP_ANY].state == PORT_OPEN) {
				queue = ports[CSP_ANY].socket->conn_queue;

			/* Or reject */
			} else {
				csp_buffer_free(packet);
				continue;
			}

			/* New incoming connection accepted */
			csp_id_t idout;
			idout.pri = packet->id.pri;
			idout.dst = packet->id.src;
			idout.src = packet->id.dst;
			idout.dport = packet->id.sport;
			idout.sport = packet->id.dport;
			idout.protocol = packet->id.protocol;
			conn = csp_conn_new(packet->id, idout);

			if (conn == NULL) {
				csp_debug(CSP_ERROR, "No more connections available\r\n");
				csp_buffer_free(packet);
				continue;
			}

			/* Store the queue to be posted to */
			conn->rx_socket = queue;

		}

		/* Pass packet to the right transport module */
		switch(packet->id.protocol) {
#if CSP_USE_RDP
		case CSP_RDP:
			csp_rdp_new_packet(conn, packet);
			break;
#endif
		case CSP_UDP:
		default:
			csp_udp_new_packet(conn, packet);
			break;
		}

	}

}

/**
 * Use this function to start the router task.
 * @param task_stack_size The number of portStackType to allocate. This only affects FreeRTOS systems.
 */
void csp_route_start_task(unsigned int task_stack_size) {
    csp_thread_handle_t handle;
    
    int ret = csp_thread_create(vTaskCSPRouter, (signed char *) "RTE", task_stack_size, NULL, 1, &handle);
    
    if (ret != 0)
        printf("Failed to start router task\n");

}

/** Set route
 * This function maintains the routing table,
 * To set default route use nodeid 16
 * To set a value pass a callback function
 * To clear a value pass a NULL value
 */
void csp_route_set(const char * name, uint8_t node, nexthop_t nexthop) {

	if (node <= 16) {
		iface[node].nexthop = nexthop;
		iface[node].name = name;
	} else {
		printf("ERROR: Failed to set route: invalid nodeid %u\r\n", node);
	}

}

/** Routing table lookup
 * This is the actual lookup in the routing table
 * The table consists of one entry per possible node
 * If there is no explicit nexthop route for the destination
 * the default route (node 16) is used.
 */
csp_iface_t * csp_route_if(uint8_t id) {

	if (iface[id].nexthop != NULL) {
		iface[id].count++;
		return &iface[id];
	}
	if (iface[16].nexthop != NULL) {
		iface[16].count++;
		return &iface[16];
	}
	return NULL;

}

/**
 * Inputs a new packet into the system
 * This function is called from interface drivers ISR to route and accept packets.
 * But it can also be called from a task, provided that the pxTaskWoken parameter is NULL!
 *
 * EXTREMELY IMPORTANT:
 * pxTaskWoken arg must ALWAYS be NULL if called from task,
 * and ALWAYS be NON NULL if called from ISR!
 * If this condition is met, this call is completely thread-safe
 *
 * This function is fire and forget, it returns void, meaning
 * that a packet will always be either accepted or dropped
 * so the memory will always be freed.
 *
 * @param packet A pointer to the incoming packet
 * @param interface A pointer to the incoming interface TX function.
 * @param pxTaskWoken This must be a pointer a valid variable if called from ISR or NULL otherwise!
 *
 */
void csp_new_packet(csp_packet_t * packet, nexthop_t interface, CSP_BASE_TYPE * pxTaskWoken) {

	int result;

	csp_route_queue_t queue_element;
	queue_element.interface = interface;
	queue_element.packet = packet;

	if (pxTaskWoken == NULL) {
		result = csp_queue_enqueue(router_input_fifo, &queue_element, 0);
	} else {
		result = csp_queue_enqueue_isr(router_input_fifo, &queue_element, pxTaskWoken);
	}

	if (result != CSP_QUEUE_OK) {
		csp_debug(CSP_WARN, "ERROR: Routing input FIFO is FULL. Dropping packet.\r\n");
		csp_buffer_free(packet);
	}

}
