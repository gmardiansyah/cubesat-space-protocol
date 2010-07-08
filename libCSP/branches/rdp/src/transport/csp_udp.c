/**
 * csp_udp.c
 *
 * @date: 24/06/2010
 * @author: Johan Christiansen
 *
 * This is the simplest implementation of a transport layer module for CSP
 *
 */

#include <stdio.h>

#include <csp/csp.h>
#include "../arch/csp_queue.h"
#include "../csp_port.h"
#include "../csp_conn.h"

void csp_udp_new_packet(csp_conn_t * conn, csp_packet_t * packet) {

	/* Enqueue */
	if (csp_queue_enqueue(conn->rx_queue, &packet, 0) != CSP_QUEUE_OK) {
		printf("ERROR: Connection buffer queue full!\r\n");
		csp_buffer_free(packet);
		return;
	}

	/* Try to queue up the new connection pointer */
	if (conn->rx_socket != NULL) {
		if (csp_queue_enqueue(conn->rx_socket, &conn, 0) == CSP_QUEUE_FULL) {
			printf("Warning Routing Queue Full\r\n");
			/* Don't call csp_conn_close, since this might be ISR context. */
			conn->state = CONN_CLOSED;
			return;
		}

		/* Ensure that this connection will not be posted to this socket again */
		conn->rx_socket = NULL;
	}

}

