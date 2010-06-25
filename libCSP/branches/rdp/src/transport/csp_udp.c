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

void csp_udp_new_packet(csp_conn_t * conn, csp_packet_t * packet, CSP_BASE_TYPE * pxTaskWoken) {

	int result;

	/* Enqueue */
	if (pxTaskWoken == NULL)
		result = csp_queue_enqueue(conn->rx_queue, &packet, 0);
	else
		result = csp_queue_enqueue_isr(conn->rx_queue, &packet, pxTaskWoken);

	if (result != CSP_QUEUE_OK) {
		printf("ERROR: Connection buffer queue full!\r\n");
		csp_buffer_free(packet);
		return;
	}

	/* Try to queue up the new connection pointer */
	if (conn->rx_socket != NULL) {
		int result;
		if (pxTaskWoken == NULL)
			result = csp_queue_enqueue(conn->rx_socket, &conn, 0);
		else
			result = csp_queue_enqueue_isr(conn->rx_socket, &conn, pxTaskWoken);

		if (result == CSP_QUEUE_FULL) {
			printf("Warning Routing Queue Full\r\n");
			/* Don't call csp_conn_close, since this might be ISR context. */
			conn->state = CONN_CLOSED;
			return;
		}

		/* Ensure that this connection will not be posted to this socket again */
		conn->rx_socket = NULL;
	}

	/* If a local callback is used, call it */
	if ((packet->id.dst == my_address) && (packet->id.dport < 16)
			&& (ports[packet->id.dport].callback != NULL))
		ports[packet->id.dport].callback(conn);

}

