/**
 * csp_rdp.c
 *
 * @date: 24/06/2010
 * @author: Johan Christiansen
 *
 * This is a implementation of the seq/ack handling taken from the Reliable Datagram Protocol (RDP)
 * For more information read RFC-908.
 *
 */

#include <stdio.h>

#include <csp/csp.h>
#include "../arch/csp_queue.h"
#include "../csp_port.h"
#include "../csp_conn.h"

void csp_rdp_new_packet(csp_conn_t * conn, csp_packet_t * packet, CSP_BASE_TYPE * pxTaskWoken) {

	printf("This is an RDP packet, rejecting\r\n");
	csp_buffer_free(packet);
	csp_close(conn);
	return;

}

