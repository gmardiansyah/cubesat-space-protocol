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
#include <string.h>

#include <csp/csp.h>
#include <csp/csp_endian.h>
#include "../arch/csp_queue.h"
#include "../arch/csp_malloc.h"
#include "../csp_port.h"
#include "../csp_conn.h"
#include "csp_transport.h"

#include <util/hexdump.h>

#define RDP_WINDOW_MAX	10

struct csp_l4data_s {
	int state;
	int snd_nxt;
	int snd_una;
	int snd_max;
	int snd_iss;
	int rcv_cur;
	int rcv_max;
	int rcv_irs;
	int sbuf_max;
	int rbuf_max;
	int rcvdseqno[RDP_WINDOW_MAX];
};

enum csp_rdp_states {
	RDP_CLOSED = 0,
	RDP_LISTEN,
	RDP_SYN_SENT,
	RDP_SYN_RCVD,
	RDP_OPEN,
	RDP_CLOSE_WAIT,
};

typedef struct rdp_header_s {
	uint8_t syn;
	uint8_t ack;
	uint8_t eak;
	uint8_t rst;
	uint8_t nul;
	uint8_t rdp_length;
	uint16_t seq_nr;
	uint16_t ack_nr;
} rdp_header_t;

static rdp_header_t * csp_rdp_header_add(csp_packet_t * packet) {
	rdp_header_t * header = (rdp_header_t *) &packet->data[packet->length];
	packet->length += sizeof(rdp_header_t);
	return header;
}

static rdp_header_t * csp_rdp_header_add_overwrite(csp_packet_t * packet, rdp_header_t * write_header) {
	memcpy(&packet->data[packet->length], write_header, sizeof(rdp_header_t));
	rdp_header_t * header = (rdp_header_t *) &packet->data[packet->length];
	packet->length += sizeof(rdp_header_t);
	return header;
}

static rdp_header_t * csp_rdp_header_remove(csp_packet_t * packet) {
	rdp_header_t * header = (rdp_header_t *) &packet->data[packet->length-sizeof(rdp_header_t)];
	packet->length -= sizeof(rdp_header_t);
	return header;
}


void csp_rdp_new_packet(csp_conn_t * conn, csp_packet_t * packet, CSP_BASE_TYPE * pxTaskWoken) {

	if (conn->l4data->state == RDP_CLOSED) {
		if (csp_rdp_connect_passive(conn, packet) == 0) {
			csp_debug("RDP: Passive connect failed\r\n");
			csp_buffer_free(packet);
			csp_close(conn);
			return;
		}
	}

	csp_debug("RDP: Packet accepted, state %u\r\n", conn->l4data->state);

	/* Get RX header */
	rdp_header_t * rx_header = csp_rdp_header_remove(packet);

	/* Prepare new TX header */
	rdp_header_t tx_header;
	memset(&tx_header, 0, sizeof(rdp_header_t));

	csp_debug("RDP: HEADER NP: syn %u, ack %u, seq_nr %u, ack_nr %u\r\n", rx_header->syn, rx_header->ack, rx_header->seq_nr, rx_header->ack_nr);

	switch(conn->l4data->state) {
	case RDP_LISTEN: {
		if (rx_header->rst)
			goto discard;

		if (rx_header->ack || rx_header->nul) {
			tx_header.rst = 1;
			tx_header.seq_nr = rx_header->ack_nr + 1;
			csp_rdp_header_add_overwrite(packet, &tx_header);
			csp_send(conn, packet, 0);
			return;
		}

		if (rx_header->syn) {
			csp_debug("RDP: SYN-Received\r\n");
			conn->l4data->rcv_cur = rx_header->seq_nr;
			conn->l4data->rcv_irs = rx_header->seq_nr;
			tx_header.seq_nr = conn->l4data->snd_iss;
			tx_header.ack_nr = rx_header->seq_nr;
			tx_header.ack = 1;
			tx_header.syn = 1;
			conn->l4data->state = RDP_SYN_RCVD;
			csp_rdp_header_add_overwrite(packet, &tx_header);
			csp_send(conn, packet, 0);
			return;
		}

		csp_debug("RDP: ERROR should never reach here __RDP_LISTEN__\r\n");
	}
	break;

	case RDP_SYN_SENT: {

		if (rx_header->syn) {
			conn->l4data->rcv_cur = rx_header->seq_nr;
			conn->l4data->rcv_irs = rx_header->seq_nr;
			if (rx_header->ack) {
				printf("RDP: Conn open!\r\n");
				conn->l4data->snd_una = rx_header->ack_nr;
				conn->l4data->state = RDP_OPEN;
				tx_header.seq_nr = conn->l4data->snd_nxt;
				tx_header.ack_nr = conn->l4data->rcv_cur;
				tx_header.ack = 1;
				csp_rdp_header_add_overwrite(packet, &tx_header);
				csp_send(conn, packet, 0);
			}
			return;
		}

	}
	break;

	case RDP_SYN_RCVD: {
		printf("Wee we are open now\r\n");
		conn->l4data->state = RDP_OPEN;
		csp_buffer_free(packet);
		return;
	}
	break;

	case RDP_OPEN: {

		printf("Queue up for userspace!\r\n");
		int result;

		/* Enqueue */
		if (pxTaskWoken == NULL)
			result = csp_queue_enqueue(conn->rx_queue, &packet, 0);
		else
			result = csp_queue_enqueue_isr(conn->rx_queue, &packet, pxTaskWoken);

		printf("Result is %u\r\n", result);

		if (result != CSP_QUEUE_OK) {
			printf("ERROR: Connection buffer queue full!\r\n");
			csp_buffer_free(packet);
			return;
		}

		/* Try to queue up the new connection pointer */
		if (conn->rx_socket != NULL) {

			printf("Wake task\r\n");
			int result;
			if (pxTaskWoken == NULL)
				result = csp_queue_enqueue(conn->rx_socket, &conn, 0);
			else
				result = csp_queue_enqueue_isr(conn->rx_socket, &conn, pxTaskWoken);

			printf("Result is %u\r\n", result);

			if (result == CSP_QUEUE_FULL) {
				printf("Warning Routing Queue Full\r\n");
				/* Don't call csp_conn_close, since this might be ISR context. */
				conn->state = CONN_CLOSED;
				return;
			}
		}

	}
	break;

	default:
		csp_debug("RDP: ERROR default state!\r\n");
		goto discard;
	}

discard:
	csp_buffer_free(packet);
	csp_close(conn);
	return;

}

int csp_rdp_connect_active(csp_conn_t * conn, int timeout) {

	csp_debug("RDP: Active connect, conn state %u\r\n", conn->l4data->state);

	if (conn->l4data->state != RDP_CLOSED) {
		printf("RDP: ERROR Connection already open\r\n");
		return 0;
	}

	conn->l4data->snd_iss = 10;
	conn->l4data->snd_nxt = conn->l4data->snd_iss + 1;
	conn->l4data->snd_una = conn->l4data->snd_iss;
	conn->l4data->snd_max = 90;
	conn->l4data->rbuf_max = 90;

	/* Send SYN */
	csp_packet_t * packet;
	packet = csp_buffer_get(10);
	packet->data[0] = 0x55;
	packet->length = 1;
	rdp_header_t * tx_header = csp_rdp_header_add(packet);
	tx_header->syn = 1;
	tx_header->seq_nr = conn->l4data->snd_iss;
	csp_debug("RDP: Sending SYN\r\n");
	hex_dump(&packet->length, packet->length+6);
	conn->l4data->state = RDP_SYN_SENT;
	csp_send(conn, packet, 0);

	printf("RDP: Active Connect state %u\r\n", conn->l4data->state);

	if (conn->l4data->state == RDP_OPEN)
		return 1;
	else
		return 0;
}

int csp_rdp_connect_passive(csp_conn_t * conn, csp_packet_t * packet) {

	csp_debug("RDP: Connect passive, conn state %u\r\n", conn->l4data->state);

	if (conn->l4data->state != RDP_CLOSED) {
		printf("RDP: ERROR Connection already open\r\n");
		return 0;
	}

	conn->l4data->snd_iss = 10;
	conn->l4data->snd_nxt = conn->l4data->snd_iss + 1;
	conn->l4data->snd_una = conn->l4data->snd_iss;
	conn->l4data->snd_max = 90;
	conn->l4data->rbuf_max = 90;
	conn->l4data->state = RDP_LISTEN;

	return 1;

}

int csp_rdp_allocate(csp_conn_t * conn) {

	csp_debug("RDP: Malloc l4 data\r\n");

	/* Allocate memory area for layer 4 information */
	conn->l4data = csp_malloc(sizeof(csp_l4data_t));
	if (conn->l4data == NULL)
		return 0;

	conn->l4data->state = RDP_CLOSED;

	return 1;

}

void csp_rdp_close(csp_conn_t * conn) {

	csp_debug("RDP: Free l4 data\r\n");

	/* Deallocate memory */
	if (conn->l4data != NULL) {
		csp_free(conn->l4data);
		conn->l4data = NULL;
	}

}
