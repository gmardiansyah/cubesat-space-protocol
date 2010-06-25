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
#include "../arch/csp_semaphore.h"
#include "../arch/csp_malloc.h"
#include "../csp_port.h"
#include "../csp_conn.h"
#include "csp_transport.h"

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
	csp_bin_sem_handle_t tx_wait;
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

static rdp_header_t * csp_rdp_header_remove(csp_packet_t * packet) {
	rdp_header_t * header = (rdp_header_t *) &packet->data[packet->length-sizeof(rdp_header_t)];
	packet->length -= sizeof(rdp_header_t);
	return header;
}

static void csp_rdp_send_cmp(csp_conn_t * conn, int ack, int syn, int rst, int seq_nr, int ack_nr) {

	csp_packet_t * packet = csp_buffer_get(20);
	packet->length = 0;
	rdp_header_t * header = csp_rdp_header_add(packet);
	memset(header, 0, sizeof(rdp_header_t));
	header->seq_nr = seq_nr;
	header->ack_nr = ack_nr;
	header->ack = ack;
	header->syn = syn;
	header->rst = rst;
	if (csp_send_direct(conn->idout, packet, 0) == 0)
		csp_buffer_free(packet);

}

static void csp_rdp_send_reset(csp_conn_t * conn) {
	csp_rdp_send_cmp(conn, 0, 0, 1, 0xFFFF, 0xFFFF);
}


void csp_rdp_new_packet(csp_conn_t * conn, csp_packet_t * packet, CSP_BASE_TYPE * pxTaskWoken) {

	/* Get RX header */
	rdp_header_t * rx_header = csp_rdp_header_remove(packet);

	csp_debug(CSP_PROTOCOL, "RDP: HEADER NP: syn %u, ack %u, rst %u, seq_nr %u, ack_nr %u, packet_len %u\r\n", rx_header->syn, rx_header->ack, rx_header->rst, rx_header->seq_nr, rx_header->ack_nr, packet->length);

	if (conn->l4data->state == RDP_CLOSED) {
		if (csp_rdp_connect_passive(conn, packet) == 0) {
			csp_debug(CSP_PROTOCOL, "RDP: Passive connect failed\r\n");
			goto discard_close;
		}
	}

	csp_debug(CSP_PROTOCOL, "RDP: Packet accepted, state %u\r\n", conn->l4data->state);

	switch(conn->l4data->state) {

	/**
	 * STATE == LISTEN
	 */
	case RDP_LISTEN: {

		if (rx_header->rst || rx_header->ack || rx_header->nul) {
			csp_debug(CSP_WARN, "Got RESET, ACK or NUL in state LISTEN, sending RESET\r\n");
			goto discard_close;
		}

		if (rx_header->syn) {
			csp_debug(CSP_PROTOCOL, "RDP: SYN-Received\r\n");
			conn->l4data->rcv_cur = rx_header->seq_nr;
			conn->l4data->rcv_irs = rx_header->seq_nr;
			conn->l4data->state = RDP_SYN_RCVD;

			/* Send SYN/ACK */
			csp_rdp_send_cmp(conn, 1, 1, 0, conn->l4data->snd_iss, conn->l4data->rcv_irs);

			csp_buffer_free(packet);
			return;
		}

		csp_debug(CSP_PROTOCOL, "RDP: ERROR should never reach here __RDP_LISTEN__\r\n");
	}
	break;

	/**
	 * STATE == SYN-SENT
	 */
	case RDP_SYN_SENT: {

		if (rx_header->syn) {
			conn->l4data->rcv_cur = rx_header->seq_nr;
			conn->l4data->rcv_irs = rx_header->seq_nr;
			if (rx_header->ack) {

				csp_debug(CSP_PROTOCOL, "RDP: NP: Conn open!\r\n");
				conn->l4data->snd_una = rx_header->ack_nr;
				conn->l4data->state = RDP_OPEN;

				/* Send ACK */
				csp_rdp_send_cmp(conn, 1, 0 ,0 , conn->l4data->snd_nxt, conn->l4data->rcv_cur);


				if (pxTaskWoken == NULL) {
					csp_bin_sem_post(&conn->l4data->tx_wait);
				} else {
					csp_bin_sem_post_isr(&conn->l4data->tx_wait, pxTaskWoken);
				}
			} else {
				csp_debug(CSP_WARN, "WARN: state SYN-SENT but ack not set\r\n");
				csp_buffer_free(packet);
			}
			return;
		}

	}
	break;

	/**
	 * STATE == SYN-RCVD
	 */
	case RDP_SYN_RCVD: {

		if (rx_header->rst) {
			csp_debug(CSP_WARN, "Got RESET expected SYN,ACK\r\n");
			goto discard_close;
		}

		if (rx_header->ack) {
			if (rx_header->ack_nr == conn->l4data->snd_iss) {
				csp_debug(CSP_PROTOCOL, "RDP: NC: Connection OPEN");
				conn->l4data->state = RDP_OPEN;
			} else {

			}
			csp_buffer_free(packet);
			return;
		}

		csp_debug(CSP_ERROR, "ERROR: Unimplemented functionality\r\n");
		goto discard_close;

	}
	break;

	/**
	 * STATE == OPEN
	 */
	case RDP_OPEN: {

		if (rx_header->rst == 1) {
			csp_debug(CSP_PROTOCOL, "RDP: Got RESET in state OPEN, closing\r\n");
			conn->l4data->state = RDP_CLOSE_WAIT;
			csp_buffer_free(packet);
			return;
		}

		if (rx_header->ack == 1) {
			if (conn->l4data->snd_una <= rx_header->seq_nr) {
				conn->l4data->snd_una = rx_header->seq_nr;
			}
		}

		if (packet->length == 0) {
			csp_buffer_free(packet);
			return;
		}

		conn->l4data->rcv_cur = rx_header->seq_nr;

		/* Send ACK */
		csp_packet_t * packet_ack = csp_buffer_get(20);
		packet_ack->length = 0;
		rdp_header_t * header_ack = csp_rdp_header_add(packet_ack);
		memset(header_ack, 0, sizeof(rdp_header_t));
		header_ack->seq_nr = conn->l4data->snd_nxt;
		header_ack->ack_nr = conn->l4data->rcv_cur;
		header_ack->ack = 1;
		if (csp_send_direct(conn->idout, packet_ack, 0) == 0)
			csp_buffer_free(packet_ack);

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

		return;

	}
	break;

	default:
		csp_debug(CSP_ERROR, "RDP: ERROR default state!\r\n");
		goto discard_close;
	}

discard_close:
	csp_buffer_free(packet);
	conn->l4data->state = RDP_CLOSE_WAIT;
	csp_close(conn);
	return;

}

int csp_rdp_connect_active(csp_conn_t * conn, int timeout) {

	csp_debug(CSP_PROTOCOL, "RDP: Active connect, conn state %u\r\n", conn->l4data->state);

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
	packet->length = 0;
	rdp_header_t * tx_header = csp_rdp_header_add(packet);
	memset(tx_header, 0, sizeof(rdp_header_t));
	tx_header->syn = 1;
	tx_header->seq_nr = conn->l4data->snd_iss;
	csp_debug(CSP_PROTOCOL, "RDP: Sending SYN\r\n");
	conn->l4data->state = RDP_SYN_SENT;

	csp_bin_sem_wait(&conn->l4data->tx_wait, 0);

	if (csp_send_direct(conn->idout, packet, 0) == 0) {
		csp_buffer_free(packet);
		return 0;
	}

	csp_debug(CSP_PROTOCOL, "RDP: AC: Waiting for connect\r\n");
	if ((csp_bin_sem_wait(&conn->l4data->tx_wait, timeout) == CSP_SEMAPHORE_OK) &&
			(conn->l4data->state == RDP_OPEN)) {
		csp_debug(CSP_PROTOCOL, "RDP: AC: Connection OPEN\r\n");
		return 1;
	} else {
		csp_debug(CSP_PROTOCOL, "RDP: AC: Connection Failed\r\n");
		return 0;
	}

}

int csp_rdp_connect_passive(csp_conn_t * conn, csp_packet_t * packet) {

	csp_debug(CSP_PROTOCOL, "RDP: Connect passive, conn state %u\r\n", conn->l4data->state);

	if (conn->l4data->state != RDP_CLOSED) {
		printf("RDP: ERROR Connection already open\r\n");
		return 0;
	}

	conn->l4data->snd_iss = 20;
	conn->l4data->snd_nxt = conn->l4data->snd_iss + 1;
	conn->l4data->snd_una = conn->l4data->snd_iss;
	conn->l4data->snd_max = 90;
	conn->l4data->rbuf_max = 90;
	conn->l4data->state = RDP_LISTEN;

	return 1;

}

int csp_rdp_send(csp_conn_t* conn, csp_packet_t * packet, int timeout) {

	if (conn->l4data == NULL)
		return 0;

	if (conn->l4data->state != RDP_OPEN) {
		csp_debug(CSP_PROTOCOL, "RDP: ERROR cannot send, connection not open!\r\n");
		return 0;
	}

	csp_debug(CSP_PROTOCOL, "RDP: SEND\r\n");

	rdp_header_t * tx_header = csp_rdp_header_add(packet);

	memset(tx_header, 0, sizeof(rdp_header_t));
	tx_header->seq_nr = conn->l4data->snd_nxt;
	tx_header->ack_nr = conn->l4data->rcv_cur;
	tx_header->ack = 1;

	conn->l4data->snd_nxt += 1;

	return 1;

}

int csp_rdp_allocate(csp_conn_t * conn) {

	csp_debug(CSP_PROTOCOL, "RDP: Malloc l4 data\r\n");

	/* Allocate memory area for layer 4 information */
	conn->l4data = csp_malloc(sizeof(csp_l4data_t));
	if (conn->l4data == NULL)
		return 0;

	conn->l4data->state = RDP_CLOSED;

	/* Create a binary semaphore to wait on for tasks */
	csp_bin_sem_create(&conn->l4data->tx_wait);
#ifdef _CSP_FREERTOS_
	if (conn->l4data->tx_wait == NULL) {
		csp_free(conn->l4data);
		return 0;
	}
#endif

	return 1;

}

void csp_rdp_close(csp_conn_t * conn) {

	if (conn->l4data->state == RDP_OPEN || conn->l4data->state == RDP_LISTEN) {

		/* Send Reset */
		csp_rdp_send_reset(conn);
		csp_debug(CSP_PROTOCOL, "RDP Close, sending RST\r\n");
		conn->l4data->state = RDP_CLOSED;

	}

	csp_debug(CSP_PROTOCOL, "RDP: Free l4 data\r\n");

	/* Deallocate memory */
	if (conn->l4data != NULL) {
#ifdef _CSP_FREERTOS_
		if (conn->l4data->tx_wait != NULL)
			csp_free(conn->l4data->tx_wait);
#endif
		csp_free(conn->l4data);
		conn->l4data = NULL;
	}

}

void csp_rdp_conn_print(csp_conn_t * conn) {

	if (conn->l4data == NULL)
		return;

	printf("\tRDP: State %u, rcv %u, snd %u\r\n", conn->l4data->state, conn->l4data->rcv_cur, conn->l4data->snd_una);

}
