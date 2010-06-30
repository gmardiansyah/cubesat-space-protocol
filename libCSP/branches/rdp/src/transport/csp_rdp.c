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
#include "../arch/csp_time.h"
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
	csp_queue_handle_t tx_queue;
};

typedef struct __attribute__((__packed__)) {
    uint8_t padding1[40];       // Interface dependent padding
    uint32_t timestamp;			// Time the message was sent
    uint16_t length;            // Length field must be just before CSP ID
    csp_id_t id;                // CSP id must be just before data
    uint8_t data[];				// This just points to the rest of the buffer, without a size indication.
} rdp_packet_t;


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

static rdp_header_t * csp_rdp_header_ref(csp_packet_t * packet) {
	rdp_header_t * header = (rdp_header_t *) &packet->data[packet->length-sizeof(rdp_header_t)];
	return header;
}

static int csp_rdp_send_cmp(csp_conn_t * conn, int ack, int syn, int rst, int seq_nr, int ack_nr) {

	csp_packet_t * packet = csp_buffer_get(20);
	if (packet == NULL) {
		csp_debug(CSP_ERROR, "No more buffers free\r\n");
		return 0;
	}
	packet->length = 0;
	rdp_header_t * header = csp_rdp_header_add(packet);
	memset(header, 0, sizeof(rdp_header_t));
	header->seq_nr = seq_nr;
	header->ack_nr = ack_nr;
	header->ack = ack;
	header->syn = syn;
	header->rst = rst;
	if (csp_send_direct(conn->idout, packet, 0) == 0) {
		csp_debug(CSP_ERROR, "INTERFACE ERROR: not possible to send\r\n");
		csp_buffer_free(packet);
		return 0;
	}

	if (syn) {
		/* Send copy to tx_queue */
		rdp_packet_t * rdp_packet = csp_buffer_get(packet->length+10);
		rdp_packet->timestamp = csp_get_ms();
		memcpy(&rdp_packet->length, &packet->length, packet->length+6);
		csp_queue_enqueue(conn->l4data->tx_queue, &rdp_packet, 0);
	}

	return 1;

}

static void csp_rdp_send_reset(csp_conn_t * conn) {
	csp_rdp_send_cmp(conn, 0, 0, 1, 0xFFFF, 0xFFFF);
}

static void inline csp_rdp_wake_tx_task(csp_conn_t * conn, CSP_BASE_TYPE * pxTaskWoken) {
	if (pxTaskWoken == NULL) {
		csp_bin_sem_post(&conn->l4data->tx_wait);
	} else {
		csp_bin_sem_post_isr(&conn->l4data->tx_wait, pxTaskWoken);
	}
}

static int inline csp_rdp_receive_data(csp_conn_t * conn, csp_packet_t * packet, CSP_BASE_TYPE * pxTaskWoken) {

	int result;

	/* If a rx_socket is set, this message is the first in a new connection
	 * so the connetion must be queued to the socket. */
	if ((conn->rx_socket != NULL) && (conn->rx_socket != (void *) 1)) {

		/* Try queueing */
		if (pxTaskWoken == NULL) {
			result = csp_queue_enqueue(conn->rx_socket, &conn, 0);
		} else {
			result = csp_queue_enqueue_isr(conn->rx_socket, &conn, pxTaskWoken);
		}

		if (result == CSP_QUEUE_FULL) {
			csp_debug(CSP_ERROR, "ERROR socket cannont accept more connections\r\n");
			return 0;
		}

		/* Ensure that this connection will not be posted to this socket again
		 * and remember that the connection handle has been passed to userspace
		 * by setting the rx_socet = 1. */
		conn->rx_socket = (void *) 1;
	}

	/* Enqueue data */
	if (pxTaskWoken == NULL) {
		result = csp_queue_enqueue(conn->rx_queue, &packet, 0);
	} else {
		result = csp_queue_enqueue_isr(conn->rx_queue, &packet, pxTaskWoken);
	}

	if (result != CSP_QUEUE_OK) {
		csp_debug(CSP_WARN, "ERROR: Conn buffer full\r\n");
		return 0;
	}

	return 1;

}

static void csp_rdp_flush_acked(csp_conn_t * conn) {

	if ((conn == NULL) || conn->l4data == NULL || conn->l4data->tx_queue == NULL) {
		csp_debug(CSP_ERROR, "Null pointer passed to rdp flush\r\n");
		return;
	}

	rdp_packet_t * packet;

	uint32_t time_now = csp_get_ms();

	/* Loop through TX queue */
	int i;

	for (i = 0; i < csp_queue_size(conn->l4data->tx_queue); i++) {

		if (csp_queue_dequeue(conn->l4data->tx_queue, &packet, 0) != CSP_QUEUE_OK) {
			csp_debug(CSP_ERROR, "Cannot dequeue from tx_queue in flush\r\n");
			break;
		}

		if (packet == NULL)
			continue;

		rdp_header_t * header = csp_rdp_header_ref((csp_packet_t *) packet);
		csp_debug(CSP_PROTOCOL, "TX Element, time %u, seq %u\r\n", packet->timestamp, header->seq_nr);
		if (header->seq_nr < conn->l4data->snd_una) {
			csp_buffer_free(packet);
			continue;
		} else {
			csp_debug(CSP_WARN, "TX Element not yet acked!\r\n");
		}

		if (packet->timestamp + 1000 < time_now) {
			csp_debug(CSP_WARN, "TX Element timed out, retransmitting!\r\n");
		}

		csp_queue_enqueue(conn->l4data->tx_queue, &packet, 0);

	}

}

static void csp_rdp_flush_all(csp_conn_t * conn) {

	if ((conn == NULL) || conn->l4data == NULL || conn->l4data->tx_queue == NULL) {
		csp_debug(CSP_ERROR, "Null pointer passed to rdp flush all\r\n");
		return;
	}

	rdp_packet_t * packet;

	/* Loop through TX queue */
	int i;
	for (i = 0; i < csp_queue_size(conn->l4data->tx_queue); i++) {

		if (csp_queue_dequeue(conn->l4data->tx_queue, &packet, 0) != CSP_QUEUE_OK) {
			csp_debug(CSP_ERROR, "Cannot dequeue from tx_queue in flush all\r\n");
			break;
		}

		if (packet == NULL)
			continue;

		rdp_header_t * header = csp_rdp_header_ref((csp_packet_t *) packet);
		csp_debug(CSP_PROTOCOL, "TX Element, time %u, seq %u\r\n", packet->timestamp, header->seq_nr);

		csp_buffer_free(packet);
		continue;
	}

}

void csp_rdp_new_packet(csp_conn_t * conn, csp_packet_t * packet, CSP_BASE_TYPE * pxTaskWoken) {

	if (!csp_conn_wait(conn)) {
		csp_buffer_free(packet);
		return;
	}

	/* Get RX header */
	rdp_header_t * rx_header = csp_rdp_header_remove(packet);

	csp_debug(CSP_PROTOCOL, "RDP: HEADER NP: syn %u, ack %u, rst %u, seq_nr %u, ack_nr %u, packet_len %u\r\n", rx_header->syn, rx_header->ack, rx_header->rst, rx_header->seq_nr, rx_header->ack_nr, packet->length);

	/* If the connection is closed, this is the first message in a new connection,
	 * Run the connect passive sequence here.
	 */
	if (conn->l4data->state == RDP_CLOSED) {
		conn->l4data->snd_iss = 20;
		conn->l4data->snd_nxt = conn->l4data->snd_iss + 1;
		conn->l4data->snd_una = conn->l4data->snd_iss + 1;
		conn->l4data->snd_max = 90;
		conn->l4data->rbuf_max = 90;
		conn->l4data->rcv_max = 10;
		conn->l4data->state = RDP_LISTEN;
	}

	csp_debug(CSP_PROTOCOL, "RDP: Packet accepted, state %u\r\n", conn->l4data->state);

	/* If a RESET was received, always goto closed state, do not send RST back */
	if (rx_header->rst) {
		csp_debug(CSP_INFO, "Got RESET in state %u\r\n", conn->l4data->state);
		conn->l4data->state = RDP_CLOSE_WAIT;
		goto discard_close;
	}

	/* The BIG FAT switch (state-machine) */
	switch(conn->l4data->state) {

	/**
	 * STATE == LISTEN
	 */
	case RDP_LISTEN: {

		/* ACK received while in listen, this is not normal. Inform by sending back RST */
		if (rx_header->ack) {
			goto discard_close;
		}

		/* SYN received, this was expected */
		if (rx_header->syn) {
			csp_debug(CSP_PROTOCOL, "RDP: SYN-Received\r\n");
			conn->l4data->rcv_cur = rx_header->seq_nr;
			conn->l4data->rcv_irs = rx_header->seq_nr;
			conn->l4data->state = RDP_SYN_RCVD;

			/* Send SYN/ACK */
			csp_rdp_send_cmp(conn, 1, 1, 0, conn->l4data->snd_iss, conn->l4data->rcv_irs);

			goto discard_open;
		}

		csp_debug(CSP_PROTOCOL, "RDP: ERROR should never reach here state: LISTEN\r\n");
		goto discard_close;

	}
	break;

	/**
	 * STATE == SYN-SENT
	 */
	case RDP_SYN_SENT: {

		/* First check SYN/ACK */
		if (rx_header->syn && rx_header->ack) {

			conn->l4data->rcv_cur = rx_header->seq_nr;
			conn->l4data->rcv_irs = rx_header->seq_nr;
			conn->l4data->snd_una = rx_header->ack_nr + 1;
			conn->l4data->state = RDP_OPEN;

			csp_rdp_flush_acked(conn);

			csp_debug(CSP_PROTOCOL, "RDP: NP: Connection OPEN\r\n");

			/* Send ACK and wake TX task */
			csp_rdp_send_cmp(conn, 1, 0 ,0 , conn->l4data->snd_nxt, conn->l4data->rcv_cur);
			csp_rdp_wake_tx_task(conn, pxTaskWoken);

			goto discard_open;
		}

		/* If there was no SYN in the reply, our SYN message hit an already open connection
		 * This is handled by sending a RST.
		 * Normally this would be followed up by a new connection attempt, however
		 * we don't have a method for signalling this to the userspace.
		 */
		if (rx_header->ack) {
			csp_debug(CSP_ERROR, "Half-open connection found, sending RST\r\n");
			csp_rdp_send_reset(conn);
			csp_rdp_wake_tx_task(conn, pxTaskWoken);

			goto discard_open;
		}

		/* Otherwise we have an invalid command, such as a SYN reply to a SYN command,
		 * indicating simultaneous connections, which is not possible in the way CSP
		 * reserves some ports for server and some for clients.
		 */
		csp_debug(CSP_ERROR, "Invalid reply to SYN request\r\n");
		goto discard_close;

	}
	break;

	/**
	 * STATE == SYN-RCVD
	 */
	case RDP_SYN_RCVD: {

		/* Check sequence number */
		if (!((conn->l4data->rcv_irs < rx_header->seq_nr) && (rx_header->seq_nr <= conn->l4data->rcv_cur + (conn->l4data->rcv_max * 2)))) {
			csp_debug(CSP_ERROR, "SYN-RCVD: Sequence number unacceptable\r\n");
			csp_rdp_send_cmp(conn, 1, 0, 0, conn->l4data->snd_nxt, conn->l4data->rcv_cur);
			goto discard_open;
		}

		/* SYN after a SYN is invalid */
		if (rx_header->syn) {
			csp_debug(CSP_ERROR, "SYN after SYN is invalid\r\n");
			goto discard_close;
		}

		/* The expected reply is an ACK */
		if (!rx_header->ack) {
			csp_debug(CSP_ERROR, "Not ACK, Invalid message\r\n");
			goto discard_close;
		}

		/* Check correct ACK number */
		if (rx_header->ack_nr != conn->l4data->snd_iss) {
			csp_debug(CSP_ERROR, "Wrong ACK number\r\n");
			goto discard_close;
		}

		csp_debug(CSP_PROTOCOL, "RDP: NC: Connection OPEN\r\n");
		conn->l4data->state = RDP_OPEN;

		csp_rdp_flush_acked(conn);

		/* If message is empty, discard */
		if (!packet->length) {
			goto discard_open;
		}

		csp_debug(CSP_WARN, "Data found in state SYN-RCVD, this is good\r\n");

		/* If message contains data, get it */
		conn->l4data->rcv_cur = rx_header->seq_nr;
		if (csp_rdp_receive_data(conn, packet, pxTaskWoken)) {
			csp_rdp_send_cmp(conn, 1, 0, 0, conn->l4data->snd_nxt, conn->l4data->rcv_cur);
		} else {
			csp_debug(CSP_ERROR, "Cannot receive data, closing conn\r\n");
			goto discard_close;
		}

		goto accepted_open;

	}
	break;

	/**
	 * STATE == OPEN
	 */
	case RDP_OPEN: {

		/* Check sequence number */
		if (!((conn->l4data->rcv_cur < rx_header->seq_nr) && (rx_header->seq_nr <= conn->l4data->rcv_cur + (conn->l4data->rcv_max * 2)))) {
			csp_debug(CSP_ERROR, "OPEN: Sequence number unacceptable\r\n");
			csp_rdp_send_cmp(conn, 1, 0, 0, conn->l4data->snd_nxt, conn->l4data->rcv_cur);
			goto discard_open;
		}

		/* SYN in OPEN is invalid */
		if (rx_header->syn == 1) {
			goto discard_close;
		}

		/* Increment Last Unacknowledged */
		if (rx_header->ack == 1) {
			if ((conn->l4data->snd_una <= rx_header->ack_nr) && (rx_header->ack_nr < conn->l4data->snd_nxt)) {
				conn->l4data->snd_una = rx_header->ack_nr + 1;
			}
			csp_rdp_flush_acked(conn);
		}

		/* If no data, return here */
		if (packet->length == 0) {
			goto discard_open;
		}

		/* Receive data */
		conn->l4data->rcv_cur = rx_header->seq_nr;
		if (csp_rdp_receive_data(conn, packet, pxTaskWoken)) {
			csp_rdp_send_cmp(conn, 1, 0, 0, conn->l4data->snd_nxt, conn->l4data->rcv_cur);
		} else {
			csp_debug(CSP_ERROR, "Cannot receive data, closing conn\r\n");
			goto discard_close;
		}

		goto accepted_open;

	}
	break;

	default:
		csp_debug(CSP_ERROR, "RDP: ERROR default state!\r\n");
		goto discard_close;
	}

discard_close:
	csp_buffer_free(packet);
	csp_conn_release(conn);
	conn->l4data->state = RDP_CLOSE_WAIT;
	if (conn->rx_socket == (void *) 1) {
		csp_debug(CSP_PROTOCOL, "Waiting for userpace to close\r\n");
		csp_close_wait(conn);
		return;
	} else {
		csp_debug(CSP_PROTOCOL, "Not passed to userspace, closing now\r\n");
		csp_close(conn);
		return;
	}

discard_open:
	csp_buffer_free(packet);
accepted_open:
	csp_conn_release(conn);
	return;

}

int csp_rdp_connect_active(csp_conn_t * conn, int timeout) {

	int retry = 1;

retry:

	csp_conn_wait(conn);

	csp_debug(CSP_PROTOCOL, "RDP: Active connect, conn state %u\r\n", conn->l4data->state);

	if (conn->l4data->state == RDP_OPEN) {
		printf("RDP: ERROR Connection already open\r\n");
		csp_conn_release(conn);
		return 0;
	}

	conn->l4data->snd_iss = 10;
	conn->l4data->snd_nxt = conn->l4data->snd_iss + 1;
	conn->l4data->snd_una = conn->l4data->snd_iss;
	conn->l4data->snd_max = 90;
	conn->l4data->rbuf_max = 90;
	conn->l4data->rcv_max = 10;

	csp_debug(CSP_PROTOCOL, "RDP: AC: Sending SYN\r\n");

	conn->l4data->state = RDP_SYN_SENT;
	if (csp_rdp_send_cmp(conn, 0, 1, 0, conn->l4data->snd_iss, 0) == 0) {
		goto error;
	}

	csp_debug(CSP_PROTOCOL, "RDP: AC: Waiting for SYN/ACK reply...\r\n");
	csp_conn_release(conn);

	csp_bin_sem_wait(&conn->l4data->tx_wait, 0);
	int result = csp_bin_sem_wait(&conn->l4data->tx_wait, timeout);

	if (!csp_conn_wait(conn)) {
		csp_debug(CSP_ERROR, "Conn forcefully closed by network stack\r\n");
		return 0;
	}

	if (result == CSP_SEMAPHORE_OK) {
		if (conn->l4data->state == RDP_OPEN) {
			csp_debug(CSP_PROTOCOL, "RDP: AC: Connection OPEN\r\n");
			csp_conn_release(conn);
			return 1;
		} else if(conn->l4data->state == RDP_SYN_SENT) {
			if (retry) {
				csp_debug(CSP_WARN, "RDP: Half-open connection detected, RST sent, now retrying\r\n");
				retry -= 1;
				goto retry;
			} else {
				csp_debug(CSP_ERROR, "RDP: Connection stayed half-open, even after RST and retry!\r\n");
				goto error;
			}
		}
	} else {
		csp_debug(CSP_PROTOCOL, "RDP: AC: Connection Failed\r\n");
		goto error;
	}

error:
	csp_conn_release(conn);
	if (conn->l4data != NULL)
		conn->l4data->state = RDP_CLOSE_WAIT;
	return 0;

}

int csp_rdp_send(csp_conn_t* conn, csp_packet_t * packet, int timeout) {

	if (!csp_conn_wait(conn))
		return 0;

	if (conn->l4data == NULL)
		return 0;

	if (conn->l4data->state != RDP_OPEN) {
		csp_debug(CSP_ERROR, "RDP: ERROR cannot send, connection reset by peer!\r\n");
		return 0;
	}

	csp_debug(CSP_PROTOCOL, "RDP: SEND\r\n");

	rdp_header_t * tx_header = csp_rdp_header_add(packet);
	memset(tx_header, 0, sizeof(rdp_header_t));
	tx_header->seq_nr = conn->l4data->snd_nxt;
	tx_header->ack_nr = conn->l4data->rcv_cur;
	tx_header->ack = 1;
	conn->l4data->snd_nxt += 1;

	/* Send copy to tx_queue */
	rdp_packet_t * rdp_packet = csp_buffer_get(packet->length+10);
	rdp_packet->timestamp = csp_get_ms();
	memcpy(&rdp_packet->length, &packet->length, packet->length+6);
	csp_queue_enqueue(conn->l4data->tx_queue, &rdp_packet, 0);

	csp_conn_release(conn);

	return 1;

}

int csp_rdp_allocate(csp_conn_t * conn) {

	csp_debug(CSP_BUFFER, "RDP: Malloc l4 data %p\r\n", conn);

	/* Allocate memory area for layer 4 information */
	conn->l4data = csp_malloc(sizeof(csp_l4data_t));
	if (conn->l4data == NULL)
		return 0;

	conn->l4data->state = RDP_CLOSED;

	/* Create a binary semaphore to wait on for tasks */
	if (csp_bin_sem_create(&conn->l4data->tx_wait) != CSP_SEMAPHORE_OK) {
		csp_free(conn->l4data);
		return 0;
	}

	conn->l4data->tx_queue = csp_queue_create(RDP_WINDOW_MAX, sizeof(csp_packet_t *));
	if (conn->l4data->tx_queue == NULL) {
		csp_bin_sem_remove(&conn->l4data->tx_wait);
		csp_free(conn->l4data);
		return 0;
	}

	return 1;

}

void csp_rdp_close(csp_conn_t * conn) {

	if (!csp_conn_wait(conn))
		csp_debug(CSP_ERROR, "Conn was closed, before rdp close call\r\n");

	if (conn->l4data->state != RDP_CLOSE_WAIT) {
		/* Send Reset */
		csp_debug(CSP_PROTOCOL, "RDP Close, sending RST on conn %p\r\n", conn);
		csp_rdp_send_reset(conn);
		conn->l4data->state = RDP_CLOSE_WAIT;
	}

	csp_debug(CSP_BUFFER, "RDP: Free l4 data %p\r\n", conn);

	csp_rdp_flush_all(conn);

	/* Deallocate memory */
	if (conn->l4data != NULL) {
		csp_queue_remove(conn->l4data->tx_queue);
		csp_bin_sem_remove(&conn->l4data->tx_wait);
		csp_free(conn->l4data);
		conn->l4data = NULL;
	}

	csp_conn_release(conn);

}

void csp_rdp_conn_print(csp_conn_t * conn) {

	if (conn->l4data == NULL)
		return;

	printf("\tRDP: State %u, rcv %u, snd %u\r\n", conn->l4data->state, conn->l4data->rcv_cur, conn->l4data->snd_una);

}
