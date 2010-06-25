/**
 * csp_transport.h
 *
 * @date: 24/06/2010
 * @author: Johan Christiansen
 *
 * This file must declare all transport layer functions used by CSP.
 *
 */

#ifndef CSP_TRANSPORT_H_
#define CSP_TRANSPORT_H_

/** ARRIVING SEGMENT */
void csp_udp_new_packet(csp_conn_t * conn, csp_packet_t * packet, CSP_BASE_TYPE * pxTaskWoken);
void csp_rdp_new_packet(csp_conn_t * conn, csp_packet_t * packet, CSP_BASE_TYPE * pxTaskWoken);

/** RDP: USER REQUESTS */
int csp_rdp_connect_active(csp_conn_t * conn, int timeout);
int csp_rdp_connect_passive(csp_conn_t * conn, csp_packet_t * packet);
int csp_rdp_allocate(csp_conn_t * conn);
void csp_rdp_close(csp_conn_t * conn);
void csp_rdp_conn_print(csp_conn_t * conn);
int csp_rdp_send(csp_conn_t* conn, csp_packet_t * packet, int timeout);

#endif /* CSP_TRANSPORT_H_ */
