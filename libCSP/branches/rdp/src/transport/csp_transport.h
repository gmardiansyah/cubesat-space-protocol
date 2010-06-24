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

void csp_udp_new_packet(csp_conn_t * conn, csp_packet_t * packet, CSP_BASE_TYPE * pxTaskWoken);
void csp_rdp_new_packet(csp_conn_t * conn, csp_packet_t * packet, CSP_BASE_TYPE * pxTaskWoken);

#endif /* CSP_TRANSPORT_H_ */
