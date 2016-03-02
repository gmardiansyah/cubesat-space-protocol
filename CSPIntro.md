# Introduction #
This guide is a short introduction to CSP. The guide includes compiling the library, initialization code and examples of a server and a client.

# Compiling libcsp with Makefile #
The Makefile takes 3 defines as arguments:
  * ARCH specifies the CSP architecture. Posix or FreeRTOS are valid options.
  * TOOLCHAIN specifies the prefix for the gcc commands. Use e.g. TOOLCHAIN=avr- to call avr-gcc, avr-ld etc.
  * OUTDIR specifies the output directory for libcsp.a

### Compiling for AVR8 with FreeRTOS ###
```
make ARCH=freertos TOOLCHAIN=avr- OUTDIR=. clean all
```

### Compiling for x86/x86\_64 with Posix compliant system ###
```
make ARCH=posix TOOLCHAIN= OUTDIR=. clean all
```

# Compiling libcsp with Eclipse IDE #
_Johan, please write this_

# CSP initialization sequence #
This code initializes the CSP buffer system, device drivers and router core. The example uses the CAN interface function `csp_can_tx` but the initialization is similar for other interfaces. The loopback interface does not require any explicit initialization.
```
/* Define subsystem address to 0 */
#define MY_ADDRESS  0

/* Use promisc mode on CAN (1 = yes, 0 = no) */
#define CAN_PROMISC 0

/* Init buffer system with 12 elements of 320 bytes each */
csp_buffer_init(12, 320);

/* Init CSP with address MY_ADDRESS */
csp_init(MY_ADDRESS);

/* Init the CAN interface without promisc mode */
csp_can_init(MY_ADDRESS, CAN_PROMISC);

/* Setup default route to CAN interface */
csp_route_set("CAN", CSP_DEFAULT_ROUTE, &csp_can_tx, CSP_HOST_MAC);

/* Start router task with 500 word stack, OS task priority 1 */
csp_route_start_task(500, 1);
```
# Creating a server #
This example shows how to create a server task that listens for incoming connections. CSP should be initialized before starting this task. Note the use of `csp_service_handler()` as the default branch in the port switch case. The service handler will automatically reply to e.g. ping requests and memory status requests.
```
void csp_task(void * parameters) {
    /* Create socket without any socket options */
    csp_socket_t * sock = csp_socket(0);

    /* Bind all ports to socket*/
    csp_bind(sock, CSP_ANY);

    /* Create 10 connections backlog queue */
    csp_listen(sock, 10);

    /* Pointer to current connection and packet */
    csp_conn_t * conn;
    csp_packet_t * packet;

    /* Process incoming connections */
    while (1) {
        /* Wait for connection, 10000 ms timeout */    
        if ((conn = csp_accept(sock, 10000)) == NULL)
            continue;

        /* Read packets. Timout is 1000 ms */
        while ((packet = csp_read(conn, 1000)) != NULL) {
            
            switch (csp_conn_dport(conn)) {

                case MY_PORT:
                    
                    /* Process packet here */
                    
                default:
                    /* Let the service handler reply pings, memory use, etc. */
                    csp_service_handler(conn, packet);
                    break;

            }

        }

        /* Close current connection, and handle next */
        csp_close(conn);

    }
}
```

# Creating a client #
This example shows how to allocate a packet buffer, connect to another host and send the packet. CSP should be initialized before calling this function.
```
void send_packet(void) {
    /* Get packet buffer for data */
    csp_packet_t * packet = csp_buffer_get(data_size);
    if (packet == NULL) {
        /* Could not get buffer element */
        printf("Failed to get buffer element\n");
        return -1;
    }

    /* Connect to host HOST, port PORT with regular UDP-like protocol and 1000 ms timeout */
    csp_conn_t * conn = csp_connect(CSP_PRIO_NORM, HOST, PORT, 1000, 0);
    if (conn == NULL) {
        /* Connect failed */
        printf("Connection failed\n");
        /* Remember to free packet buffer */
        csp_buffer_free(packet);
        return -1;
    }

    /* Copy dummy data to packet (Note potential buffer overflow) */
    char * msg = "HELLO";
    strcpy(packet->data, dummy);

    /* Set packet length */
    packet->length = strlen(msg);

    /* Send packet */
    if (!csp_send(conn, packet, 1000)) {
        /* Send failed */
        printf("Send failed\n");
        csp_buffer_free(packet);
    }

    /* Close connection */
    csp_close(conn);
}
```