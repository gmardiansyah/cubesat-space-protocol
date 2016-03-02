# CSP is now hosted at Github: #
# https://github.com/GomSpace/libcsp #


---


## About the Cubesat Space Protocol ##
Cubesat Space Protocol (CSP) is a small network-layer delivery protocol designed for Cubesats. The idea was developed by a group of students from Aalborg University in 2008, and further developed for the AAUSAT3 Cubesat mission scheduled for launch in 2011. The protocol is based on a 32-bit header containing both transport and network-layer information. Its implementation is designed for, but not limited to, embedded systems such as the 8-bit AVR microprocessor and the 32-bit ARM and AVR from Atmel. The implementation is written in GNU C and is currently ported to run on FreeRTOS or POSIX operating systems like Linux and BSD.

The three letter acronym CSP was originally an abbreviation for CAN Space Protocol because the first MAC-layer driver was written for CAN-bus. The physical layer has since been extended to include support for e.g. spacelink, I2C and RS232 interfaces and the name was thus changed to the more general Cubesat Space Protocol without changing the abbreviation.

The protocol and the implementation is today actively maintained by the students at Aalborg University and the spin-off company GomSpace ApS.

Notable features include:
  * Simple API similar to Berkeley sockets.
  * Router core with static routes. Supports transparent forwarding of packets over e.g. spacelink.
  * Support for both connectionless operation (similar to UDP), and connection oriented operation (RFC 908 and 1151).
  * Service handler that implements ICMP-like requests such as ping and buffer status.
  * Support for loopback traffic. This can e.g. be used for Inter-process communication between subsystem tasks.
  * Optional Support for broadcast traffic if supported by the physical interface.
  * Optional support for promiscuous mode if supported by the physical interface.
  * Optional support for encrypted packets with XTEA in CTR mode.
  * Optional support for RFC 2104 authenticated packets with truncated HMAC-SHA1.

The source code includes a MAC layer interface for CAN bus with support for fragmentation. Drivers are available for the Atmel AT90CAN128, Atmel AT91SAM7A1 and all hosts supporting the Linux SocketCAN framework, including the Analog Devices Blackfin DSPs. The CAN interface is easily extensible with new CPU architectures.

## Mailing List ##
You can join our Google groups list at http://groups.google.com/group/cubesat-space-protocol.