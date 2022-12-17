#ifndef PORT_SCANNER_UDP_SCAN_H
#define PORT_SCANNER_UDP_SCAN_H

#include "syn_scanning.h"
#include <errno.h>

int block_socket(int sd);

extern u_long num_ports;

portlist lamer_udp_scan(struct in_addr target, unsigned short *portarray,
                        portlist *ports);


#endif //PORT_SCANNER_UDP_SCAN_H
