#ifndef PORT_SCANNER_SYN_SCANNING_H
#define PORT_SCANNER_SYN_SCANNING_H

#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <net/if.h>
#include <linux/if_ether.h>
//#include <sys/ioctl.h>
#include <linux/if_packet.h>        //  for pack sockets

#include <memory.h>                 //  for memset()
#include <unistd.h>
#include <iostream>

struct pseudo_header { //Needed for checksum calculation
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    tcphdr tcp;
};

void prepare_datagram(char *datagram, in_addr local, in_addr remote,
                      struct iphdr *iph, struct tcphdr *tcph);

unsigned short check_sum(unsigned short *ptr, int nbytes);

int set_send_sock();

int set_recv_sock();

#endif //PORT_SCANNER_SYN_SCANNING_H
