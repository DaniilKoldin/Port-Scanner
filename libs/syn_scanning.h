#ifndef PORT_SCANNER_COMPRESSION_H
#define PORT_SCANNER_COMPRESSION_H

#ifndef PORT_SCANNER_SYN_SCANNING_H
#define PORT_SCANNER_SYN_SCANNING_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>

#include <stdlib.h>
#include <math.h>
#include <stdio.h>

#include <sys/ioctl.h>
#include <fcntl.h>

#include <time.h>
#include <sys/time.h>
#include <memory.h>
#include <unistd.h>
#include <asm/byteorder.h>

#define fatal(x) { fprintf(stderr, "%s\n", x); exit(-1); }
#define error(x) fprintf(stderr, "%s\n", x);
#define MAXHOSTNAMELEN 255
#define MAX_SOCKETS 36
#define MAGIC_PORT 49724


extern u_long num_ports;                //  number of ports

/*****************STRUCTURES****************/
typedef struct pseudo_header { //Needed for checksum calculation
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
} pseudo_header;

typedef struct port {
    unsigned short portno;
    unsigned char proto;
    char *owner;
    struct port *next;
} port;

typedef port *portlist;


/*****************Help functions****************/
void printusage(char *name);
void printandfreeports(portlist ports);
u_int16_t check_sum(unsigned short *ptr, int nbytes);
int isup(struct in_addr target);


/*****************PORT FUNCTIONS****************/
unsigned short *getpts(char *origexpr);
int addport(portlist *ports, unsigned short portno, u_int16_t protocol, char *owner);


/*****************SOCKET FUNCTIONS****************/
int unblock_socket(int sd);

/*****************SCANNING FUNCTIONS****************/
int send_tcp_raw( int sd, struct in_addr *source,
                  struct in_addr *victim, unsigned short sport,
                  unsigned short dport, unsigned long seq,
                  unsigned long ack, unsigned char flags,
                  unsigned short window, char *data,
                  unsigned short datalen);

portlist syn_scan(struct in_addr target, unsigned short *portarray,
                  portlist *ports);

//void prepare_datagram(char *datagram, struct in_addr local, struct in_addr remote,
//                      struct iphdr *iph, struct tcphdr *tcph);

#endif //PORT_SCANNER_SYN_SCANNING_H

#endif //PORT_SCANNER_COMPRESSION_H
