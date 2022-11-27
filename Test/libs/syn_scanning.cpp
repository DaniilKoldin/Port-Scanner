#include "syn_scanning.h"

void prepare_datagram(char *datagram, in_addr local, in_addr remote,  struct iphdr *iph, struct tcphdr *tcph) {
    memset(datagram, 0, 4096);

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htons(46156); //Id of this packet
    iph->frag_off = htons(16384);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = local.s_addr; //Spoof the source ip address
    iph->daddr = remote.s_addr;
    iph->check = check_sum((unsigned short *) datagram, iph->tot_len >> 1);

    //TCP Header
    tcph->source = htons(46156); //Source Port
    tcph->dest = htons(80);
    tcph->seq = htonl(1105024978);
    tcph->ack_seq = 0;
    tcph->doff = sizeof(struct tcphdr) / 4; //Size of tcp header
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(14600); //Maximum allowed window size
    tcph->check = 0; //If you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
    tcph->urg_ptr = 0;
}

int set_send_sock() {
    int fd;
    const int one_value = 1;
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {    //TODO: debug fd=-1
        perror("Unable to create socket");
        return (-1);
    }
    //  set options for raw_socket, editing pack ip_header
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, (const void *) &one_value, sizeof(one_value)) < 0) {
        perror("unable to set option IP_HDRINCL");
        close(fd);
        return (-1);
    }
    return fd;
}

//  func for setting receiving socket parameters
int set_recv_sock() {
    int fd;
    //  creating of pack socket for receiving data
    if ((fd = socket(AF_PACKET, SOCK_DGRAM, IPPROTO_TCP)) < 0) {
        perror("unable to create socket");
        return (-1);
    }
    return fd;
}

unsigned short check_sum(unsigned short *ptr, int nbytes) {
    long sum;
    short answer;
    unsigned short oddbyte;
    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) &oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short) ~sum;
    return answer;
}
