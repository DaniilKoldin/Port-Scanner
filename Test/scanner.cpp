#include <netinet/in.h>             //  for sockaddr_in
#include <netdb.h>                  //  for hostent
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <pthread.h>

#include <iostream>
#include <cmath>
//#include <stdio.h>
//#include <set>

#include "./libs/syn_scanning.h"

//char *hostname_to_ip(char *hostname);

int parse_cidr(const char *cidr, struct in_addr *addr, struct in_addr *mask);

//void get_local_host(sockaddr_in *local);

void parse_target(char *target, struct in_addr *target_in_addr,
        u_int64_t *num_hosts);

void process_packet(unsigned char* buffer,
                    in_addr remote, u_int64_t open_hosts);

int start_sniffer(in_addr remote, u_int64_t open_hosts);

int main(int argc, char **argv) {
    sockaddr_in local;
    ifreq ifr;
    double program_duration;
    struct timespec start_time, finish_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    sockaddr_in remote_host;
    u_int64_t num_hosts;

    parse_target(argv[1], (in_addr *) &remote_host, &num_hosts);
    u_int16_t beg_port = atoi(argv[2]);
    u_int16_t end_port = atoi(argv[3]);
//    get_local_host(&local);
    int sender = set_send_sock();
    for (int cur_host = 0; cur_host < num_hosts; cur_host++) {
        if (remote_host.sin_addr.s_addr == -1) {
            perror("Invalid address\n");
            exit(2);
        }
        remote_host.sin_family = AF_INET;
        char datagram[4096];
        iphdr *iph = (struct iphdr *) datagram; //IP header
        tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct iphdr)); //TCP header

        prepare_datagram(datagram, local.sin_addr, remote_host.sin_addr, iph, tcph);

        pthread_t sniffer_thread;
        if (pthread_create(&sniffer_thread, NULL, (void *(*)(void *))(start_sniffer), NULL) < 0) { //Thread to listen for just one SYN-ACK packet from any of the selected ports
            printf("Could not create sniffer thread. Error number: %d. Error message: %s\n", errno, strerror(errno));
            exit(2);
        }

        for (int cur_port = beg_port;
             cur_port <= end_port; ++cur_port) { //Iterate all selected ports and send SYN packet all at once
            struct pseudo_header psh;

            tcph->dest = htons(cur_port);
            tcph->check = 0;

            psh.source_address = local.sin_addr.s_addr;
            psh.dest_address = remote_host.sin_addr.s_addr;
            psh.placeholder = 0;
            psh.protocol = IPPROTO_TCP;
            psh.tcp_length = htons(sizeof(struct tcphdr));

            memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

            tcph->check = check_sum((unsigned short *) &psh, sizeof(struct pseudo_header));

            // printf("[DEBUG] Sending SYN packet to %s:%d\n", target, port);
            // fflush(stdout);
            if (sendto(sender, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                       (struct sockaddr *) &remote_host, sizeof(remote_host)) < 0) {
                printf("Error sending syn packet. Error number: %d. Error message: %s\n", errno, strerror(errno));
                exit(2);
            }
        }
        pthread_join(sniffer_thread, NULL); //Will wait for the sniffer to receive a reply, host is considered closed if there aren't any
        remote_host.sin_addr.s_addr = htonl(ntohl(remote_host.sin_addr.s_addr) + 1);
    }
    clock_gettime(CLOCK_MONOTONIC, &finish_time);
    program_duration = (finish_time.tv_sec - start_time.tv_sec);
    program_duration += (finish_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;

    int hours_duration = program_duration / 3600;
    int mins_duration = (int)(program_duration / 60) % 60;
    double secs_duration = fmod(program_duration, 60);

    printf("Scan duration    : %d hour(s) %d min(s) %.05lf sec(s)\n", hours_duration, mins_duration, secs_duration);

    return 0;
}

void process_packet(unsigned char* buffer,
                    in_addr remote, u_int64_t open_hosts)
{
    iphdr* iph = (struct iphdr*)buffer; //IP Header part of this packet
    sockaddr_in source, dest;
    unsigned short iphdrlen;

    if (iph->protocol == 6) {
        struct iphdr* iph = (struct iphdr*)buffer;
        iphdrlen = iph->ihl * 4;

        struct tcphdr* tcph = (struct tcphdr*)(buffer + iphdrlen);

        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;

        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;

        if (tcph->syn == 1 && tcph->ack == 1 && source.sin_addr.s_addr == remote.s_addr) {
            printf("Port %d open\n", ntohs(tcph->source));
            fflush(stdout);

            ++open_hosts;
        }
    }
}

int start_sniffer(in_addr remote, u_int64_t open_hosts)
{
    int sock_raw;
    socklen_t saddr_size;
    int data_size;
    struct sockaddr_in saddr;

    unsigned char* buffer = (unsigned char*)malloc(65536);

    //Create a raw socket that shall sniff
    sock_raw = set_recv_sock();
    if (sock_raw < 0) {
        printf("Socket Error\n");
        fflush(stdout);
        return 1;
    }

    saddr_size = sizeof(saddr);

    //Receive a packet
    data_size = recvfrom(sock_raw, buffer, 65536, 0, (sockaddr*)&saddr, &saddr_size);

    if (data_size < 0) {
        printf("Recvfrom error, failed to get packets\n");
        fflush(stdout);
        return 1;
    }
    process_packet(buffer, remote, open_hosts);
    close(sock_raw);

    return 0;
}

//  Filling remote host Address params
//    std::set<int> targets; //  Set of  target sockets

int parse_cidr(const char *cidr, struct in_addr *addr, struct in_addr *mask) {
    int bits = inet_net_pton(AF_INET, cidr, addr, sizeof(addr));
    mask->s_addr = htonl(~(bits == 32 ? 0 : ~0U >> bits));
    return bits;
}

//void get_local_host(sockaddr_in *local) {
//    memset(local, 0, sizeof(struct sockaddr_in));
//    int fd = socket(AF_INET, SOCK_DGRAM, 0);
//    sprintf(ifr->ifr_name, "%s", "wlan0");
//    ioctl(fd, SIOCGIFADDR, (void *)ifr);
//    memcpy((char *) local, (char *) &(ifr->ifr_addr), sizeof(struct sockaddr));
//    local->sin_port = htons(53);
//    ioctl(fd, SIOCGIFINDEX, ifr);
//    close(fd);
//}

char *hostname_to_ip(char *hostname) {
    struct hostent *he;
    struct in_addr **addr_list;

    if ((he = gethostbyname(hostname)) == NULL) {
        perror("gethostbyname");
        exit(2);
    }

    addr_list = (struct in_addr **) he->h_addr_list;

    if (inet_ntoa(*addr_list[0]) != NULL)
        return inet_ntoa(*addr_list[0]); //Return the first one;

    return NULL;
}

void parse_target(char *target, struct in_addr *target_in_addr, u_int64_t *num_hosts) {
    struct in_addr parsed_addr,
            mask_addr,
            wildcard_addr,
            network_addr,
            broadcast_addr,
            min_addr,
            max_addr;

    int bits = parse_cidr(target, &parsed_addr, &mask_addr);
    if (bits == -1) {
        perror("Invalid network address: %s\nValid example: 166.104.0.0/16\n");
        exit(2);
    }

    wildcard_addr = mask_addr;
    wildcard_addr.s_addr = ~wildcard_addr.s_addr;

    network_addr = parsed_addr;
    network_addr.s_addr &= mask_addr.s_addr;

    broadcast_addr = parsed_addr;
    broadcast_addr.s_addr |= wildcard_addr.s_addr;

    min_addr = network_addr;
    max_addr = broadcast_addr;

    if (network_addr.s_addr != broadcast_addr.s_addr) {
        min_addr.s_addr = htonl(ntohl(min_addr.s_addr) + 1);
        max_addr.s_addr = htonl(ntohl(max_addr.s_addr) - 1);
    }

    *target_in_addr = min_addr;
    *num_hosts = (int64_t) ntohl(broadcast_addr.s_addr) - ntohl(network_addr.s_addr) + 1;
}


//  functions for syn-scanning
//  func for setting sending socket parameters


