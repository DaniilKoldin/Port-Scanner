#include "syn_scanning.h"

struct in_addr ouraddr = { 0 };
unsigned long global_rtt = 0;        //  round time of transfering

/***********HELP FUNCTIONS*********/
void printusage(char *name) {
    printf("%s  dest-IP[/mask] [options]\n\
    options (none are required, most can be combined):\n\
    -s tcp SYN stealth port scan (must be root)\n\
    -u UDP port scan,\n\
    -M <positive number> set number of parallel ports\n\
    -d <positive number> set debug level to print additive indo\n\
    -p <range> ports: ex: \'-p 23\' will only try port 23 of the host(s)\n\
    \'-p 20-30,63000-\' scans 20-30 and 63000-65535 default: 1-1024\'\n",
           name);
    exit(1);
}

u_int16_t check_sum(unsigned short *ptr, int nbytes) {
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

void printandfreeports(portlist ports) {
    char protocol[4];
    struct servent *service;
    port *current = ports, *tmp;

    printf("Port Number  Protocol  Service\n");
    while(current != NULL) {
        strcpy(protocol,(current->proto == IPPROTO_TCP)? "tcp": "udp");
        service = getservbyport(htons(current->portno), protocol);
        printf("%-13d%-11s%-16s%s\n", current->portno, protocol,
               (service) ? service->s_name: "unknown",
               (current->owner)? current->owner : "");
        tmp = current;
        current = current->next;
        if (tmp->owner) free(tmp->owner);
        free(tmp);
    }
    printf("\n");
}

int isup(struct in_addr target) {
    int res, retries = 3;
    struct sockaddr_in sock;
    /*type(8bit)=8, code(8)=0 (echo REQUEST), checksum(16)=34190, id(16)=31337 */
#ifdef __LITTLE_ENDIAN_BITFIELD
    unsigned char ping[64] = { 0x8, 0x0, 0x8e, 0x85, 0x69, 0x7A };
#else
    unsigned char ping[64] = { 0x8, 0x0, 0x85, 0x8e, 0x7A, 0x69 };
#endif
    int sd;
    struct timeval tv;
    struct timeval start, end;
    fd_set fd_read;
    struct {
        struct iphdr ip;
        unsigned char type;
        unsigned char code;
        unsigned short checksum;
        unsigned short identifier;
        char crap[16536];
    }  response;

    sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    bzero((char *)&sock,sizeof(struct sockaddr_in));
    sock.sin_family=AF_INET;
    sock.sin_addr = target;
    while(--retries) {
        if ((res = sendto(sd,(char *) ping,64,0,(struct sockaddr *)&sock,
                          sizeof(struct sockaddr))) != 64) {
            fprintf(stderr, "sendto in isup returned %d! skipping host.\n", res);
            return 0;
        }
        FD_ZERO(&fd_read);
        FD_SET(sd, &fd_read);
        tv.tv_sec = 0;
        tv.tv_usec = 1e6 * (2 / 3.0);
        while(1) {
            if ((res = select(sd + 1, &fd_read, NULL, NULL, &tv)) != 1)
                break;
            else {
                read(sd,&response,sizeof(response));
                if  (response.ip.saddr == target.s_addr &&  !response.type
                     && !response.code   && response.identifier == 31337) {
                    gettimeofday(&end, NULL);
                    global_rtt = (end.tv_sec - start.tv_sec) * 1e6 + end.tv_usec - start.tv_usec;
                    ouraddr.s_addr = response.ip.daddr;
                    close(sd);
                    return 1;
                }
            }
        }
    }
    close(sd);
    return 0;
}


/******************PORT FUNCTIONS*******************/
unsigned short *getpts(char *origexpr) {
    int exlen = strlen(origexpr);
    char *p,*q;
    unsigned short *tmp, *ports;
    int i=0, j=0,start,end;
    char *expr = strdup(origexpr);
    ports = (unsigned short *)malloc(65536 * sizeof(short));
    for(;j < exlen; j++)
        if (expr[j] != ' ') expr[i++] = expr[j];
    expr[i] = '\0';
    exlen = i + 1;
    i=0;
    while((p = strchr(expr,','))) {
        *p = '\0';
        if (*expr == '-') {start = 1; end = atoi(expr+ 1);}
        else {
            start = end = atoi(expr);
            if ((q = strchr(expr,'-')) && *(q+1) ) end = atoi(q + 1);
            else if (q && !*(q+1)) end = 65535;
        }
        if (start < 1 || start > end) fatal("Your port specifications are illegal!");
        for(j=start; j <= end; j++)
            ports[i++] = j;
        expr = p + 1;
    }
    if (*expr == '-') {
        start = 1;
        end = atoi(expr+ 1);
    }
    else {
        start = end = atoi(expr);
        if ((q =  strchr(expr,'-')) && *(q+1) ) end = atoi(q+1);
        else if (q && !*(q+1)) end = 65535;
    }
    if (start < 1 || start > end) fatal("Your port specifications are illegal!");
    for(j=start; j <= end; j++)
        ports[i++] = j;
    ports[i++] = 0;
    tmp = (unsigned short *)realloc(ports, i * sizeof(short));
    free(expr);
    return tmp;
}

int addport(portlist *ports, unsigned short portno, unsigned short protocol,
            char *owner) {
    struct port *current, *tmp;
    int len;

    num_ports++;
    if (*ports) {
        current = *ports;
        /* case 1: we add to the front of the list */
        if (portno <= current->portno) {
            if (current->portno == portno && current->proto == protocol) {
                return -1;
            }
            tmp = current;
            *ports = (port *)malloc(sizeof(struct port));
            (*ports)->next = tmp;
            current = *ports;
            current->portno = portno;
            current->proto = protocol;
            if (owner && *owner) {
                len = strlen(owner);
                current->owner = (char *)malloc(sizeof(char) * (len + 1));
                strncpy(current->owner, owner, len + 1);
            }
            else current->owner = NULL;
        }
        else { /* case 2: we add somewhere in the middle or end of the list */
            while( current->next  && current->next->portno < portno)
                current = current->next;
            if (current->next && current->next->portno == portno
                && current->next->proto == protocol) {
                return -1;
            }
            tmp = current->next;
            current->next = (port *)malloc(sizeof(struct port));
            current->next->next = tmp;
            tmp = current->next;
            tmp->portno = portno;
            tmp->proto = protocol;
            if (owner && *owner) {
                len = strlen(owner);
                tmp->owner = (char *)malloc(sizeof(char) * (len + 1));
                strncpy(tmp->owner, owner, len + 1);
            }
            else tmp->owner = NULL;
        }
    }

    else { /* Case 3, list is null */
        *ports = (port *)malloc(sizeof(struct port));
        tmp = *ports;
        tmp->portno = portno;
        tmp->proto = protocol;
        if (owner && *owner) {
            len = strlen(owner);
            tmp->owner = (char *)malloc(sizeof(char) * (len + 1));
            strncpy(tmp->owner, owner, len + 1);
        }
        else tmp->owner = NULL;
        tmp->next = NULL;
    }
    return 0; /*success */
}



/*******************SOCKET FUNCTIONS*****************/
int unblock_socket(int sd) {
    int options;
/*Unblock our socket to prevent recvfrom from blocking forever
  on certain target ports. */
    options = O_NONBLOCK | fcntl(sd, F_GETFL);
    fcntl(sd, F_SETFL, options);
    return 1;
}

/*****************SCANNING FUNCTIONS****************/
portlist syn_scan(struct in_addr target, unsigned short *portarray, portlist *ports) {
    int received, bytes, starttime;
    struct sockaddr_in from;
    int fromsize = sizeof(struct sockaddr_in);
    int sockets[max_parallel_sockets];
    struct timeval tv;
    char packet[65535];
    struct iphdr *ip = (struct iphdr *) packet;
    struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));
    fd_set fd_read, fd_write;
    int res;
    struct in_addr *source;
    u_char source_malloc = 0;
    char myname[MAXHOSTNAMELEN + 1];
    struct hostent *myhostent;

    FD_ZERO(&fd_read);
    FD_ZERO(&fd_write);

    tv.tv_sec = 7;
    tv.tv_usec = 0;

    if ((received = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0 )
        perror("socket troubles in syn_scan");
    unblock_socket(received);
    FD_SET(received, &fd_read);

    if (ouraddr.s_addr) {
        source = &ouraddr;
    }
    else {
        source = malloc(sizeof(struct in_addr));
        source_malloc = 1;
        if (gethostname(myname, MAXHOSTNAMELEN) ||
            !(myhostent = gethostbyname(myname)))
        fatal("Your network system isn't works.\n");
        memcpy(source, myhostent->h_addr_list[0], sizeof(struct in_addr));
    }

    starttime = time(NULL);
    int j = 0;
    do {
        for(int i=0; i < max_parallel_sockets && portarray[j]; i++) {
            if ((sockets[i] = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
                perror("socket troubles in syn_scan");
            else {
                send_tcp_raw(sockets[i], source, &target, MAGIC_PORT,
                             portarray[j++], 0, 0, TH_SYN, 0, 0, 0);
            }
//            usleep(10000);
        }
        if ((res = select(received + 1, &fd_read, NULL, NULL, &tv)) < 0)
            perror("select problems in syn_scan");
        else if (res > 0) {
            while  ((bytes = recvfrom(received, packet, 65535, 0,
                                      (struct sockaddr *)&from, &fromsize)) > 0 ) {
                if (ip->saddr == target.s_addr) {
                    if (tcp->th_flags & TH_RST) {
                        if (debugging > 1)
                            printf("Nothing open on port %d\n",
                                   ntohs(tcp->th_sport));
                    }
                    else {
                        addport(ports, ntohs(tcp->source),
                                IPPROTO_TCP, NULL);
                    }
                }
            }
        }
        for(int i=0; i < max_parallel_sockets && portarray[j]; i++) close(sockets[i]);
    } while (portarray[j]);
    if (debugging)
        printf("The TCP SYN scan took %ld seconds to scan %d ports.\n",
            time(NULL) - starttime, num_ports);
    close(received);
    return *ports;
}

int send_tcp_raw( int sd, struct in_addr *source,
                  struct in_addr *victim, unsigned short sport,
                  unsigned short dport, unsigned long seq,
                  unsigned long ack, unsigned char flags,
                  unsigned short window, char *data,
                  unsigned short datalen)
{
    struct pseudo_header {
        unsigned long s_addr;
        unsigned long d_addr;
        char zer0;
        unsigned char protocol;
        unsigned short length;
    };
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + datalen];
    /*With these placement we get data and some field alignment so we aren't
      wasting too much in computing the checksum */
    struct iphdr *ip = (struct iphdr *) packet;
    struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));
    struct pseudo_header *pseudo =  (struct pseudo_header *) (packet + sizeof(struct iphdr) - sizeof(struct pseudo_header));
    int res;
    struct sockaddr_in sock;
    char myname[MAXHOSTNAMELEN + 1];
    struct hostent *myhostent;
    int source_malloced = 0;

/* check that required fields are there and not too silly */
    if ( !victim || !sport || !dport || sd < 0) {
        fprintf(stderr, "send_tcp_raw: One or more of your parameters are bad!\n");
        return -1;
    }

/* if they didn't give a source address, fill in our first address */
    if (!source) {
        source_malloced = 1;
        source = malloc(sizeof(struct in_addr));
        if (gethostname(myname, MAXHOSTNAMELEN) ||
            !(myhostent = gethostbyname(myname)))
        fatal("Your network system isn't works.\n");
        memcpy(source, myhostent->h_addr_list[0], sizeof(struct in_addr));
    }

    sock.sin_family = AF_INET;
    sock.sin_port = htons(dport);
    sock.sin_addr.s_addr = victim->s_addr;

    bzero(packet, sizeof(struct iphdr) + sizeof(struct tcphdr));

    pseudo->s_addr = source->s_addr;
    pseudo->d_addr = victim->s_addr;
    pseudo->protocol = IPPROTO_TCP;
    pseudo->length = htons(sizeof(struct tcphdr) + datalen);

    tcp->source = htons(sport);
    tcp->dest = htons(dport);
    if (seq)
        tcp->th_seq = htonl(seq);
    else tcp->th_seq = rand() + rand();

    if (flags & TH_ACK && ack)
        tcp->th_ack = htonl(seq);
    else if (flags & TH_ACK)
        tcp->th_ack = rand() + rand();

    tcp->doff = 5 /*words*/;
    tcp->th_flags = flags;

    if (window)
        tcp->th_win = window;
    else tcp->th_win = htons(2048);

    tcp->th_sum = check_sum((unsigned short *)pseudo, sizeof(struct tcphdr) +
                                                      sizeof(struct pseudo_header) + datalen);

/* Now for the ip header */
    bzero(packet, sizeof(struct iphdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + datalen);
    ip->id = rand();
    ip->ttl = 255;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = source->s_addr;
    ip->daddr = victim->s_addr;
    ip->check = check_sum((unsigned short *)ip, sizeof(struct iphdr));

    if ((res = sendto(sd, packet, ntohs(ip->tot_len), 0,
                      (struct sockaddr *)&sock, sizeof(struct sockaddr_in))) == -1)
    {
        perror("sendto in send_tcp_raw");
        if (source_malloced) free(source);
        return -1;
    }

    if (source_malloced) free(source);
    return res;
}
