#include "./libs/syn_scanning.h"


/*GLOBAL FLAGS*/
u_char udpscan=0, synscan=0, lamerscan = 0;
u_char max_parallel_sockets= MAX_SOCKETS;
u_long num_ports;
u_short *ports = NULL;
u_char is_root = 0;

int parse_cidr(const char *cidr, struct in_addr *addr, struct in_addr *mask);

void parse_com_str(int argc, char *fakeargv[]);

void parse_target(char *target, struct in_addr *target_in_addr, struct in_addr *last_addr);

int main(int argc, char **argv) {
    u_long num_ports;
    struct in_addr cur_addr, last_addr;
    u_int32_t cur_ip, last_ip;
    u_long test = 65510;
    portlist openports;
    struct hostent *host;
    struct in_addr *source;
    char *fakeargv[argc + 1];

    is_root = !(geteuid());
    if ((synscan) && !is_root)
        fatal("Options specified require root privileges. You don't have them!");

    for(int i=0; i < argc; i++) {
        fakeargv[i] = malloc(strlen(argv[i]) + 1);
        strncpy(fakeargv[i], argv[i], strlen(argv[i]) + 1);
    }
    fakeargv[argc] = NULL;
    parse_com_str(argc, fakeargv);

    if (!ports) ports = getpts("1-1024");

    /*GETTING TARGETS*/
    parse_target(argv[1], &cur_addr, &last_addr);
    cur_ip = ntohl(cur_addr.s_addr);
    last_ip = ntohl(last_addr.s_addr);

    while (cur_ip <= last_ip) {
        char *cur_name = malloc(MAXHOSTNAMELEN * (sizeof(char)));
        u_short hostup = 0;
        openports = NULL;
        cur_addr.s_addr = htonl(cur_ip);
        host = gethostbyaddr((char *) &cur_ip, 4, AF_INET);
        if (host)
            strncpy(cur_name, host->h_name, MAXHOSTNAMELEN);
        else cur_name[0] = '\0';
        cur_name[MAXHOSTNAMELEN + 1] = '\0';
        if (is_root) {
            if (!(hostup = isup(cur_addr))) {
                printf("Host %s (%s) appears to be  down\n",
                       cur_name, inet_ntoa(cur_addr));
            } else hostup = 1;
        }

        /* Time for some actual scanning! */
        if (hostup) {
            if (synscan) syn_scan(cur_addr, ports, &openports);

//        if (udpscan) {
//            if (!is_root || lamerscan)
//                lamer_udp_scan(cur_addr, ports, &openports);
//
//            else udp_scan(cur_addr, ports, &openports);
//        }

            if (openports) {
                printf("Open ports on %s (%s):\n", cur_name,
                       inet_ntoa(cur_addr));
                printandfreeports(openports);
            }
        }
        ++cur_ip;
    }



    return 0;
}

int parse_cidr(const char *cidr, struct in_addr *addr, struct in_addr *mask) {
    int bits = inet_net_pton(AF_INET, cidr, addr, sizeof(addr));
    mask->s_addr = htonl(~(bits == 32 ? 0 : ~0U >> bits));
    return bits;
}


void parse_target(char *target, struct in_addr *target_in_addr, struct in_addr *last_addr) {
    struct in_addr parsed_addr,
            mask_addr,
            network_addr;

    int bits = parse_cidr(target, &parsed_addr, &mask_addr);
    if (bits == -1) {
        perror("Invalid network address: %s\nValid example: 166.104.0.0/16\n");
        exit(2);
    }

    network_addr = parsed_addr;
    network_addr.s_addr &= mask_addr.s_addr;

    *target_in_addr = parsed_addr;
    *last_addr = parsed_addr;
    if (network_addr.s_addr != (parsed_addr.s_addr | ~(mask_addr.s_addr))) {
        target_in_addr->s_addr = htonl(ntohl(target_in_addr->s_addr) + 1);
        last_addr->s_addr = htonl(ntohl(network_addr.s_addr | ~(mask_addr.s_addr)) - 1);
    }
}

void parse_com_str(int argc, char *fakeargv[]){
    int arg;
    while((arg = getopt(argc,fakeargv,"lM:p:s")) != EOF) {
        switch(arg) {
            case 'h':
            case '?': printusage(fakeargv[0]); break;
            case 'l': lamerscan++; udpscan++; break;
            case 'M': max_parallel_sockets = atoi(optarg); break;
            case 'p':
                if (ports)
                    fatal("Only 1 -p option allowed, separate multiple ranges with commas.");
                ports = getpts(optarg); break;
            case 's': synscan++; break;
        }
    }
}
