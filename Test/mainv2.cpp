int main(int argc, char **argv) {

    //  I think ifr cannot be pointer
    struct ifreq *ifr;      //  use for tcp and syn
    struct iphdr *iph;       //  ip-header struct
    struct tcphdr *tcph;      //  tcp-header struct

    int sender, listener, receiver;     //  sockets' descriptors
    int sent_b,                         //  number of sent bytes
    rec_b,                              //  number of  received bytes
    if_index;                           //  interface index
    u_char *pack;                       //  sent pack

    sockaddr_in remote;
    sockaddr_in local;
    hostent *hostname;

    //  initialization remote host params
    memset(&remote, 0, sizeof(struct sockaddr_in));
    if (!inet_aton(argv[1], &remote.sin_addr)) {
        if (!(hostname = gethostbyname(argv[1]))) {
            perror("Cant find host");
            exit(2);
        } else {
            remote.sin_addr.s_addr = htonl(*(u_long *) hostname->h_addr_list[0]);
        }
    }
    remote.sin_family = AF_INET;
    remote.sin_port = htons(atoi(argv[2]));

    //  initialization local host params
    memset(&local, 0, sizeof(struct sockaddr_in));
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    sprintf(ifr->ifr_name, "%s", "eth0");
    ioctl(fd, SIOCGIFADDR, ifr);
    memcpy((char *) &local, (char *) &(ifr->ifr_addr), sizeof(struct sockaddr));
    local.sin_port = htons(53);                                                     //  can be another port
    ioctl(fd, SIOCGIFINDEX, ifr);
    if_index = ifr->ifr_ifindex;

    //  creating sending packet
    pack = (u_char *) calloc(1, sizeof(struct iphdr) +
                                sizeof(struct tcphdr));              //  an error????????????????????????
    iph = (struct iphdr *) pack;
    tcph = (struct tcphdr *) (pack + sizeof(struct iphdr));
//    pseudo = (struct p_header *) ( pack + sizeof ( struct iphdr) - sizeof ( struct p_header ));   //  for check-sum


    sender = socket(AF_INET, SOCK_DGRAM, 0);
    listener = socket(AF_INET, SOCK_DGRAM, 0);
    u_int16_t beg_p = atoi(argv[2]);
    u_int16_t end_p = atoi(argv[3]);
    for (u_int16_t i = beg_p; i <= end_p; ++i) {
        remote.sin_port = i;
        if (connect(sender, (sockaddr *) &remote, sizeof(remote)) < 0) {
            perror("connect");
            exit(2);
        }
        listener = socket(AF_INET, SOCK_DGRAM, 0);
        if (bind(listener, (sockaddr *) &remote, sizeof(remote)) < 0) {
            perror("Cant find host");
            exit(2);
        }
        listen(listener, 1);
        if ((sendto(sender, 0/*data*/, 0, 0, (sockaddr *) &remote, sizeof remote)) < 0) {
            perror("sendto");
            exit(1);
        }
    }
    return 0;
}