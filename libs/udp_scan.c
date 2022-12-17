#include "udp_scan.h"

int block_socket(int sd) {
    int options;
    options = (~O_NONBLOCK) & fcntl(sd, F_GETFL);
    fcntl(sd, F_SETFL, options);
    return 1;
}

portlist lamer_udp_scan(struct in_addr target, unsigned short *portarray,
                        portlist *ports) {
    int sockaddr_in_size = sizeof(struct sockaddr_in),i=0,j=0,k=0, bytes;
    int sockets[max_parallel_sockets], trynum[max_parallel_sockets];
    unsigned short portno[max_parallel_sockets];
    int last_open = 0;
    char response[1024];
    struct sockaddr_in her, stranger;
    char data[] = "\nhelp\nquit\n";
    unsigned long sleeptime;
    unsigned int starttime;

/* Initialize our target sockaddr_in */
    bzero((char *) &her, sizeof(struct sockaddr_in));
    her.sin_family = AF_INET;
    her.sin_addr = target;

    if (debugging)
        printf("Initiating UDP scan against %s (%s)\n",
               gethostbyaddr((char *) &target.s_addr, 4, AF_INET)->h_name,
               inet_ntoa(target));

    starttime = time(NULL);

    for(i = 0 ; i < max_parallel_sockets; i++)
        trynum[i] =  portno[i] = 0;

    while(portarray[j]) {
        for(i=0; i < max_parallel_sockets && portarray[j]; i++, j++) {
            if (i >= last_open) {
                if ((sockets[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
                {perror("datagram socket troubles"); exit(1);}
                block_socket(sockets[i]);
                portno[i] = portarray[j];
            }
            her.sin_port = htons(portarray[j]);
            bytes = sendto(sockets[i], data, sizeof(data), 0, (struct sockaddr *) &her,
                           sizeof(struct sockaddr_in));
            usleep(5000);
            if (debugging > 1)
                printf("Sent %d bytes on socket %d to port %hi, try number %d.\n",
                       bytes, sockets[i], portno[i], trynum[i]);
            if (bytes < 0 ) {
                printf("Sendto returned %d the FIRST TIME!@#$!, errno %d\n", bytes,
                       errno);
                perror("");
                trynum[i] = portno[i] = 0;
                close(sockets[i]);
            }
        }
        last_open = i;
        /* Might need to change this to 1e6 if you are having problems*/
        usleep(5e5);
        for(i=0; i < last_open ; i++) {
            if (portno[i]) {
                unblock_socket(sockets[i]);
                if ((bytes = recvfrom(sockets[i], response, 1024, 0,
                                      (struct sockaddr *) &stranger,
                                      &sockaddr_in_size)) == -1)
                {
                    if (debugging > 1)
                        printf("2nd recvfrom on port %d returned %d with errno %d.\n",
                               portno[i], bytes, errno);
                    if (errno == EAGAIN)
                    {
                        if (trynum[i] < 2) trynum[i]++;
                        else {
                            if (debugging)
                                printf("Skipping possible false positive, port %d\n",
                                       portno[i]);
                            trynum[i] = portno[i] = 0;
                            close(sockets[i]);
                        }
                    }
                    else if (errno == ECONNREFUSED /*111*/) {
                        trynum[i] = portno[i] = 0;
                        close(sockets[i]);
                    }
                    else {
                        printf("Curious recvfrom error (%d) on port %hi: ",
                               errno, portno[i]);
                        perror("");
                        trynum[i] = portno[i] = 0;
                        close(sockets[i]);
                    }
                }
                else /*bytes is positive*/ {
                    if (debugging)
                        printf("Adding UDP port %d due to positive read!\n", portno[i]);
                    addport(ports,portno[i], IPPROTO_UDP, NULL);
                    trynum[i] = portno[i] = 0;
                    close(sockets[i]);
                }
            }
        }
        /* Update last_open, we need to create new sockets.*/
        for(i=0, k=0; i < last_open; i++)
            if (portno[i]) {
                close(sockets[i]);
                sockets[k] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                /*      unblock_socket(sockets[k]);*/
                portno[k] = portno[i];
                trynum[k] = trynum[i];
                k++;
            }
        last_open = k;
        for(i=k; i < max_parallel_sockets; i++)
            trynum[i] = sockets[i] = portno[i] = 0;
    }
    if (debugging)
        printf("UDP scanned %d ports in %ld seconds with %d parallel sockets\n",
               num_ports, time(NULL) - starttime, max_parallel_sockets);
    return *ports;
}
