#include <netinet/in.h>
#include "err_proc.h"

int Socket(int socket_family, int socket_type, int protocol) {
    int fd = socket(socket_family, socket_type, protocol);
    if (fd < 0) {
        perror("Could not open the socket");
        exit(errno);
    }
    return fd;
}

//int Socket(int socket_family, int socket_type, int protocol) {
//    int fd = socket(socket_family, socket_type, protocol);
//    if (fd < 0) {
//        perror("Could not open the socket");
//        exit(errno);
//    }
//    return fd;
//}