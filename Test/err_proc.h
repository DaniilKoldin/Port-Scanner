#ifndef PORT_SCANNER_ERR_PROC_H
#define PORT_SCANNER_ERR_PROC_H

#include <sys/socket.h>
#include <errno.h>

#include <iostream>
#include <string>

int Socket(int socket_family, int socket_type, int protocol);

#endif      //  PORT_SCANNER_ERR_PROC_H
