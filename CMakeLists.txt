cmake_minimum_required(VERSION 3.23)
project(Port_Scanner)


set(CMAKE_C_STANDARD 11)

add_executable(Port_Scanner
        scanner.c
        libs/udp_scan.h
        libs/udp_scan.c
        libs/syn_scanning.h
        libs/syn_scanning.c
        )

target_link_libraries(Port_Scanner resolv -lm)
