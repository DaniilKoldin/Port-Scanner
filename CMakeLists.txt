cmake_minimum_required(VERSION 3.23)
project(Port_Scanner)


set(CMAKE_C_STANDARD 17)

add_executable(Port_Scanner
        scanner.c
#        Test/libs/syn_scanning.h
        libs/syn_scanning.c
        )

target_link_libraries(Port_Scanner resolv -lm)
