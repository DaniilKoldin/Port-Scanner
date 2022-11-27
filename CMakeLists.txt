cmake_minimum_required(VERSION 3.23)
project(Port_Scanner)


set(CMAKE_CXX_STANDARD 17)

#add_link_options(Port_Scanner -lresolv)

add_executable(Port_Scanner
        Test/scanner.cpp
        Test/libs/syn_scanning.cpp
#        Test/t.cpp
        )

target_link_libraries(Port_Scanner resolv)
