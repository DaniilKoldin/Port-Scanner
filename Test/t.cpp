#include <pthread.h>

#include <iostream>

void test(int some, char c){
    std::cout << "Hello from " << some << c;
}

struct argss{
    int arg1;
    char ch;
};
int main() {
    pthread_t tt;
    argss *args = (argss *)malloc(sizeof(argss));
    std::cin >> args->arg1 >> args->ch;
    if (pthread_create(&tt, NULL, (void *(*)(void *))(test), args) < 0) { //Thread to listen for just one SYN-ACK packet from any of the selected ports
        exit(2);
    }
    return 0;
}

