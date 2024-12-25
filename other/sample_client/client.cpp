#include <stdio.h>

#ifdef __linux__
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "sample.h"



void send_to_server(const char *host, int port, const char *message)
{
    printf("send_to_server %s %d %s\n", host, port, message);
    #ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    #endif

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        printf("socket error\n");
        return;
    }

    #ifdef _WIN32
    struct sockaddr_in server;
    #endif

    const char *ip = host;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);
    connect(sock, (struct sockaddr *)&server, sizeof(server));
    send(sock, message, strlen(message), 0);
}

int main()
{
    EncHandler *enc = new EncHandler(key, iv);
    CryptoPP::byte outBuffer[16];
    enc->encrypt("hello", outBuffer);

    send_to_server("192.168.88.38", 8821, (char *)outBuffer);
    printf("Hello World %s \n", "aaaa");
    return 0;
}
