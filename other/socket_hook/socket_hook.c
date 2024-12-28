#include <stdio.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// hook all socket calls

int socket(int domain, int type, int protocol) {
    static int (*real_socket)(int, int, int) = NULL;
    if (!real_socket) {
        real_socket = dlsym(RTLD_NEXT, "socket");
    }


    FILE *fd = fopen("/tmp/socket.log", "a");
    fprintf(fd, "socket() called %i %i %i\n", domain, type, protocol);
    return real_socket(domain, type, protocol);
}

#ifdef __APPLE__
int connect_hook(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
#else
static inline int connect_hook(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
    if (!real_connect) {
        real_connect = dlsym(RTLD_NEXT, "connect");
    }
#endif
    FILE *fd = fopen("/tmp/socket.log", "a");

    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
        char *ip = inet_ntoa(addr_in->sin_addr);
        int port = ntohs(addr_in->sin_port);
        fprintf(fd, "connect() called %s %i\n", ip, port);
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) addr;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip, INET6_ADDRSTRLEN);
        int port = ntohs(addr_in6->sin6_port);
        fprintf(fd, "connect() called %s %i\n", ip, port);
    } else if (addr-> sa_family == AF_UNIX) {
        struct sockaddr_un *addr_un = (struct sockaddr_un *) addr;
        fprintf(fd, "connect() called for UNIX socket %s\n", addr_un->sun_path);
    } else {
        fprintf(fd, "connect() called unknown address family %i\n", addr->sa_family);
    }
#ifdef __APPLE__
    return connect(sockfd, addr, addrlen);
#else
    return real_connect(sockfd, addr, addrlen);
#endif
}

#ifdef __APPLE__
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { \
        const void *replacement; \
        const void *replacee; \
    } _interpose_##_replacee \
    __attribute__ ((section ("__DATA,__interpose"))) = { (const void *)(unsigned long)&_replacement, (const void *)(unsigned long)&_replacee };

DYLD_INTERPOSE(connect_hook, connect);
#else
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return connect_hook(sockfd, addr, addrlen);
}
#endif
