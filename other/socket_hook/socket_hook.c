#include <stdio.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/netlink.h>
#endif

// hook all socket calls

#ifdef __APPLE__
int socket_hook(int domain, int type, int protocol) {
#else
static inline int socket_hook(int domain, int type, int protocol) {
    static int (*real_socket)(int, int, int) = NULL;
    if (!real_socket) {
        real_socket = dlsym(RTLD_NEXT, "socket");
    }
#endif

    FILE *fd = fopen("/tmp/socket.log", "a");
    fprintf(fd, "socket() called  %i / %i / %i\n", domain, type, protocol);
    fsync(fileno(fd));

    char type_string[20];
    sprintf(type_string, "UNKNOWN/%i", type);

    switch (type) {
        case SOCK_STREAM:
            strcpy(type_string, "SOCK_STREAM");
            break;
        case SOCK_DGRAM:
            strcpy(type_string, "SOCK_DGRAM");
            break;
        case SOCK_RAW:
            strcpy(type_string, "SOCK_RAW");
            break;
        case SOCK_SEQPACKET:
            strcpy(type_string, "SOCK_SEQPACKET");
            break;
        case SOCK_RDM:
            strcpy(type_string, "SOCK_RDM");
            break;
    }
    char domain_string[20] = { };
    sprintf(domain_string, "UNKNOWN/%i", domain);

    switch (domain) {
        case AF_INET:
            strcpy(domain_string, "AF_INET");
            break;
        case AF_INET6:
            strcpy(domain_string, "AF_INET6");
            break;
        case AF_UNIX:
            strcpy(domain_string, "AF_UNIX");
            break;
        case AF_UNSPEC:
            strcpy(domain_string, "AF_UNSPEC");
            break;
    }
    char protocol_string[20];
    sprintf(protocol_string, "UNKNOWN/%i", protocol);

    switch (protocol) {
        case IPPROTO_IP:
            strcpy(protocol_string, "IPPROTO_IP");
            break;
        case IPPROTO_ICMP:
            strcpy(protocol_string, "IPPROTO_ICMP");
            break;
        case IPPROTO_TCP:
            strcpy(protocol_string, "IPPROTO_TCP");
            break;
        case IPPROTO_UDP:
            strcpy(protocol_string, "IPPROTO_UDP");
            break;
        case IPPROTO_IPV6:
            strcpy(protocol_string, "IPPROTO_IPV6");
            break;
        case IPPROTO_ICMPV6:
            strcpy(protocol_string, "IPPROTO_ICMPV6");
            break;
        case IPPROTO_RAW:
            strcpy(protocol_string, "IPPROTO_RAW");
            break;
    }

    int sockfd;
#ifdef __APPLE__
    sockfd = socket(domain, type, protocol);
#else
    sockfd = real_socket(domain, type, protocol);
#endif

    fprintf(fd, "socket(%s, %s, %s) => %i\n", domain_string, type_string, protocol_string, sockfd);
    fclose(fd);
    return sockfd;
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
    fclose(fd);

#ifdef __APPLE__
    return connect(sockfd, addr, addrlen);
#else
    return real_connect(sockfd, addr, addrlen);
#endif
}

void write_hex_bytes(FILE *fd, const void *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        fprintf(fd, "%02x ", ((unsigned char *) buf)[i]);
    }
    // now as chars:
    for (size_t i = 0; i < len; i++) {
        fprintf(fd, "%c", ((unsigned char *) buf)[i]);
    }
    fprintf(fd, "\n");
}


#ifdef __APPLE__
ssize_t sendto_hook(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
#else
static inline ssize_t sendto_hook(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    static int (*real_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = NULL;
    if (!real_sendto) {
        real_sendto = dlsym(RTLD_NEXT, "sendto");
    }
#endif
    FILE *fd = fopen("/tmp/socket.log", "a");
    fprintf(fd, "sendto() called\n");
    fprintf(fd, "sendto content: ");
    write_hex_bytes(fd, buf, len);
    fclose(fd);
#ifdef __APPLE__
    return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
#else
    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
#endif
}

#ifdef __APPLE__
int bind_hook(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
#else
static inline int bind_hook(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;
    if (!real_bind) {
        real_bind = dlsym(RTLD_NEXT, "bind");
    }
#endif
    FILE *fd = fopen("/tmp/socket.log", "a");
    char *address[addrlen] = {};
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
        char *ip = inet_ntoa(addr_in->sin_addr);
        int port = ntohs(addr_in->sin_port);
        fprintf(fd, "bind() called %s %i\n", ip, port);
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) addr;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip, INET6_ADDRSTRLEN);
        int port = ntohs(addr_in6->sin6_port);
        fprintf(fd, "bind() called %s %i\n", ip, port);
    } else if (addr-> sa_family == AF_UNIX) {
        struct sockaddr_un *addr_un = (struct sockaddr_un *) addr;
        fprintf(fd, "bind() called for UNIX socket %s\n", addr_un->sun_path);
#ifdef __linux__
    } else if (addr->sa_family == AF_NETLINK) {
        struct sockaddr_nl *addr_nl = (struct sockaddr_nl *) addr;
        fprintf(fd, "bind() called for NETLINK socket %i\n", addr_nl->nl_groups);
#endif
    } else {
        fprintf(fd, "bind() called unknown address family %i\n", addr->sa_family);
    }
    fclose(fd);
#ifdef __APPLE__
    return bind(sockfd, addr, addrlen);
#else
    return real_bind(sockfd, addr, addrlen);
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
DYLD_INTERPOSE(socket_hook, socket);
DYLD_INTERPOSE(sendto_hook, sendto);
DYLD_INTERPOSE(bind_hook, bind);
#else
int socket(int domain, int type, int protocol) {
    return socket_hook(domain, type, protocol);
}
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return connect_hook(sockfd, addr, addrlen);
}
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    return sendto_hook(sockfd, buf, len, flags, dest_addr, addrlen);
}
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return bind_hook(sockfd, addr, addrlen);
}
#endif
