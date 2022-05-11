#include "common.h"

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#if defined _WIN32 || defined __CYGWIN__
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#endif


static struct addrinfo *__gethostbyname(__const__ char *hostname)
{
    struct addrinfo *result = NULL;
    if(getaddrinfo(hostname, NULL, NULL, &result) != 0)
        return NULL;
    return result;
}

int getfirsthostbyname(__const__ char *hostname, struct sockaddr *addr)
{
    struct addrinfo *result = __gethostbyname(hostname);
    if(result == NULL)
        return 1;
    if(result->ai_family == AF_INET)
    {
        memcpy(addr, result->ai_addr, sizeof(struct sockaddr_in));
    }
    if(result->ai_family == AF_INET6)
    {
        memcpy(addr, result->ai_addr, sizeof(struct sockaddr_in6));
    }
    freeaddrinfo(result);
    return 0;
}

char *address_str(struct sockaddr* addr)
{
    static char addstr[100];
    char s[80];
    if(addr->sa_family == AF_INET)
    {
        inet_ntop(addr->sa_family, &((struct sockaddr_in *) addr)->sin_addr, s, 80);
        sprintf(addstr, "%s:%d", s, ntohs(((struct sockaddr_in *) addr)->sin_port));
    }
    else
    {
        inet_ntop(addr->sa_family, &((struct sockaddr_in6 *) addr)->sin6_addr, s, 80);
        sprintf(addstr, "[%s]:%d", s, ntohs(((struct sockaddr_in6 *) addr)->sin6_port));
    }
    return addstr;
}
