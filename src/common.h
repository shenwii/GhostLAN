#ifndef _COMMON_H
#define _COMMON_H

#include <netinet/in.h>

int getfirsthostbyname(__const__ char *hostname, struct sockaddr *addr);

char *address_str(struct sockaddr *addr);

#endif
