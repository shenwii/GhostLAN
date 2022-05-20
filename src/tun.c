#include "tun.h"

#include <net/if.h>
#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_tun.h>

int tun_set_mtu(int udp_fd, struct ifreq *ifr, int mtu)
{
    ifr->ifr_mtu = mtu;
    if(ioctl(udp_fd, SIOCSIFMTU, ifr) < 0)
        return -1;
    return 0;
}

int tun_get_mtu(int udp_fd, struct ifreq *ifr, int *mtu)
{
    if(ioctl(udp_fd, SIOCGIFMTU, ifr) < 0)
        return -1;
    *mtu = ifr->ifr_mtu;
    return 0;
}

int tun_set_ip4(int udp_fd, struct ifreq *ifr, struct in_addr *ip4_addr)
{
    ((struct sockaddr_in *) &ifr->ifr_addr)->sin_family = AF_INET;
    ((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr = *ip4_addr;
    if(ioctl(udp_fd, SIOCSIFADDR, ifr) < 0)
        return -1;
    return 0;
}

int tun_get_ip4(int udp_fd, struct ifreq *ifr, struct in_addr *ip4_addr)
{
    ((struct sockaddr_in *) &ifr->ifr_addr)->sin_family = AF_INET;
    if(ioctl(udp_fd, SIOCGIFADDR, ifr) < 0)
        return -1;
    *ip4_addr = ((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr;
    return 0;
}

int tun_set_netmask4(int udp_fd, struct ifreq *ifr, struct in_addr *ip4_netmask)
{
    ((struct sockaddr_in *) &ifr->ifr_netmask)->sin_family = AF_INET;
    ((struct sockaddr_in *) &ifr->ifr_netmask)->sin_addr = *ip4_netmask;
    if(ioctl(udp_fd, SIOCSIFNETMASK, ifr) < 0)
        return -1;
    return 0;
}

int tun_get_netmask4(int udp_fd, struct ifreq *ifr, struct in_addr *ip4_netmask)
{
    ((struct sockaddr_in *) &ifr->ifr_netmask)->sin_family = AF_INET;
    if(ioctl(udp_fd, SIOCGIFNETMASK, ifr) < 0)
        return -1;
    *ip4_netmask = ((struct sockaddr_in *) &ifr->ifr_netmask)->sin_addr;
    return 0;
}

int tun_get_ether_address(int udp_fd, struct ifreq *ifr, struct ether_addr *eth_addr)
{
    if(ioctl(udp_fd, SIOCGIFHWADDR, ifr) < 0)
        return -1;
    memcpy(eth_addr, &ifr->ifr_hwaddr.sa_data, sizeof(struct ether_addr));
    return 0;
}

int tun_up(int udp_fd, struct ifreq *ifr)
{
    ifr->ifr_flags |= IFF_UP;
    if(ioctl(udp_fd, SIOCSIFFLAGS, ifr) < 0)
        return -1;
    return 0;
}

int tun_alloc(char *tun_name, char type, struct ifreq *ifr)
{
    int fd;
    memset(ifr, 0, sizeof(struct ifreq));
    fd = open("/dev/net/tun", O_RDWR);
    if(fd <= 0)
        return -1;
    ifr->ifr_flags = type | IFF_NO_PI;
    memcpy(ifr->ifr_name, tun_name, strlen(tun_name) + 1);
    if(ioctl(fd, TUNSETIFF, ifr) < 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}
