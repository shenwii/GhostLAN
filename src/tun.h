#ifndef _TUN_H
#define _TUN_H

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ether.h>

int tun_set_mtu(int udp_fd, struct ifreq *ifr, int mtu);

int tun_get_mtu(int udp_fd, struct ifreq *ifr, int *mtu);

int tun_set_ip4(int udp_fd, struct ifreq *ifr, struct in_addr *ip4_addr);

int tun_get_ip4(int udp_fd, struct ifreq *ifr, struct in_addr *ip4_addr);

int tun_set_netmask4(int udp_fd, struct ifreq *ifr, struct in_addr *ip4_netmask);

int tun_get_netmask4(int udp_fd, struct ifreq *ifr, struct in_addr *ip4_netmask);

int tun_get_ether_address(int udp_fd, struct ifreq *ifr, struct ether_addr *eth_addr);

int tun_up(int udp_fd, struct ifreq *ifr);

int tun_alloc(char *tun_name, char type, struct ifreq *ifr);

#endif
