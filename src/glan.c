#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>
#if defined __linux__ && !defined SELECT
#include <sys/epoll.h>
#else
#include <sys/select.h>
#endif
#include <linux/if_tun.h>
#include <sys/fcntl.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "aes.h"
#include "log.h"
#include "tun.h"
#include "common.h"
#include "crc32.h"

//don't change this
#define TUN_MTU 1420
#define DEFAULT_PORT 5578
#define BUFFER_LENGTH 1456
#define IO_MUXING_NUM 2
#define IO_MUXING_TIMEOUT 5000
#define HEARTBEAT_SNEDTIME 10
#define HEARTBEAT_TIMEOUT 30

#define TUNNEL_TPYE_HEARTBEAT 0x01
#define TUNNEL_TPYE_DATA 0x02

typedef struct 
{
    int fd;
    struct in_addr ip4_addr;
    struct in_addr ip4_netmask;
    struct ether_addr eth_addr;
} tun_device_t;

typedef struct route_s
{
    struct in_addr ip4_addr;
    struct sockaddr_storage fd_addr;
    time_t heartbeat_time;
    struct route_s *next;
} route_t;

typedef struct
{
    unsigned char type;
    char udp_ip_version;
    uint16_t data_len;
    uint16_t total_len;
    //key crc32
    union
    {
        unsigned char crc32[4];
        uint32_t crc32_i;
    } key_u;
    struct in_addr saddr;
    char udp_ip[16];
    uint16_t udp_port;
} __attribute__((__packed__)) tunnel_hdr_t;

static char *__address_str4(struct in_addr *in_addr)
{
    static char addr[16];
    inet_ntop(AF_INET, in_addr, addr, 16);
    return addr;
}

static void __send_tunnel_data(int fd, struct sockaddr_storage *addr, tunnel_hdr_t *tunnel_hdr, unsigned char *aes_key, char *buf, int len)
{
    tunnel_hdr->type = TUNNEL_TPYE_DATA;
    tunnel_hdr->data_len = len;
    tunnel_hdr->total_len = AES_ENCRYPT_LEN(len);
    char send_buf[sizeof(tunnel_hdr_t) + tunnel_hdr->total_len];
    char aes_buf[tunnel_hdr->total_len];
    memcpy(send_buf, tunnel_hdr, sizeof(tunnel_hdr_t));
    aes_encrypt((unsigned char *) buf, len, (unsigned char *) aes_buf, aes_key);
    memcpy(send_buf + sizeof(tunnel_hdr_t), aes_buf, tunnel_hdr->total_len);
    sendto(fd, send_buf, sizeof(tunnel_hdr_t) + tunnel_hdr->total_len, MSG_NOSIGNAL, (struct sockaddr*) addr, sizeof(struct sockaddr_storage));
}

static void __send_tunnel_heartbeat(int fd, struct sockaddr_storage *addr, tunnel_hdr_t *tunnel_hdr)
{
    tunnel_hdr->type = TUNNEL_TPYE_HEARTBEAT;
    tunnel_hdr->data_len = 0;
    tunnel_hdr->total_len = 0;
    sendto(fd, tunnel_hdr, sizeof(tunnel_hdr_t), MSG_NOSIGNAL, (struct sockaddr*) addr, sizeof(struct sockaddr_storage));
}

// static void __send_udp_data(int fd, struct sockaddr_storage *addr, tunnel_hdr_t *tunnel_hdr, char type, char *aes_key, char buf, int len)
// {
//     tunnel_hdr->type = type;
//     if(type == TUNNEL_TPYE_DATA)
//         __send_tunnel_data(fd, addr, tunnel_hdr, aes_key, buf, len);
//     else
//         __send_tunnel_heartbeat(fd, addr, tunnel_hdr);
// }

static void __set_tunnel_hdr_udp_info(tunnel_hdr_t *tunnel_hdr, struct sockaddr_storage *addr)
{
    if(addr->ss_family == AF_INET)
    {
        tunnel_hdr->udp_ip_version = 4;
        memcpy(tunnel_hdr->udp_ip, &((struct sockaddr_in *) addr)->sin_addr, 4);
        tunnel_hdr->udp_port = ((struct sockaddr_in *) addr)->sin_port;
    }
    else
    {
        tunnel_hdr->udp_ip_version = 6;
        memcpy(tunnel_hdr->udp_ip, &((struct sockaddr_in6 *) addr)->sin6_addr, 16);
        tunnel_hdr->udp_port = ((struct sockaddr_in6 *) addr)->sin6_port;
    }
}

static void __start_forever(tun_device_t *tun_device, char *key , char server_mode, struct sockaddr_storage *server_addr, struct sockaddr_storage *listen_addr)
{
    char tun_buffer[TUN_MTU];
    char buffer[BUFFER_LENGTH];
    char tmp_buffer[BUFFER_LENGTH * 2];
    size_t tmp_buffer_len = 0;
    time_t last_heartbeat_time = 0;
    char addr_ipv4_str[16];
#if defined __linux__ && !defined SELECT
    //epoll fd
    int epfd;
    //temporary epoll event
    struct epoll_event ev;
    //temporary epoll event array
    struct epoll_event events[IO_MUXING_NUM];
#else
    //select read set
    fd_set read_set;
    struct timeval timeout_s;
    int fd_array[IO_MUXING_NUM];
    memset(&timeout_s, 0, sizeof(struct timeval));
    timeout_s.tv_usec = IO_MUXING_TIMEOUT * 1000;
#endif
    unsigned char key_buffer[AES_KEY_LEN / 8] = {0};
    memcpy(key_buffer, key, strlen(key));
    //calculate the key crc32
    uint32_t key_crc32 = CRC32(key_buffer, AES_KEY_LEN / 8);
    tunnel_hdr_t tunnel_hdr;
    tunnel_hdr.saddr = tun_device->ip4_addr;
    tunnel_hdr.key_u.crc32_i = htonl(key_crc32);
    int on = 1;
    int udp_fd;
    int event_fd;
    int wait_count;
    route_t *route_table = NULL;
    if(server_mode == 1)
    {
        udp_fd = socket(listen_addr->ss_family, SOCK_DGRAM, IPPROTO_UDP);
        if(udp_fd <= 0)
        {
            LOG_ERR("create socket failed\n");
            abort();
        }
        if(listen_addr->ss_family == AF_INET6)
        {
            if(setsockopt(udp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) != 0)
                return;
        }
        if(setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0)
            return;
        if(bind(udp_fd, (struct sockaddr *) listen_addr, sizeof(struct sockaddr_storage)) != 0)
            return;
    }
    else
    {
        udp_fd = socket(server_addr->ss_family, SOCK_DGRAM, IPPROTO_UDP);
        if(udp_fd <= 0)
        {
            LOG_ERR("create socket failed\n");
            abort();
        }
    }
#if defined __linux__ && !defined SELECT
    LOG_DEBUG("use epoll\n");
    epfd = epoll_create1(0);
    if(epfd < 0)
    {
        LOG_ERR("create epoll failed\n");
        abort();
    }
    ev.data.ptr = NULL;
    ev.events = EPOLLIN;
    ev.data.fd = tun_device->fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, tun_device->fd, &ev);
    ev.data.fd = udp_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, udp_fd, &ev);
#else
    LOG_DEBUG("use select\n");
    fd_array[0] = tun_device->fd;
    fd_array[1] = udp_fd;
#endif
    while(1)
    {
#if defined __linux__ && !defined SELECT
        wait_count = epoll_wait(epfd, events, IO_MUXING_NUM, IO_MUXING_TIMEOUT);
#else
        FD_ZERO(&read_set);
        FD_SET(tun_device->fd, &read_set);
        FD_SET(udp_fd, &read_set);
        wait_count = select(udp_fd + 1, &read_set, NULL, NULL, &timeout_s);
#endif
        if(server_mode)
        {
            route_t *pre_node = NULL;
            route_t *tmp_node;
            tmp_node = route_table;
            while(tmp_node != NULL)
            {
                if(difftime(time(NULL), tmp_node->heartbeat_time) > HEARTBEAT_TIMEOUT)
                {
                    inet_ntop(AF_INET, &tmp_node->ip4_addr, addr_ipv4_str, 16);
                    LOG_INFO("client closed, sockaddr = %s, client = %s\n", address_str((struct sockaddr *) &tmp_node->fd_addr), addr_ipv4_str);
                    if(pre_node == NULL)
                    {
                        route_table = tmp_node->next;
                        free(tmp_node);
                        tmp_node = route_table;
                    }
                    else
                    {
                        pre_node->next = tmp_node->next;
                        free(tmp_node);
                        tmp_node = pre_node->next;
                    }
                    continue;
                }
                pre_node = tmp_node;
                tmp_node = tmp_node->next;
            }
        }
        else
        {
            if(difftime(time(NULL), last_heartbeat_time) > HEARTBEAT_SNEDTIME)
            {
                __send_tunnel_heartbeat(udp_fd, server_addr, &tunnel_hdr);
                last_heartbeat_time = time(NULL);
            }
        }
#if defined __linux__ && !defined SELECT
        for(int i = 0; i < wait_count; i++)
        {
            //events although there is still the possibility of EPOLLERR and EPOLLHUP, it should not be possible here.
            if(!(events[i].events & EPOLLIN))
                continue;
            event_fd = events[i].data.fd;
#else
        if(wait_count <= 0)
            continue;
        for(int i = 0; i < IO_MUXING_NUM; i++)
        {
            if(!FD_ISSET(fd_array[i], &read_set))
                continue;
            event_fd = fd_array[i];
#endif
            if(event_fd == tun_device->fd)
            {
                int r = read(event_fd, tun_buffer, TUN_MTU);
                if(r <= sizeof(struct ether_header))
                    continue;
                struct ether_header *eth_hdr = (struct ether_header *) tun_buffer;
                if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
                {
                    struct iphdr *iphdr = (struct iphdr *) (tun_buffer + sizeof(struct ether_header));
                    //tun device, only ipv4 packets are processed, ipv6 packets are discarded
                    if(iphdr->version != 4)
                        continue;
                    if(server_mode == 0)
                    {
                        LOG_INFO("send ipv4 package to server\n");
                        __send_tunnel_data(udp_fd, server_addr, &tunnel_hdr, key_buffer, tun_buffer, r);
                    }
                    else
                    {
                        //if it is the server side, then first determine whether the destination IP is the same virtual LAN
                        if((iphdr->daddr & tun_device->ip4_netmask.s_addr) == (tun_device->ip4_addr.s_addr & tun_device->ip4_netmask.s_addr))
                        {
                            route_t *tmp_node;
                            char has_client = 0;
                            for(tmp_node = route_table; tmp_node != NULL; tmp_node = tmp_node->next)
                            {
                                if(tmp_node->ip4_addr.s_addr == iphdr->daddr)
                                {
                                    inet_ntop(AF_INET, &tmp_node->ip4_addr, addr_ipv4_str, 16);
                                    LOG_INFO("send ipv4 package to client(%s)\n", addr_ipv4_str);
                                    __send_tunnel_data(udp_fd, &tmp_node->fd_addr, &tunnel_hdr, key_buffer, tun_buffer, r);
                                }
                            }
                            if(!has_client)
                            {
                                //if the client is not found, it is discarded
                                LOG_INFO("client %s is not exists\n", __address_str4((struct in_addr *) &iphdr->daddr));
                            }
                        }
                        else
                        {
                            //if it is not from the same LAN, it is discarded
                            LOG_DEBUG("not the same lan package, droped\n");
                        }
                    }
                }
                else if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IPV6)
                {
                    LOG_INFO("ipv6 package drop\n");
                }
                else if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
                {
                    struct ether_arp *eth_arp;
                    eth_arp = (struct ether_arp *) (tun_buffer + sizeof(struct ether_header));
                    if(server_mode == 0)
                    {
                        LOG_DEBUG("send arp package to server\n");
                        __send_tunnel_data(udp_fd, server_addr, &tunnel_hdr, key_buffer, tun_buffer, r);
                    }
                    else
                    {
                        route_t *tmp_node;
                        for(tmp_node = route_table; tmp_node != NULL; tmp_node = tmp_node->next)
                        {
                            if(ntohs(eth_arp->arp_op) == ARPOP_REQUEST || memcmp(&tmp_node->ip4_addr, eth_arp->arp_tpa, sizeof(struct in_addr)) == 0)
                            {
                                tunnel_hdr.udp_ip_version = 0;
                                inet_ntop(AF_INET, &tmp_node->ip4_addr, addr_ipv4_str, 16);
                                LOG_INFO("send arp package to client(%s)\n", addr_ipv4_str);
                                __send_tunnel_data(udp_fd, &tmp_node->fd_addr, &tunnel_hdr, key_buffer, tun_buffer, r);
                            }
                        }
                    }
                }
                else
                {
                    LOG_WARN("ether type 0x%04x is not supported\n", eth_hdr->ether_type);
                }
            }
            else
            {
                char *handle_buf;
                size_t handle_buf_len;
                struct sockaddr_storage client_addr;
                socklen_t addr_len = sizeof(client_addr);
                int r = recvfrom(event_fd, buffer, BUFFER_LENGTH, MSG_NOSIGNAL, (struct sockaddr *) &client_addr, &addr_len);
                if(tmp_buffer_len == 0)
                {
                    handle_buf = buffer;
                    handle_buf_len = r;
                }
                else
                {
                    memcpy(tmp_buffer + tmp_buffer_len, buffer, r);
                    handle_buf = tmp_buffer;
                    handle_buf_len = tmp_buffer_len + r;
                }
                while(1)
                {
                    if(handle_buf_len < sizeof(tunnel_hdr_t))
                        break;
                    tunnel_hdr_t *recv_tunnel_hdr = (tunnel_hdr_t *) handle_buf;
                    if(ntohl(recv_tunnel_hdr->key_u.crc32_i) != key_crc32)
                    {
                        LOG_INFO("incorrect key\n");
                        handle_buf_len = 0;
                        break;
                    }
                    if(recv_tunnel_hdr->type == TUNNEL_TPYE_HEARTBEAT)
                    {
                        LOG_DEBUG("recv heartbeat package\n");
                        if(server_mode == 1)
                        {
                            route_t *tmp_node;
                            route_t *last_socket = NULL;
                            char has_client = 0;
                            for(tmp_node = route_table; tmp_node != NULL; tmp_node = tmp_node->next)
                            {
                                if(tmp_node->ip4_addr.s_addr == recv_tunnel_hdr->saddr.s_addr)
                                {
                                    memcpy(&tmp_node->fd_addr, &client_addr, addr_len);
                                    tmp_node->heartbeat_time = time(NULL);
                                    has_client = 1;
                                    break;
                                }
                                last_socket = tmp_node;
                            }
                            if(!has_client)
                            {
                                tmp_node = malloc(sizeof(route_t));
                                if(tmp_node == NULL)
                                {
                                    LOG_ERR("malloc failed\n");
                                    abort();
                                }
                                memcpy(&tmp_node->fd_addr, &client_addr, addr_len);
                                tmp_node->heartbeat_time = time(NULL);
                                tmp_node->ip4_addr = recv_tunnel_hdr->saddr;
                                tmp_node->next = NULL;
                                inet_ntop(AF_INET, &tmp_node->ip4_addr, addr_ipv4_str, 16);
                                LOG_INFO("new client connected, sockaddr = %s, client = %s\n", address_str((struct sockaddr *) &tmp_node->fd_addr), addr_ipv4_str);
                                if(route_table == NULL)
                                {
                                    route_table = tmp_node;
                                }
                                else
                                {
                                    last_socket->next = tmp_node;
                                }
                            }
                        }
                    }
                    else if(recv_tunnel_hdr->type == TUNNEL_TPYE_DATA)
                    {
                        LOG_DEBUG("recv data package\n");
                        if(recv_tunnel_hdr->total_len < recv_tunnel_hdr->data_len || recv_tunnel_hdr->data_len == 0)
                        {
                            handle_buf_len = 0;
                            break;
                        }
                        if(handle_buf_len < recv_tunnel_hdr->total_len + sizeof(tunnel_hdr_t))
                            break;
                        unsigned char aes_buf[recv_tunnel_hdr->total_len];
                        if(aes_decrypt((unsigned char *) handle_buf + sizeof(tunnel_hdr_t), AES_ENCRYPT_LEN(recv_tunnel_hdr->data_len), aes_buf, key_buffer) != 0)
                        {
                            handle_buf_len = 0;
                            break;
                        }
                        //FIXME
                        if(recv_tunnel_hdr->data_len < sizeof(struct ether_header))
                        {
                            handle_buf_len = 0;
                            break;
                        }
                        struct ether_header *eth_hdr = (struct ether_header *) aes_buf;
                        if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
                        {
                            LOG_DEBUG("recv ipv4 package\n");
                            if(recv_tunnel_hdr->data_len < sizeof(struct ether_header) + sizeof(struct iphdr))
                            {
                                handle_buf_len = 0;
                                break;
                            }
                            struct iphdr *iphdr = (struct iphdr *) (aes_buf + sizeof(struct ether_header));
                            if(iphdr->version != 4)
                            {
                                handle_buf_len = 0;
                                break;
                            }
                            if(iphdr->daddr == tun_device->ip4_addr.s_addr)
                            {
                                LOG_INFO("send data package to tun\n");
                                write(tun_device->fd, aes_buf, recv_tunnel_hdr->data_len);
                            }
                            else
                            {
                                if(server_mode == 1)
                                {
                                    route_t *tmp_node;
                                    // char has_client = 0;
                                    for(tmp_node = route_table; tmp_node != NULL; tmp_node = tmp_node->next)
                                    {
                                        if(tmp_node->ip4_addr.s_addr == iphdr->daddr)
                                        {
                                            inet_ntop(AF_INET, &tmp_node->ip4_addr, addr_ipv4_str, 16);
                                            LOG_INFO("forward data package to other client(%s)\n", addr_ipv4_str);
                                            sendto(udp_fd, handle_buf, handle_buf_len, MSG_NOSIGNAL, (struct sockaddr *) &tmp_node->fd_addr, sizeof(struct sockaddr_storage));
                                        }
                                    }

                                }
                            }

                        }
                        else if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IPV6)
                        {
                            LOG_INFO("ipv6 package drop\n");
                        }
                        else if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
                        {
                            LOG_DEBUG("recv arp package\n");
                            if(recv_tunnel_hdr->data_len < sizeof(struct ether_header) + sizeof(struct ether_arp))
                            {
                                handle_buf_len = 0;
                                break;
                            }
                            struct ether_arp *eth_arp = (struct ether_arp *) (aes_buf + sizeof(struct ether_header));
                            LOG_INFO("send data package to tun\n");
                            write(tun_device->fd, aes_buf, recv_tunnel_hdr->data_len);
                            if(ntohs(eth_arp->arp_op) == ARPOP_REQUEST && server_mode == 1)
                            {
                                route_t *tmp_node;
                                // char has_client = 0;
                                for(tmp_node = route_table; tmp_node != NULL; tmp_node = tmp_node->next)
                                {
                                    if(memcmp(&tmp_node->ip4_addr, eth_arp->arp_spa, 4) != 0)
                                    {
                                        LOG_INFO("forward data package to other client(%s)\n", addr_ipv4_str);
                                        sendto(udp_fd, handle_buf, handle_buf_len, MSG_NOSIGNAL, (struct sockaddr *) &tmp_node->fd_addr, sizeof(struct sockaddr_storage));
                                    }
                                }
                            }
                        }
                        else
                        {
                            LOG_WARN("ether type 0x%04x is not supported\n", eth_hdr->ether_type);
                        }
                    }
                    handle_buf_len -= recv_tunnel_hdr->total_len + sizeof(tunnel_hdr_t);
                    handle_buf += recv_tunnel_hdr->total_len + sizeof(tunnel_hdr_t);
                }
                tmp_buffer_len = handle_buf_len;
                if(handle_buf_len != 0)
                {
                    memmove(tmp_buffer, handle_buf, handle_buf_len);
                }
            }
        }
    }
}

static int __tun_alloc(char *tun_name, tun_device_t *tun_device)
{
    struct ifreq ifr;
    int fd;
    if(tun_name == NULL || strlen(tun_name) == 0)
        fd = tun_alloc("tap%d", IFF_TAP, &ifr);
    else
        fd = tun_alloc(tun_name, IFF_TAP, &ifr);
    if(fd <= 0)
        return -1;
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(udp_fd <= 0)
    {
        close(fd);
        return -1;
    }
    if(tun_set_mtu(udp_fd, &ifr, TUN_MTU) < 0)
    {
        close(udp_fd);
        close(fd);
        return -1;
    }
    if(tun_set_ip4(udp_fd, &ifr, &tun_device->ip4_addr) < 0)
    {
        close(udp_fd);
        close(fd);
        return -1;
    }
    if(tun_set_netmask4(udp_fd, &ifr, &tun_device->ip4_netmask) < 0)
    {
        close(udp_fd);
        close(fd);
        return -1;
    }
    if(tun_up(udp_fd, &ifr) < 0)
    {
        close(udp_fd);
        close(fd);
        return -1;
    }
    if(tun_get_ether_address(udp_fd, &ifr, &tun_device->eth_addr) < 0)
    {
        close(udp_fd);
        close(fd);
        return -1;
    }
    close(udp_fd);
    return fd;
}

static void __usage(char *prog, struct option *long_options, size_t len)
{
    char option_str[25];
    fprintf(stderr, "Usage: %s [OPTION]...\n", prog);
    fprintf(stderr, "Option:\n");
    for(int i = 0; i < len; i++) {
        sprintf(option_str, "  -%c, --%s", long_options[i].val, long_options[i].name);
        fprintf(stderr, "%-24s", option_str);
        switch(long_options[i].val)
        {
            case 'a':
                fprintf(stderr, "tun device ipv4 address\n");
                break;
            case 'h':
                fprintf(stderr, "display this help and exit\n");
                break;
            case 'k':
                fprintf(stderr, "authentication key\n");
                break;
            case 'l':
                fprintf(stderr, "server listen address\n");
                break;
            case 'n':
                fprintf(stderr, "tun device netmask, default: 255.255.255.0\n");
                break;
            case 'p':
                fprintf(stderr, "port, default: %d\n", DEFAULT_PORT);
                break;
            case 's':
                fprintf(stderr, "server address, runs in service mode if not specified\n");
                break;
            case 't':
                fprintf(stderr, "tun name, if empty, the default assignment\n");
                break;
        }
    }
    fflush(stderr);
}

int main(int argc, char **argv)
{
    int c;
    int index;
    int tun_fd;
    struct option long_options[] = 
    {
        {"addr", required_argument, NULL, 'a'},
        {"help", no_argument, NULL, 'h'},
        {"key", required_argument, NULL, 'k'},
        {"listen", required_argument, NULL, 'l'},
        {"netmask", required_argument, NULL, 'n'},
        {"port", required_argument, NULL, 'p'},
        {"server", required_argument, NULL, 's'},
        {"tun", required_argument, NULL, 't'}
    };
    char address[16] = {0};
    char key[AES_KEY_LEN / 8 + 1] = {0};
    char netmask[16] = {0};
    char server[256] = {0};
    char listen[256] = {0};
    uint16_t port = DEFAULT_PORT;
    char server_mode = 1;
    char tun_name[IFNAMSIZ + 1] = {0};
    tun_device_t tun_device;
    struct sockaddr_storage server_addr;
    struct sockaddr_storage listen_addr;

    while(EOF != (c = getopt_long(argc, argv, "a:hk:l:n:p:s:t:", long_options, &index)))
    {
        switch(c)
        {
            case 'a':
                if(strlen(optarg) >= 16)
                {
                    fprintf(stderr, "illegal IPv4 addresses\n");
                    return 1;
                }
                memcpy(address, optarg, strlen(optarg) + 1);
                break;
            case 'h':
                __usage(argv[0], long_options, sizeof(long_options) / sizeof(struct option));
                return 1;
            case 'k':
                if(strlen(optarg) > AES_KEY_LEN / 8)
                {
                    fprintf(stderr, "the key is up to %d bits\n", AES_KEY_LEN / 8);
                    return 1;
                }
                memcpy(key, optarg, strlen(optarg) + 1);
                break;
            case 'l':
                if(strlen(optarg) >= 256)
                {
                    fprintf(stderr, "listen address is up to 255 bits\n");
                    return 1;
                }
                memcpy(listen, optarg, strlen(optarg) + 1);
                break;
            case 'n':
                if(strlen(optarg) >= 16)
                {
                    fprintf(stderr, "illegal netmask addresses\n");
                    return 1;
                }
                memcpy(netmask, optarg, strlen(optarg) + 1);
                break;
            case 'p':
                port = atoi(optarg);
                if(port == 0)
                {
                    fprintf(stderr, "illegal port\n");
                    return 1;
                }
                break;
            case 's':
                if(strlen(optarg) >= 256)
                {
                    fprintf(stderr, "server address is up to 255 bits\n");
                    return 1;
                }
                memcpy(server, optarg, strlen(optarg) + 1);
                break;
            case 't':
                if(strlen(optarg) > IFNAMSIZ)
                {
                    fprintf(stderr, "tun name is up to %d bits\n", IFNAMSIZ);
                    return 1;
                }
                memcpy(tun_name, optarg, strlen(optarg) + 1);
                break;
            case '?':
                fprintf(stderr, "unknow option:%c\n", optopt);
                __usage(argv[0], long_options, sizeof(long_options) / sizeof(struct option));
                return 1;
            default:
                break;
        }   
    }
    if(strlen(address) == 0)
    {
        fprintf(stderr, "ipv4 address cannot be empty\n");
        __usage(argv[0], long_options, sizeof(long_options) / sizeof(struct option));
        return 1;
    }
    if(strlen(key) == 0)
    {
        fprintf(stderr, "key cannot be empty\n");
        __usage(argv[0], long_options, sizeof(long_options) / sizeof(struct option));
        return 1;
    }
    if(strlen(netmask) == 0)
    {
        memcpy(netmask, "255.255.255.0", 14);
    }
    if(strlen(server) != 0)
    {
        server_mode = 0;
        if(getfirsthostbyname(server, (struct sockaddr *) &server_addr) != 0)
        {
            fprintf(stderr, "can't resolve server address: %s\n", server);
            return 1;
        }
        if(server_addr.ss_family == AF_INET)
            ((struct sockaddr_in *) &server_addr)->sin_port = htons(port);
        else
            ((struct sockaddr_in6 *) &server_addr)->sin6_port = htons(port);
    }
    if(server_mode == 1)
    {
        if(strlen(listen) == 0)
        {
            fprintf(stderr, "listener address and server address cannot be empty at the same time\n");
            return 1;
        }
        if(getfirsthostbyname(listen, (struct sockaddr *) &listen_addr) != 0)
        {
            fprintf(stderr, "can't resolve listen address: %s\n", listen);
            return 1;
        }
        if(listen_addr.ss_family == AF_INET)
            ((struct sockaddr_in *) &listen_addr)->sin_port = htons(port);
        else
            ((struct sockaddr_in6 *) &listen_addr)->sin6_port = htons(port);
    }
    if(inet_pton(AF_INET, address, &tun_device.ip4_addr) < 0)
    {
        fprintf(stderr, "illegal IPv4 addresses\n");
        return 1;
    }
    if(inet_pton(AF_INET, netmask, &tun_device.ip4_netmask) < 0)
    {
        fprintf(stderr, "illegal netmask addresses\n");
        return 1;
    }
    tun_fd = __tun_alloc(tun_name, &tun_device);
    if(tun_fd < 0)
    {
        LOG_ERR("create tun device failed, you should probably run it with root\n");
        return 1;
    }
    tun_device.fd = tun_fd;
    __start_forever(&tun_device, key, server_mode, &server_addr, &listen_addr);
    return 0;
}
