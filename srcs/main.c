#include "ft_traceroute.h"

int main(int argc, char** argv)
{
    int rec_sockfd, send_sockfd;
    struct sockaddr_in *endpoint;
    struct addrinfo *info;
    char *ip;
    
    // Check for root access for SOCK_RAW
    if (getuid() != 0)
    {
        fprintf(stderr, "%s: This program requires root privileges!\n", argv[0]);
        return (EXIT_FAILURE);
    }

    options opts;
    if (parse_argv(argc, argv, &opts) == FALSE)
        return (EXIT_FAILURE);

    info = dns_lookup(opts.host, &opts);
    if (info == NULL)
        return (EXIT_FAILURE);
    ft_memset(&endpoint, 0, sizeof(endpoint));
    endpoint = (struct sockaddr_in *)(info->ai_addr); 
    ip = inet_ntoa((struct in_addr)endpoint->sin_addr);
    
    printf("ft_traceroute to %s (%s), %ld hops max, %d byte packets\n",
        opts.host, ip, opts.maxhops, opts.packetlen);
    
    rec_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    
    // open sockesin_addrt
    if (opts.pack_type == PTYPE_ICMP)
        send_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    else if (opts.pack_type == PTYPE_UDP)
    {
        send_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        printf("PRE PORT SEARCH\n");
        opts.port = get_server_port(send_sockfd, endpoint, opts.port);
        printf("ENDPORT = %d\n", opts.port);
    }
    
    ping_loop(endpoint, &opts, rec_sockfd, send_sockfd);

    close(send_sockfd);
    freeaddrinfo(info);

    return (EXIT_SUCCESS);
}