#include "ft_traceroute.h"

int main(int argc, char** argv)
{
    // Check for root access for SOCK_RAW
    if (getuid() != 0)
    //TODO: do we keep this ? DGRAM socket ?
    {
        fprintf(stderr, "%s: This program requires root privileges!\n", argv[0]);
        return (EXIT_FAILURE);
    }

    options opts;
    if (parse_argv(argc, argv, &opts) == FALSE)
        return (EXIT_FAILURE);

    // open socket for icmp paquet
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    struct addrinfo *info = dns_lookup(opts.host, &opts);
    if (info == NULL)
        return (EXIT_FAILURE);
    struct sockaddr_in *addr_in;
    addr_in = (struct sockaddr_in *)info->ai_addr; 
    char *ip = inet_ntoa((struct in_addr)addr_in->sin_addr);
    
    printf("ft_traceroute to %s (%s), %ld hops max, %d byte packets\n",
        opts.host, ip, opts.maxhops, opts.packetlen);

    // create socket destination structure
    struct sockaddr_in endpoint;
    ft_memset(&endpoint, 0, sizeof(endpoint));
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr = addr_in->sin_addr;
    
    ping_loop(&endpoint, sockfd, &opts);

    close(sockfd);
    freeaddrinfo(info);

    return (EXIT_SUCCESS);
}