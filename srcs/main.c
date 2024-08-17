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

    char *ip = dns_lookup(opts.host, &opts);
    if (ip == NULL)
        return (EXIT_FAILURE);
    printf("ft_traceroute to %s (%s), %ld hops max, %d byte packets\n",
        opts.host, ip, opts.maxhops, opts.packetlen);

    // create socket destination structure
    struct sockaddr_in endpoint;
    memset(&endpoint, 0, sizeof(endpoint));
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = inet_addr(ip);
    
    ping_loop(&endpoint, sockfd, &opts);

    close(sockfd);

    return (EXIT_SUCCESS);
}