#include "ft_traceroute.h"

char    *dns_lookup(char *canonname, options *opts)
{
    // check direction of lookup ?
    struct addrinfo hint;
    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_family = AF_INET;   // IPv4 
    hint.ai_socktype = SOCK_RAW; // configure sent packet header
    hint.ai_flags = AI_CANONNAME;
    hint.ai_protocol = IPPROTO_ICMP; // ICMP packet    
    hint.ai_canonname = NULL;
    hint.ai_addr = NULL;
    hint.ai_next = NULL;
    if (opts->flags & OPTS_VERBOSE)
        printf(", hints.ai_family: AF_INET\n\n");
    
    struct addrinfo add_res;
    struct addrinfo* res = &add_res;
    int s = getaddrinfo(canonname, 0, &hint, &res);
    if (s != 0) {
        fprintf(stderr, "ping: %s: %s\n", canonname, gai_strerror(s));
        return NULL;
    }
    if (opts->flags & OPTS_VERBOSE)
    {
        if (res->ai_family & AF_INET)
            printf("ai->ai_family: AF_INET");
        else if (res->ai_family & AF_INET6)
            printf("ai->ai_family: AF_INET6");
        else if (res->ai_family & AF_UNSPEC)
            printf("ai->ai_family: AF_UNSPEC");
        printf(", ai->ai_canonname: '%s'\n", res->ai_canonname);
    }

    struct sockaddr_in *addr;
    addr = (struct sockaddr_in *)res->ai_addr; 
    char *ip = inet_ntoa((struct in_addr)addr->sin_addr);

    free(res->ai_canonname);
    free(res);

    return (ip);
}

// get hostname and dns from ip
int    hostname_lookup(unsigned int ip, char *revhostname)
{
    struct sockaddr_in endpoint;
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = ip;

    bzero(revhostname, 256);
    int ret = getnameinfo((struct sockaddr*)&endpoint, (socklen_t)sizeof(struct sockaddr),
                    revhostname, 1000, 0, 0, NI_NOFQDN);
    if (ret != 0)
        printf("%s\n", gai_strerror(ret));
    return ret;
}