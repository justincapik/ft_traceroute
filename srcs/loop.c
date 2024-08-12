#include "ft_traceroute.h"

void    create_sent_info()
{
    struct timeval t;
    gettimeofday( &t, NULL );
    printf("current time s:%ld m:%ld\n", t.tv_sec, t.tv_usec);
}

int     rec_packet(int sockfd, packet_info_t *base, options *opts, struct timeval ct)
{
    packet_info_t *pkg;
    char recbuffer[BUFFER_SIZE];
    bzero(recbuffer, BUFFER_SIZE);

    int rres = recv(sockfd, recbuffer, BUFFER_SIZE, MSG_PEEK | MSG_DONTWAIT);
    c_icmphdr *recicmp = (c_icmphdr *)(recbuffer + sizeof(struct iphdr));
    struct iphdr *iph = (struct iphdr *)recbuffer;

    if (rres > 0 && recicmp->type == 11 && recicmp->code == 0
        && (pkg = check_packet_to_list(base, (c_icmphdr*)((char*)recicmp + 28))) != NULL)
    {
        char ip[BUFFER_SIZE];
        char hostname[256];
        rres = recv(sockfd, recbuffer, BUFFER_SIZE, MSG_DONTWAIT);
        inet_ntop(AF_INET, &(iph->saddr), ip, BUFFER_SIZE);
        hostname_lookup(iph->saddr, (char *)hostname);

        difftime = (ct.tv_sec - pkg->sent_sec) * 1000000
            + ct.tv_usec - pkg->sent_usec;

        pkg->ip = ip;
        pkg->hostname = hostname;
        pkg->difftime = difftime;
        pkg->state = PACK_RECEIVED;
        
        // mostly debug
        if (strlen(hostname) != 0)
            printf("From %s (%s) ", hostname, ip);
        else
            printf("From %s (%s) ", ip, ip);
        
        return (TRUE);
    }
    else if (rres > 0 && (pkg = check_packet_to_list(base, recicmp)) != NULL)
    {
        if (0 != checksum(recicmp, rres - sizeof(struct iphdr)))
        {
            printf("ping: error: Invalid checksum\n");
            return (FALSE);
        }
        rres = recv(sockfd, recbuffer, BUFFER_SIZE, MSG_DONTWAIT);
        printf("got end packet\n");
        return (TRUE);
    }
    return (FALSE);
}

void    send_packet(packet_info_t *pkg_lst, int count,
    int sockfd, struct sockaddr_in *endpoint, options *opts)
{
    int ttl;
    int id;
    int seq;
    c_icmphdr* icmp_hdr;
    char buff[BUFFER_SIZE];

    id = ID_START + count;
    seq = count + 1;

    icmp_hdr = create_icmp_packet(buff, id, seq);
    
    ttl = count / opts->nqueries;
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    
    if (sendto(sockfd, buffer, sizeof(c_icmphdr) + opts->size,
            0, (struct sockaddr*)endpoint, sizeof(*endpoint)) < 0)
    {
        fprintf(stderr, "error: could not send message\n");
        // ¯\_(ツ)_/¯ oh well ? probably TODO:
        return ;
    }
    
    gettimeofday(&ct, NULL);
    pkg_lst[count].sent_sec = ct.tv_sec;
    pkg_lst[count].sent_usec = ct.tv_usec;
}

size_t  check_time_exceeded(packet_info_t *pkg_lst, )

// void print_progress

void    ping_loop(struct sockaddr_in *endpoint, int sockfd, options *opts)
{
    u_int8_t    nb_rec_left;
    u_int8_t    nb_sent;
    sentp_info_t *pkg_lst = NULL;
    struct timeval ct;

    pkg_lst = create_packet_list(opts);

    nb_rec_left = opts->maxhops;
    nb_sent = 0;

    while (nb_rec_left > 0)
    {
        gettimeofday(&ct, NULL);
        
        if (nb_sent < OPTS_NB_PACK)
        // TODO for bonus: -z here
        {
            send_packet(pkg_lst, nb_sent);
            ++nb_sent;
        }
        
        // rec packet
        int ret = rec_packet(sockfd, sentp_base, opts);
        if (ret == TRUE)
            nb_rec_left--;
        // TODO: check time exceeded for packets
        ret = check_time_exceeded(base);
        if (ret > 0)
            nb_rec_left -= ret;
        
        // check list to print new lines or values
    }
}