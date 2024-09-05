#include "ft_traceroute.h"

void    print_lst(packet_info_t *lst, options *opts)
{
    printf("\nPACKAGE LIST:");
    for (size_t i = 0; i < OPTS_NB_PACK; ++i)
    {
        if (i % opts->nqueries == 0)
        {
            if (lst[i].hostname != NULL && ft_strlen(lst[i].hostname) > 0)
                printf("\n%s ", lst[i].hostname);
            else if (lst[i].ip != NULL)
                printf("\n%ld %s ", i, lst[i].ip);
            else
                printf("\n%ld NULL ", i);
        }
        if (lst[i].state == PACK_UNSENT)
            printf("UNSENT  ");
        if (lst[i].state == PACK_SENT)
            printf("SENT    ");
        if (lst[i].state == PACK_RECEIVED)
            printf("RECEIVE ");
        if (lst[i].state == PACK_REC_END)
            printf("REC_END ");
        if (lst[i].state == PACK_REC_PRINTED)
            printf("PRINTED ");
        if (lst[i].state == PACK_EXCEEDED)
            printf("EXCEED  ");
    }
    printf("\n");
}

size_t  difftime_calc(struct timeval older, struct timeval recent)
{
    return (recent.tv_sec - older.tv_sec) * 1000000
        + recent.tv_usec - older.tv_usec;
}

void    update_pkg_lst(packet_info_t *pkg, struct iphdr *iph, struct timeval ct)
{
    char ip[BUFFER_SIZE];
    char hostname[256];
    inet_ntop(AF_INET, &(iph->saddr), ip, BUFFER_SIZE);
    hostname_lookup(iph->saddr, (char *)hostname);

    pkg->ip = ft_strdup(ip);
    pkg->hostname = ft_strdup(hostname);
    pkg->difftime = (ct.tv_sec - pkg->sent_sec) * 1000000
        + ct.tv_usec - pkg->sent_usec;
    pkg->state = PACK_RECEIVED;
}

int     rec_packet(int sockfd, packet_info_t *base,
    options *opts, struct timeval ct)
{
    packet_info_t *pkg;
    char recbuffer[BUFFER_SIZE];
    char databuffer[BUFFER_SIZE];
    ft_bzero(recbuffer, BUFFER_SIZE);
    ft_bzero(databuffer, BUFFER_SIZE);

    int rres = recvfrom(sockfd, recbuffer, BUFFER_SIZE, MSG_DONTWAIT,
        NULL, NULL);
    c_icmphdr *recicmp = (c_icmphdr *)(recbuffer + sizeof(struct iphdr));
    struct iphdr *iph = (struct iphdr *)recbuffer;

    // interessant pour les explications
    // if (rres > 0 && recicmp->type == 11 && recicmp->code == 0)
    // {
    //     char *search = (char*)recicmp;
    //     for(int i = 0; i < 16; ++i)
    //     {
    //         printf("%02x",(unsigned char)(*((char*)search
    //             + sizeof(c_icmphdr) + sizeof(struct iphdr)
    //             + sizeof(struct udphdr) + i)));
    //         if (i % 2 == 1)
    //             printf(" ");
    //     }
    //     printf("\n");
    // }

    if (rres > 0 && recicmp->type == 11 && recicmp->code == 0
        && ((pkg = check_packet_to_list(base,
            (c_icmphdr*)((char*)recicmp + 28), OPTS_NB_PACK)) != NULL
        || (pkg = check_packet_to_list(base,
            (c_icmphdr*)((char*)recicmp + sizeof(c_icmphdr) + sizeof(struct iphdr)
                + sizeof(struct udphdr) ), OPTS_NB_PACK)) != NULL))
    {
        update_pkg_lst(pkg, iph, ct);
        
        return (TRUE);
    }
    else if (rres > 0 && (pkg =
        check_packet_to_list(base, recicmp, OPTS_NB_PACK)) != NULL)
    {
        if (0 != checksum(recicmp, rres - sizeof(struct iphdr)))
        {
            printf("ping: error: Invalid checksum\n");
            return (FALSE);
        }
        
        update_pkg_lst(pkg, iph, ct);
        pkg->state = PACK_REC_END;
        return (TRUE);
    }
    return (FALSE);
}

void    send_packet(packet_info_t *pkg_lst, int nb_sent,
    int sockfd, struct sockaddr_in *endpoint, options *opts)
{
    int ttl;
    int id;
    int seq;
    char buff[BUFFER_SIZE];
    struct timeval ct;

    id = START_ID + nb_sent;
    seq = nb_sent + 1;
    
    gettimeofday(&ct, NULL);
    pkg_lst[nb_sent].sent_sec = ct.tv_sec;
    pkg_lst[nb_sent].sent_usec = ct.tv_usec;
    pkg_lst[nb_sent].state = PACK_SENT;
    ttl = nb_sent / opts->nqueries + 1 + opts->first_ttl;
    pkg_lst[nb_sent].ttl = ttl;
    
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

    if (opts->pack_type == PTYPE_ICMP)
    {
        create_icmp_packet(buff, opts->packetlen, id, seq);

        if (sendto(sockfd, buff, opts->packetlen,
                0, (struct sockaddr*)endpoint, sizeof(*endpoint)) < 0)
        {
            fprintf(stderr, "error: could not send message\n");
            return ;
        }
    }
    else if (opts->pack_type == PTYPE_UDP)
    {
        // artificially making an icmp header in udp package
        // because that makes things simpler
        create_icmp_packet(buff, opts->packetlen, id, seq);

        endpoint->sin_port = htons(opts->port); 
        if (sendto(sockfd, buff, opts->packetlen, 0,
            (struct sockaddr*)endpoint, sizeof(*endpoint)) < 0)
        {
            fprintf(stderr, "error: could not send message\n");
            return ;
        }

    }    
}

size_t  check_time_exceeded(packet_info_t *pkg_lst,
    options *opts, struct timeval ct)
{
    int     count = 0;
    size_t  difftime;

    for (size_t i = 0; i < OPTS_NB_PACK; ++i)
    {
        difftime = (ct.tv_sec - pkg_lst[i].sent_sec) * 1000000
        + ct.tv_usec - pkg_lst[i].sent_usec;
        if (difftime/10000 < INT_MAX
            && pkg_lst[i].state == PACK_SENT && difftime/10000 > opts->maxwait)
        {
            pkg_lst[i].state = PACK_EXCEEDED;
            count++;
        }
    }
    return count;
}

int     print_progress(packet_info_t *pkg_lst, options *opts, int c_pkg)
{
    static char     endcount = 0;
    char            *hostname;
    char            *ip;
    size_t          difftime;
    size_t          server_nbr;

    server_nbr = (c_pkg + opts->nqueries) / opts->nqueries + opts->first_ttl;
    if (pkg_lst[c_pkg].state == PACK_RECEIVED
        || pkg_lst[c_pkg].state == PACK_REC_END)
    {
        if (c_pkg % opts->nqueries == 0
            || ft_strcmp(pkg_lst[c_pkg].ip,
                pkg_lst[server_nbr * opts->nqueries - opts->nqueries].ip) != 0)
        {
            if (c_pkg % opts->nqueries == 0)
            {
                if (server_nbr < 10)
                    printf(" ");
                printf("%ld", server_nbr);
            }
            hostname = pkg_lst[c_pkg].hostname;
            ip = pkg_lst[c_pkg].ip;
            if (ft_strlen(hostname) > 0)
                printf(" %s (%s)", hostname, ip);
            else
                printf(" %s (%s)", ip, ip);
        }

        difftime = pkg_lst[c_pkg].difftime;
        printf(" %lu", difftime/10000);
        printf(".%02lu", difftime%10000);
        printf(" ms");

        if (pkg_lst[c_pkg].state == PACK_REC_END)
            ++endcount;
        if (endcount == opts->nqueries)
            return (-1);
        c_pkg++;
        if (c_pkg % opts->nqueries == 0)
            printf("\n");
    }
    else if (pkg_lst[c_pkg].state == PACK_EXCEEDED)
    {
        if (c_pkg % opts->nqueries == 0)
        {
            if (server_nbr < 10)
                printf(" ");
            printf("%ld", server_nbr);
        }
        printf(" *");
        c_pkg++;
        if (c_pkg % opts->nqueries == 0)
            printf("\n");
    }
    return c_pkg;
}

void    ping_loop(struct sockaddr_in *endpoint, options *opts,
    int rec_sockfd, int send_sockfd)
{
    u_int8_t    nb_rec_left;
    u_int8_t    nb_sent;
    int         pkg_print_nb = 0;
    packet_info_t *pkg_lst = NULL;
    struct timeval ct;
    struct timeval last_pkg;

    pkg_lst = create_packet_list(opts);

    nb_rec_left = OPTS_NB_PACK;
    nb_sent = 0;
    
    gettimeofday(&last_pkg, NULL);

    while (nb_rec_left > 0)
    {
        gettimeofday(&ct, NULL);
        
        if (nb_sent == 0 || (nb_sent < OPTS_NB_PACK
            && difftime_calc(last_pkg, ct) > opts->max_send_wait
            && (nb_sent % opts->simul_send_nb != 0
                || (nb_sent % opts->simul_send_nb == 0
                    && difftime_calc(last_pkg, ct) > opts->max_simul_send))))
        {
            send_packet(pkg_lst, nb_sent, send_sockfd, endpoint, opts);
            ++nb_sent;
            gettimeofday(&last_pkg, NULL);
        }
        
        // rec packet
        int ret = rec_packet(rec_sockfd, pkg_lst, opts, ct);
        if (ret == TRUE)
        {
            nb_rec_left--;
            pkg_print_nb = print_progress(pkg_lst, opts, pkg_print_nb);
            if (pkg_print_nb == -1)
                break;
        }
        
        // check list to print new lines or values
        ret = (int)check_time_exceeded(pkg_lst, opts, ct);
        if (ret > 0)
        {
            nb_rec_left -= ret;
            pkg_print_nb = print_progress(pkg_lst, opts, pkg_print_nb);
            if (pkg_print_nb == -1)
                break;
        }
    }
    if (pkg_print_nb >= 0)
    {
        while (pkg_print_nb != -1 && pkg_print_nb < (int)OPTS_NB_PACK)
            pkg_print_nb = print_progress(pkg_lst, opts, pkg_print_nb);
    }
    printf("\n");
    // print_lst(pkg_lst, opts);
    
    free_packet_list(pkg_lst, OPTS_NB_PACK);
}