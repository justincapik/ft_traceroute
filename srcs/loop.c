#include "ft_traceroute.h"

void    update_pkg_lst(packet_info_t *pkg, struct iphdr *iph, struct timeval ct)
{
    char ip[BUFFER_SIZE];
    char hostname[256];
    inet_ntop(AF_INET, &(iph->saddr), ip, BUFFER_SIZE);
    hostname_lookup(iph->saddr, (char *)hostname);

    pkg->ip = ip;
    pkg->hostname = hostname;
    pkg->difftime = (ct.tv_sec - pkg->sent_sec) * 1000000
        + ct.tv_usec - pkg->sent_usec;
    pkg->state = PACK_RECEIVED;
}

int     rec_packet(int sockfd, packet_info_t *base,
    options *opts, struct timeval ct)
{
    packet_info_t *pkg;
    char recbuffer[BUFFER_SIZE];
    bzero(recbuffer, BUFFER_SIZE);

    int rres = recv(sockfd, recbuffer, BUFFER_SIZE, MSG_PEEK | MSG_DONTWAIT);
    c_icmphdr *recicmp = (c_icmphdr *)(recbuffer + sizeof(struct iphdr));
    struct iphdr *iph = (struct iphdr *)recbuffer;

    if (rres > 0 && recicmp->type == 11 && recicmp->code == 0
        && (pkg = check_packet_to_list(base,
            (c_icmphdr*)((char*)recicmp + 28), OPTS_NB_PACK)) != NULL)
    {
        rres = recv(sockfd, recbuffer, BUFFER_SIZE, MSG_DONTWAIT);
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

        rres = recv(sockfd, recbuffer, BUFFER_SIZE, MSG_DONTWAIT);
        update_pkg_lst(pkg, iph, ct);
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
    
    ttl = nb_sent / opts->nqueries + 1;
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

    create_icmp_packet(buff, id, seq);
    
    if (sendto(sockfd, buff, sizeof(c_icmphdr),
            0, (struct sockaddr*)endpoint, sizeof(*endpoint)) < 0)
    {
        fprintf(stderr, "error: could not send message\n");
        // ¯\_(ツ)_/¯ oh well ? probably TODO:
        return ;
    }
    
    gettimeofday(&ct, NULL);
    pkg_lst[nb_sent].sent_sec = ct.tv_sec;
    pkg_lst[nb_sent].sent_usec = ct.tv_usec;
    pkg_lst[nb_sent].state = PACK_SENT;
    pkg_lst[nb_sent].ttl = ttl;
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
        printf("i = %ld, diff = %lu", i, difftime);
        if (difftime/10000 < INT_MAX
            && pkg_lst[i].state == PACK_SENT && difftime/10000 > opts->maxwait)
        {
            pkg_lst[i].state = PACK_EXCEEDED;
            count++;
        }
    }
    if (count > 0)
        printf("\n");
    return count;
}

int     print_progress(packet_info_t *pkg_lst, options *opts, int c_pkg)
{
    char    *hostname;
    char    *ip;
    size_t  difftime;

    if (pkg_lst[c_pkg].state == PACK_RECEIVED)
    {
        if (c_pkg % opts->nqueries == 0
            || strcmp(pkg_lst[c_pkg].ip,
                pkg_lst[c_pkg / opts->nqueries * opts->nqueries].ip) != 0)
        {
            hostname = pkg_lst[c_pkg].hostname;
            ip = pkg_lst[c_pkg].ip;
            printf("% 2ld ", (c_pkg + opts->nqueries) / opts->nqueries);
            if (strlen(hostname) > 0)
                printf("%s (%s)", hostname, ip);
            else
                printf("%s (%s)", ip, ip);
        }

        difftime = pkg_lst[c_pkg].difftime;
        printf(" %lu", difftime/10000);
        printf(".%02lu", difftime%10000);
        printf(" ms");
        pkg_lst[c_pkg].state = PACK_REC_PRINTED;
        c_pkg++;
        if (c_pkg % opts->nqueries == 0)
            printf("\n");
    }
    else if (pkg_lst[c_pkg].state == PACK_EXCEEDED)
    {
        // TODO:
        if (c_pkg % opts->nqueries == 0)
        {
            printf("% 2ld ", (c_pkg + opts->nqueries) / opts->nqueries);
        }
        printf(" *");
        c_pkg++;
        if (c_pkg % opts->nqueries == 0)
            printf("\n");
    } // TODO: in case all three are not found and no hostname?
    return c_pkg;
}

void    ping_loop(struct sockaddr_in *endpoint, int sockfd, options *opts)
{
    u_int8_t    nb_rec_left;
    u_int8_t    nb_sent;
    int         pkg_print_nb = 0;
    packet_info_t *pkg_lst = NULL;
    struct timeval ct;

    pkg_lst = create_packet_list(opts);

    nb_rec_left = OPTS_NB_PACK;
    nb_sent = 0;

    while (nb_rec_left > 0)
    {
        gettimeofday(&ct, NULL);
        
        if (nb_sent < OPTS_NB_PACK)
        // todo for bonus: -z here
        {
            send_packet(pkg_lst, nb_sent, sockfd, endpoint, opts);
            ++nb_sent;
        }
        // rec packet
        int ret = rec_packet(sockfd, pkg_lst, opts, ct);
        if (ret == TRUE)
        {
            nb_rec_left--;
            pkg_print_nb = print_progress(pkg_lst, opts, pkg_print_nb);
        }
        // check list to print new lines or values
        // ret = (int)check_time_exceeded(pkg_lst, opts, ct);
        // if (ret > 0)
        // {
        //     nb_rec_left -= ret;
        //     pkg_print_nb = print_progress(pkg_lst, opts, pkg_print_nb);
        // }
    }
}