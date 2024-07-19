#include "ft_traceroute.h"

void    create_sent_info()
{
    struct timeval t;
    gettimeofday( &t, NULL );
    printf("current time s:%ld m:%ld\n", t.tv_sec, t.tv_usec);
}

void    print_packet_info(int rres, c_icmphdr *recicmp,
    struct iphdr *iph, sentp_info_t *old_package, options *opts)
{
    struct timeval ct;
    gettimeofday( &ct, NULL );
        
    int64_t difftime;
    difftime = (ct.tv_sec - old_package->sent_sec) * 1000000 + ct.tv_usec - old_package->sent_usec;
    old_package->difftime = difftime;
    
    if (!(opts->flags & OPTS_QUIET))
    {
        if (opts->flags & OPTS_FLOOD)
            printf("\33[2K\r");
        else
        {
            char ip[BUFFER_SIZE];
            inet_ntop(AF_INET, &(iph->saddr), ip, BUFFER_SIZE);
            if (opts->flags & OPTS_TIMESTAMP)
                printf("[%lu.%06lu] ", ct.tv_sec, ct.tv_usec);
            if (opts->flags & OPTS_NO_HOSTNAME)
                printf("%d bytes from %s: ", rres, ip);
            else 
            { 
                char hostname[256];
                hostname_lookup(iph->saddr, (char *)hostname);
                printf("%d bytes from %s (%s): ", rres, hostname, ip);
            }
            if (opts->flags & OPTS_VERBOSE)
                printf("icmp_seq=%d ident=%d ttl=%d ", recicmp->sequence, recicmp->id, iph->ttl);
            else
                printf("icmp_seq=%d ttl=%d ", recicmp->sequence, iph->ttl);

            printf("time=%lu", difftime/1000);
            if (difftime < 10000)
                printf(".%02lu", (difftime%1000)/10);
            else if (difftime < 100000)
                printf(".%01lu", (difftime%1000)/100);
            printf("ms");
            
            if (opts->flags & OPTS_ALERT)
                printf("\a");
            
            printf("\n");
        }
    }        
}

int     rec_packet(int sockfd, sentp_info_t *base, options *opts)
{
    sentp_info_t *old_package;
    char recbuffer[BUFFER_SIZE];
    bzero(recbuffer, BUFFER_SIZE);

    int rres = recv(sockfd, recbuffer, BUFFER_SIZE, MSG_PEEK | MSG_DONTWAIT);
    c_icmphdr *recicmp = (c_icmphdr *)(recbuffer + sizeof(struct iphdr));
    struct iphdr *iph = (struct iphdr *)recbuffer;

    if (rres > 0 && recicmp->type == 11 && recicmp->code == 0
        && (old_package = check_if_packet_exists(base, (c_icmphdr*)((char*)recicmp + 28))) != NULL)
    {
        char ip[BUFFER_SIZE];
        char hostname[256];
        rres = recv(sockfd, recbuffer, BUFFER_SIZE, MSG_DONTWAIT);
        inet_ntop(AF_INET, &(iph->saddr), ip, BUFFER_SIZE);
        hostname_lookup(iph->saddr, (char *)hostname);
        if (strlen(hostname) != 0)
            printf("From %s (%s) ", hostname, ip);
        else
            printf("From %s ", ip);
        printf("icmp_seq=%d Time to live exceeded\n", old_package->seq);
        return (ERROR);
    }
    else if (rres > 0 && (old_package = check_if_packet_exists(base, recicmp)) != NULL)
    {
        if (0 != checksum(recicmp, rres - sizeof(struct iphdr)))
        {
            printf("ping: error: Invalid checksum\n");
            return (FALSE);
        }
        rres = recv(sockfd, recbuffer, BUFFER_SIZE, MSG_DONTWAIT);
        print_packet_info(rres, recicmp, iph, old_package, opts);
        return (TRUE);
    }
    return (FALSE);
}

void    sigintHandler(int dummy) {
    keepRunning = FALSE;
    (void)dummy;
}

void    ping_loop(struct sockaddr_in *endpoint, int sockfd, options *opts, packet_stats_t *stats)
{
    struct timeval ct;
    gettimeofday( &ct, NULL );
    
    sentp_info_t *sentp_base = NULL;
    stats->transmitted = 0;
    stats->received = 0;
    stats->error = 0;
    stats->start_sec = ct.tv_sec;
    stats->start_usec = ct.tv_usec;
    stats->base = sentp_base;

    char tmp[BUFFER_SIZE];
    char *buffer = (char *)tmp;
    c_icmphdr *icmp_hdr = create_icmp_packet(buffer);

    int count = (opts->count > 0) ? opts->count : 1;
    int ident = (ct.tv_usec * SHRT_MAX) % (SHRT_MAX + 1);

    ct.tv_sec -= 100000; // send first pquage as soon as loop starts
    signal(SIGINT, sigintHandler);
    while (count > 0 && keepRunning == TRUE)
    {
        // send packet
        struct timeval t;
        gettimeofday( &t, NULL );
        int64_t difftime;
        difftime = (t.tv_sec - ct.tv_sec) * 1000000 + t.tv_usec - ct.tv_usec;
        if (difftime > opts->interval * 1000000
            && (stats->transmitted < opts->count || opts->count < 0))
        {
            if (opts->flags & OPTS_FLOOD)
                printf(".");
            update_packet(icmp_hdr, ident);
            if (sendto(sockfd, buffer, sizeof(c_icmphdr) + opts->size,
                    0, (struct sockaddr*)endpoint, sizeof(*endpoint)) < 0)
            {
                fprintf(stderr, "ping: error: could not send message\n");
                break ;
            }
            gettimeofday( &ct, NULL );
            stats->transmitted++;
            add_p_to_list(&sentp_base, icmp_hdr->id, icmp_hdr->sequence);
        }
        sleep(0.01);
        // rec packet
        int ret = rec_packet(sockfd, sentp_base, opts); 
        if (ret == TRUE)
        {
            stats->received++;
            if (opts->count > 0)
                count--;
        }
        else if (ret == ERROR)
        {
            stats->error++;
            if (opts->count > 0)
                count--;
        }
    }
    stats->base = sentp_base;
}