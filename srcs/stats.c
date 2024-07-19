#include "ft_traceroute.h"

void    get_time_stats(packet_stats_t *stats)
{
    stats->min = INT_MAX;
    stats->max = INT_MIN;
    stats->unreceived = 0;
    int64_t sum = 0;
    int64_t count = 0;
    int64_t mdevsum = 0;

    // stats loop for min, max and avg
    sentp_info_t *tmp = stats->base;
    while (tmp != NULL)
    {
        if (tmp->received == TRUE)
        {
            if (tmp->difftime < stats->min)
                stats->min = tmp->difftime;
            if (tmp->difftime > stats->max)
                stats->max = tmp->difftime;
            sum += tmp->difftime;
            ++count;
        }
        else
            ++(stats->unreceived);
        tmp = tmp->next;
    }
    if (count > 0)
        stats->avg = sum / count;
    else
        stats->avg = 0;

    // mdev loop after getting average
    tmp = stats->base;
    while (tmp != NULL)
    {
        if (tmp->received == TRUE)
        {
            int64_t val = tmp->difftime - stats->avg;
            val = (val > 0) ? val : -val;
            mdevsum += val;
        }
        tmp = tmp->next;
    }
    if (count > 0)
        stats->mdev = mdevsum / count;
}

void    free_ll(sentp_info_t *base)
{
    while (base != NULL)
    {
        sentp_info_t *tmp = base;
        base = tmp->next;
        free(tmp);
    }
}

void    print_stats(packet_stats_t *stats, options *opts)
{
    double packet_loss;

    //print_sentp_info(stats->base);

    if (stats->transmitted == 0)
        packet_loss = 100;
    else
        packet_loss = (int)(100.0 * ((float)(stats->transmitted - stats->received) / (float)stats->transmitted));

    struct timeval ct;
    gettimeofday( &ct, NULL );
    int64_t difftime;
    difftime = (ct.tv_sec - stats->start_sec) * 1000000 + ct.tv_usec - stats->start_usec;
    
    printf("\n--- %s ping statistics ---\n", opts->host);
    printf("%ld packets transmitted, %ld received", stats->transmitted, stats->received);
    if (stats->error > 0)
        printf(", +%ld errors", stats->error);
    printf(", %.f%% packet loss", packet_loss);
    printf(", time %ldms\n", difftime/1000);
    
    get_time_stats(stats);
    if (stats->received > 0)
    {
        printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms",
            (double)stats->min/1000, (double)stats->avg/1000,
            (double)stats->max/1000, (double)stats->mdev/1000);
        if (stats->unreceived > 1)
            printf(", pipe %ld", stats->unreceived);
    }
    printf("\n");
}