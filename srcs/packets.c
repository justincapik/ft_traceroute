#include "ft_traceroute.h"

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

c_icmphdr   *create_icmp_packet(char *buffer, int size, u_int16_t id, u_int16_t sequence)
{
    // create and fill icmp package
    c_icmphdr *icmp_hdr = (c_icmphdr *)buffer;
    ft_bzero(buffer, BUFFER_SIZE);
    for(int i = sizeof(icmp_hdr); i < BUFFER_SIZE; ++i)
        buffer[i] = (char)(i - sizeof(icmp_hdr));
    
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->id = id;
    icmp_hdr->sequence = sequence;
    icmp_hdr->cksum = 0;
    icmp_hdr->cksum = checksum(icmp_hdr, size);

    return icmp_hdr;
}

packet_info_t *create_packet_list(options *opts)
{
    packet_info_t *base;

    base = (packet_info_t*)malloc(sizeof(packet_info_t) * OPTS_NB_PACK);

    for (size_t i = 0; i < OPTS_NB_PACK; ++i)
    {
        base[i].sent_sec = 0;
        base[i].sent_usec = 0;
        base[i].difftime = 0;
        base[i].hostname = NULL;
        base[i].ip = NULL;
        base[i].state = PACK_UNSENT;
    }

    return (base);
}

void            free_packet_list(packet_info_t *lst, size_t size)
{
    for (size_t i = 0; i < size; ++i)
    {
        if (lst[i].hostname != NULL)
            free(lst[i].hostname);
        if (lst[i].ip != NULL)
            free(lst[i].ip);
    }
    free(lst);
}

// returns sent time
packet_info_t     *check_packet_to_list(packet_info_t *base, c_icmphdr *recicmp,
    size_t opts_nb_pack)
{
    u_int16_t id_start;

    id_start = (u_int16_t)START_ID;

    // printf("rec: id=%d, seq=%d\n", recicmp->id, recicmp->sequence);

    if (recicmp->id >= id_start && recicmp->id < id_start + opts_nb_pack
        && recicmp->sequence <= opts_nb_pack + 1)
    // TODO: condition might be fucky with recicmp->sequence
    // confirmed the condition is fucky, or at least printfs are
    {
        return &(base[recicmp->sequence - 1]);
    }
    else
        return NULL;
}

u_int16_t       get_server_port(int sockfd, struct sockaddr_in *endpoint,
    u_int16_t sug_port)
{
    (void)sug_port;
    endpoint->sin_port = htons(33434); 
    bind(sockfd, (struct sockaddr*)endpoint, sizeof(endpoint));

    return endpoint->sin_port;
}