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

c_icmphdr   *create_icmp_packet(char *buffer, u_int16_t id, u_int16_t sequence)
{
    // create and fill icmp package
    c_icmphdr *icmp_hdr = (c_icmphdr *)buffer;
    bzero(buffer, BUFFER_SIZE);
    for(int i = sizeof(icmp_hdr); i < BUFFER_SIZE; ++i)
        buffer[i] = (char)(i - sizeof(icmp_hdr));
    
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->id = id;
    icmp_hdr->sequence = sequence;
    icmp_hdr->cksum = 0;
    icmp_hdr->cksum = checksum(icmp_hdr, 56); //TODO:

    return icmp_hdr;
}

packet_stats_t create_packet_list(options *opts)
{
    size_t id;
    size_t seq;
    packet_info_t *base;

    base = (packet_info_t*)malloc(sizeof(packet_info_t) * OPTS_NB_PACK);

    for (int i = 0; i < OPTS_NB_PACK; ++i)
    {
        base[i].sent_sec = 0;
        base[i].sent_usec = 0;
        base[i].difftime = 0;
        base[i].host = NULL;
        base[i].ip = NULL;
        base[i].state = PACK_UNSENT;
    }

    return (base);
}

// returns sent time
sentp_info_t     *check_packet_to_list(packet_info_t *base, c_icmphdr *recicmp,
    size_t opts_nb_pack)
{
    size_t id_start;

    id_start = ID_START;

    if (recicmp->id >= id_start && recicmp < id_start + opts_nb_pack
        && recicmp->sequence <= opts_nb_pack
        && recicmp->id - recicmp->sequence - 1 == id_start)
    // TODO: condition might be fucky with recicmp->sequence
    {
        return base[recicmp->sequence - 1];
    }
    else
        return NULL;
}