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

c_icmphdr   *create_icmp_packet(char *buffer)
{
    // create and fill icmp package
    c_icmphdr *icmp_hdr = (c_icmphdr *)buffer;
    bzero(buffer, BUFFER_SIZE);
    for(int i = sizeof(icmp_hdr); i < BUFFER_SIZE; ++i)
        buffer[i] = (char)(i - sizeof(icmp_hdr));
    
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->id = 12345; //filler 
    icmp_hdr->sequence = 0;
    icmp_hdr->cksum = 0;
    icmp_hdr->cksum = checksum(icmp_hdr, 56); //TODO:

    return icmp_hdr;
}

// MAYBE keep
void        update_packet(c_icmphdr *icmp_hdr, int ident)
{
    icmp_hdr->sequence = icmp_hdr->sequence + 1;
    icmp_hdr->id = ident;
    icmp_hdr->cksum = 0;
    icmp_hdr->cksum = checksum(icmp_hdr, 56 + sizeof(c_icmphdr)); //TODO:
}

// returns sent time
sentp_info_t     *check_if_packet_exists(sentp_info_t *base, c_icmphdr *recicmp)
{
    sentp_info_t    *tmp = base;

    while (tmp != NULL)
    {
        if (tmp->received == FALSE
            && tmp->id == recicmp->id && tmp->seq == recicmp->sequence)
        {
            tmp->received = TRUE;
            return tmp;
        }
        tmp = tmp->next;
    }
    return NULL;
}