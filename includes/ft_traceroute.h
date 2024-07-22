#ifndef FT_TRACEROUTE_H
# define FT_TRACEROUTE_H

#include <stdio.h>
#include <stdlib.h> //for exit()
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <netdb.h> // for NI_MAXHOST, getnameinfo() and gai_strerror()
#include <netinet/in.h> 
#include <netinet/ip_icmp.h>
#include <errno.h> // for errno
#include <time.h>
#include <sys/time.h>
#include <limits.h>

#include "libft.h"

# define TRUE 1
# define FALSE 0
# define ERROR 2

# define OPTS_VERBOSE 0x1
# define OPTS_NO_HOSTNAME 0x2

# define BUFFER_SIZE SHRT_MAX

typedef struct options_s {
    size_t      maxhops;
    int         packetlen;
    uint64_t    flags;
    size_t      nqueries;
    char        *host;
    char        *ip;
} options;

typedef struct custom_icmphdr_s
{
    u_int8_t    type;                /* message type */
    u_int8_t    code;                /* type sub-code */
    u_int16_t   cksum;
    u_int16_t   id;
    u_int16_t   sequence;
} c_icmphdr;

typedef struct packet_info_s
{
    // id is index in table
    u_int16_t   seq;
    time_t      sent_sec;
    suseconds_t sent_usec;
    int64_t     difftime; // maybe delete ?
    int         received; //bool
} packet_info_t;

int                 parse_argv(int argc, char **argv, options *opts);
char                *dns_lookup(char *canonname, options *opts);
int                 hostname_lookup(unsigned int ip, char *revhostname);

c_icmphdr           *create_icmp_packet(char *buffer);
unsigned short      checksum(void *b, int len);
void                update_packet(c_icmphdr *icmp_hdr, int ident);
sentp_info_t        *check_if_packet_exists(sentp_info_t *base, c_icmphdr *recicmp);

void                ping_loop(struct sockaddr_in *endpoint, int sockfd,
                        options *opts, packet_stats_t *stats);

#endif