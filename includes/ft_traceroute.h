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

# define TRUE 1
# define FALSE 0
# define ERROR 2

# define OPTS_VERBOSE 0x1
# define OPTS_NO_HOSTNAME 0x2
# define OPTS_COUNT 0x4
# define OPTS_TIMESTAMP 0x8
# define OPTS_QUIET 0x10
# define OPTS_ALERT 0x20
# define OPTS_FLOOD 0x40
# define OPTS_CONNECT 0x80

# define BUFFER_SIZE SHRT_MAX

static volatile int keepRunning = TRUE;

typedef struct options_s {
    int64_t     count;
    double      interval;
    uint64_t    flags;
    int         size;
    char        *host;
    char        *ip;
    char        ttl;
} options;

typedef struct sent_paquet_info_s sentp_info_t;
struct sent_paquet_info_s {
    u_int16_t                   id;
    u_int16_t                   seq;
    time_t                      sent_sec;
    suseconds_t                 sent_usec;
    int64_t                     difftime;
    int                         received; //bool
    sentp_info_t                *next;
};

typedef struct custom_icmphdr_s
{
    u_int8_t    type;                /* message type */
    u_int8_t    code;                /* type sub-code */
    u_int16_t   cksum;
    u_int16_t   id;
    u_int16_t   sequence;
} c_icmphdr;

typedef struct packet_stats {
    int64_t         transmitted;
    int64_t         received;
    int64_t         unreceived;
    int64_t         error;
    time_t          start_sec;
    suseconds_t     start_usec;
    int64_t         last_difftime;
    int64_t         min;
    int64_t         max;
    int64_t         avg;
    int64_t         mdev;
    sentp_info_t    *base;
} packet_stats_t;

int                 parse_argv(int argc, char **argv, options *opts);
char                *dns_lookup(char *canonname, options *opts);
int                 hostname_lookup(unsigned int ip, char *revhostname);

c_icmphdr           *create_icmp_packet(char *buffer);
unsigned short      checksum(void *b, int len);
void                update_packet(c_icmphdr *icmp_hdr, int ident);
void                add_p_to_list(sentp_info_t **base, u_int16_t id, u_int16_t seq);
sentp_info_t        *check_if_packet_exists(sentp_info_t *base, c_icmphdr *recicmp);
void                print_sentp_info(sentp_info_t *base);
void                free_ll(sentp_info_t *base);

void                ping_loop(struct sockaddr_in *endpoint, int sockfd,
                        options *opts, packet_stats_t *stats);
void                get_time_stats(packet_stats_t *stats);
void                print_stats(packet_stats_t *stats, options *opts);

#endif