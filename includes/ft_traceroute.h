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

# define PACK_UNSENT 0 
# define PACK_SENT 1
# define PACK_RECEIVED 2
# define PACK_REC_END 3
# define PACK_REC_PRINTED 4
# define PACK_EXCEEDED 5

# define OPTS_VERBOSE 0x1
# define OPTS_NO_HOSTNAME 0x2

# define PTYPE_ICMP 0x1
# define PTYPE_UDP 0x2
# define PTYPE_TCP 0x3

# define BUFFER_SIZE SHRT_MAX

# define OPTS_NB_PACK (opts->nqueries * opts->maxhops - opts->first_ttl)

# define START_ID getpid()

typedef struct options_s 
{
    size_t      simul_send_nb;
    size_t      max_simul_send; // -w
    size_t      pkg_send_diff;
    size_t      grp_send_diff;
    size_t      first_ttl;
    size_t      maxhops; // -m max_ttl 
    int         packetlen;
    size_t      maxwait; // -w
    size_t      max_send_wait; // -w
    size_t      size;
    u_int16_t   port;
    u_int8_t    pack_type;
    char        nqueries; // -q number of probes per hop
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

typedef struct packet_info_s packet_info_t;
struct packet_info_s
{
    time_t          sent_sec;
    suseconds_t     sent_usec;
    size_t          difftime;
    char            ttl;
    char            *hostname;
    char            *ip;
    char            state; // PACK_ values
};
// id starts with getuid() and +1 for every packet
// id and seq can be deduced

int                 parse_argv(int argc, char **argv, options *opts);
struct addrinfo     *dns_lookup(char *canonname, options *opts);
int                 hostname_lookup(unsigned int ip, char *revhostname);

c_icmphdr           *create_icmp_packet(char *buffer, int size, u_int16_t id,
                        u_int16_t sequence);
u_int16_t           get_server_port(int sockfd, struct sockaddr_in *endoint, u_int16_t sug);
unsigned short      checksum(void *b, int len);
void                update_packet(c_icmphdr *icmp_hdr, int ident);
packet_info_t       *check_packet_to_list(packet_info_t *base, c_icmphdr *recicmp,
                        size_t opts_nb_pack);
packet_info_t       *create_packet_list(options *opt);
void                free_packet_list(packet_info_t *lst, size_t size);

void                ping_loop(struct sockaddr_in *endpoint, options *opts,
                        int rec_sock_fd, int send_sockfd);

#endif