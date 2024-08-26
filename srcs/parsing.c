#include "ft_traceroute.h"

int     isnumber(char *str)
{
    size_t i;
    size_t len;
    int pointcheck = FALSE;

    len = ft_strlen(str);
    i = 0;

    if (len == 0)
        return FALSE;
    if (str[0] == '-' || str[0] == '+')
        ++i;
    while (i < len)
    {
        if ((str[i] < '0' || str[i] > '9') && str[i] != '.')
            return FALSE;
        
        if (str[i] == '.' && pointcheck == TRUE)
            return FALSE;
        else if (str[i] == '.')
            pointcheck = TRUE;
        
        ++i;
    }
    return TRUE;
}

int     parse_argv(int argc, char **argv, options *opts)
{
    char usage[] =
"Usage\n\
    traceroute [ options ] host [ packet length ]\n\n\
Options:\n\
    -I              Send icmp packet. default is udp.\n\
    -U              Send udp packet\n\
    -q              Sets the number of probe packets per hop. The default is 3.\n\
    -m              Specifies the maximum number of hops (max time-to-live value) traceroute will probe. The default is 30.\n\
    -f              Specifies with what TTL to start. Defaults to 1.\n\
    -N              Set the number of probes to be tried simultaneously (default is 16)\n\
    -p              Set the destination port to use. default is 53 for udp.\n\
    -h --help       read this help and exit\n\n\
Arguments:\n\
+     host          The host to traceroute to\n\
      packetlen     The full packet length (default is the length of an IP\n\
                    header plus 40). Can be ignored or increased to a minimal\n\
                    allowed value\n";
  
    if (argc == 1)
    {
        fprintf(stderr, "%s: usage error: destination addresse or ip required\n", argv[0]);
        return FALSE;
    }

    opts->simul_send_nb = 16;
    opts->max_simul_send = 1000;
    opts->first_ttl = 1;
    opts->maxhops = 30;
    opts->pack_type = 0;
    opts->nqueries = 3;
    opts->maxwait = 100; //TODO: change to float ?
    opts->max_send_wait = 100;
    opts->size = 60;
    opts->port = 80;

    // TODO: argv/argc for both of these
    opts->host = argv[argc - 1]; 
    opts->packetlen = 60;

    // run through arguments
    for (int i = 1; i < argc - 1; ++i)
    {
        if (ft_strcmp(argv[i], "-h") == 0 || ft_strcmp(argv[i], "--help") == 0)
        {
            printf("%s", usage);
            return (FALSE);
        }
        else if (ft_strcmp(argv[i], "-I") == 0 || ft_strcmp(argv[i], "--icmp") == 0)
        {
            opts->pack_type = PTYPE_ICMP;
        }
        else if (ft_strcmp(argv[i], "-U") == 0 || ft_strcmp(argv[i], "--udp") == 0)
        {
            opts->pack_type = PTYPE_UDP;
        }
        else if (strcmp(argv[i], "-f") == 0 && i < argc - 2 && isnumber(argv[i+1]))
        {
            opts->first_ttl = (size_t)ft_atoi(argv[i+1]);
            ++i;
        }
        else if (strcmp(argv[i], "-p") == 0 && i < argc - 2 && isnumber(argv[i+1]))
        {
            opts->port = (size_t)ft_atoi(argv[i+1]);
            ++i;
        }
        else if (strcmp(argv[i], "-m") == 0 && i < argc - 2 && isnumber(argv[i+1]))
        {
            opts->maxhops = (size_t)ft_atoi(argv[i+1]);
            if (opts->maxhops > CHAR_MAX)
            {
                fprintf(stderr, "max hops can not be more than %d\n", CHAR_MAX);
                return FALSE;
            }
            ++i;
        }
        else if (strcmp(argv[i], "-q") == 0 && i < argc - 2 && isnumber(argv[i+1]))
        {
            opts->nqueries = (size_t)ft_atoi(argv[i+1]);
            if (opts->nqueries > 8 || opts->nqueries <= 0)
            {
                fprintf(stderr, "no more than 8 probes per hop\n");
                return FALSE;
            }
            ++i;

        }
        else if (strcmp(argv[i], "-N") == 0 && i < argc - 2 && isnumber(argv[i+1]))
        {
            opts->simul_send_nb = (size_t)ft_atoi(argv[i+1]);
            if (opts->simul_send_nb > INT_MAX || opts->simul_send_nb <= 0)
            {
                fprintf(stderr, "no more than 8 probes per hop\n");
                return FALSE;
            }
            ++i;
        }
        else
        {
            fprintf(stderr, "Bad option `%s` (argc %d)\n", argv[i], i);
            return FALSE;
        }
    }

    if (opts->pack_type == 0)
        opts->pack_type = PTYPE_UDP;

    if (opts->first_ttl <= 0 || opts->first_ttl > opts->maxhops
        || opts->maxhops == 0)
    {
        fprintf(stderr, "first hop out of range\n");
        return FALSE;
    }
    --opts->first_ttl; // for convenience later in code

    if (opts->packetlen < 8)
        opts->packetlen = 8;

    return TRUE;
}
