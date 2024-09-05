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

int     assign_host_or_packlen(char *str, options *opts, int i)
{
    static int count = 0;

    count++;
    if (count > 2)
    {
        fprintf(stderr, "Extra arg `%s' (argc %d)\n", str, i);
        return FALSE;   
    }
    else if (count == 1)
        opts->host = str;
    else if (count == 2)
    {
        if (isnumber(str) == FALSE)
        {
            fprintf(stderr, "Cannot handle \"packetlen\" cmdline arg `%s' (argc %d)\n", str, i);
            return FALSE;
        }
        opts->packetlen = ft_atoi(str);
        if (opts->packetlen < 0)
        {
            fprintf(stderr, "Bad option `%s' (argc %d)\n", str, i);
            return FALSE;
        }
    }

    return TRUE;
}

int     parse_options(int argc, char **argv, options *opts)
{
    char usage[] =
"Usage\n\
    traceroute [ options ] host [ packet length ]\n\n\
Options:\n\
    -I              Send icmp packet.\n\
    -U              Send udp packet. default is icmp\n\
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
        printf("%s", usage);
        return FALSE;
    }

    // run through arguments
    for (int i = 1; i < argc; ++i)
    {
        if (ft_strcmp(argv[i], "-h") == 0 || ft_strcmp(argv[i], "--help") == 0)
        {
            printf("%s", usage);
            return FALSE;
        }
        else if (ft_strcmp(argv[i], "-I") == 0 || ft_strcmp(argv[i], "--icmp") == 0)
        {
            opts->pack_type = PTYPE_ICMP;
        }
        else if (ft_strcmp(argv[i], "-U") == 0 || ft_strcmp(argv[i], "--udp") == 0)
        {
            opts->pack_type = PTYPE_UDP;
        }
        else if (strcmp(argv[i], "-f") == 0 && i < argc - 1 && isnumber(argv[i+1]))
        {
            opts->first_ttl = (size_t)ft_atoi(argv[i+1]);
            ++i;
        }
        else if (strcmp(argv[i], "-p") == 0 && i < argc - 1 && isnumber(argv[i+1]))
        {
            opts->port = (size_t)ft_atoi(argv[i+1]);
            ++i;
        }
        else if (strcmp(argv[i], "-m") == 0 && i < argc - 1 && isnumber(argv[i+1]))
        {
            opts->maxhops = (size_t)ft_atoi(argv[i+1]);
            if (opts->maxhops > CHAR_MAX)
            {
                fprintf(stderr, "max hops can not be more than %d\n", CHAR_MAX);
                return FALSE;
            }
            ++i;
        }
        else if (strcmp(argv[i], "-q") == 0 && i < argc - 1 && isnumber(argv[i+1]))
        {
            opts->nqueries = (size_t)ft_atoi(argv[i+1]);
            if (opts->nqueries > 8 || opts->nqueries <= 0)
            {
                fprintf(stderr, "no more than 8 probes per hop\n");
                return FALSE;
            }
            ++i;

        }
        else if (strcmp(argv[i], "-N") == 0 && i < argc - 1 && isnumber(argv[i+1]))
        {
            opts->simul_send_nb = (size_t)ft_atoi(argv[i+1]);
            if (opts->simul_send_nb > INT_MAX || opts->simul_send_nb <= 0)
            {
                fprintf(stderr, "no more than 8 probes per hop\n");
                return FALSE;
            }
            ++i;
        }
        else if (argv[i][0] == '-')
        {
            fprintf(stderr, "Bad option `%s` (argc %d)\n", argv[i], i);
            return FALSE;
        }
        else
        {
            if (assign_host_or_packlen(argv[i], opts, i) == FALSE)
                return FALSE;
        }
    }

    return TRUE;
}

int     parse_argv(int argc, char **argv, options *opts)
{
    opts->simul_send_nb = 16;
    opts->max_simul_send = 1000;
    opts->first_ttl = 1;
    opts->maxhops = 30;
    opts->pack_type = 0;
    opts->nqueries = 3;
    opts->maxwait = 100;
    opts->max_send_wait = 100;
    opts->port = 80;
    opts->packetlen = 60;
    opts->host = NULL;

    // it's all happening in this function
    if (parse_options(argc, argv, opts) != TRUE)
        return FALSE;
    if (opts->host == NULL)
    {
        fprintf(stderr, "Specify \"host\" missing argument.\n");
        return FALSE;
    }

    if (opts->pack_type == 0)
        opts->pack_type = PTYPE_ICMP;

    if (opts->first_ttl <= 0 || opts->first_ttl > opts->maxhops
        || opts->maxhops == 0)
    {
        fprintf(stderr, "first hop out of range\n");
        return FALSE;
    }
    --opts->first_ttl; // for convenience later in code
    
    if (opts->packetlen < 28)
        opts->packetlen = 28;

    return TRUE;
}
