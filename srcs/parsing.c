#include "ft_traceroute.h"

int     isnumber(char *str)
{
    size_t i;
    size_t len;
    int pointcheck = FALSE;

    len = strlen(str);
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
    ping [options] <destination>\n\n\
Options:\n\
  <destination>  dns name or ip address\n\
  -a             use audible ping\n\
  -c <count>     stop after <count> replies\n\
  -D             print timestamps\n\
  -i <interval>  seconds between sending each packet\n\
  -h             print help and exit\n\
  -q             quiet output\n\
  -t <ttl>       define time to live\n\
  -v             verbose output\n";
  
    if (argc == 1)
    {
        fprintf(stderr, "%s: usage error: destination addresse or ip required\n", argv[0]);
        return FALSE;
    }

    opts->ttl = 64;
    opts->flags = 0;
    opts->host = argv[argc - 1];
    opts->count = -1;
    opts->interval = 1;
    opts->size = 56;

    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            opts->flags |= OPTS_VERBOSE;
        else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--alert") == 0)
            opts->flags |= OPTS_ALERT;
        else if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0)
            opts->flags |= OPTS_QUIET;
        else if (strcmp(argv[i], "-D") == 0 || strcmp(argv[i], "--timestamps") == 0)
            opts->flags |= OPTS_TIMESTAMP;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            printf("%s", usage);
            return (FALSE);
        }
        else if (strcmp(argv[i], "-c") == 0 && isnumber(argv[i+1]) && i < argc - 2)
        {
            opts->count = atol(argv[i+1]);
            if (opts->count <= 0 || opts->count > LONG_MAX)
            {
                fprintf(stderr, "%s: invalid argument: '%s': out of range: 1 <= value <= %ld\n",
                    argv[0], argv[i+1], LONG_MAX);
                return FALSE;
            }
            ++i;
        }
        else if (strcmp(argv[i], "-i") == 0 && isnumber(argv[i+1]) && i < argc - 2)
        {
            opts->interval = atof(argv[i+1]);
            if (opts->interval < 0 || opts->interval > SHRT_MAX)
            {
                fprintf(stderr, "%s: invalid argument: '%s': out of range: 0 <= value <= %d\n",
                    argv[0], argv[i+1], SHRT_MAX);
                return FALSE;
            }
            if (opts->interval < 0.01)
                opts->interval = 0.01;
            ++i;
        }
        else if (strcmp(argv[i], "-t") == 0 && isnumber(argv[i+1]) && i < argc - 2)
        {
            long tmp = atol(argv[i+1]);
            if (tmp < 0 || tmp > 255)
            {
                fprintf(stderr, "%s: invalid argument: '%s': out of range: 0 <= value <= 255\n",
                    argv[0], argv[i+1]);
                return FALSE;
            }
            opts->ttl = tmp;
            ++i;
        }
        else if (i != argc - 1)
        {
            fprintf(stderr, "%s: invalid argument: %s\n", argv[0], argv[i]);
            return FALSE;
        }
    }

    return TRUE;
}
