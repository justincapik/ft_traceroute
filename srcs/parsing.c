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
    traceroute [ options ] host [ packet length ]\n\n\
Options:\n\
    --help          read this help and exit\n\n\
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

    opts->maxhops = 20;
    opts->flags = 0;
    opts->nqueries = 3;
    opts->maxwait = 5; //TODO: change to float ?

    // TODO: argv/argc for both of these
    opts->host = argv[argc - 1]; 
    opts->packetlen = 60;

    // run through arguments
    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            printf("%s", usage);
            return (FALSE);
        }
    }

    return TRUE;
}
