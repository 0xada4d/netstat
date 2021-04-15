#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define FILEPATH "/proc/net/tcp"
#define MAX_DATA 65535
#define NUM_DES_FIELDS 4

char *STATUS_ID[12] = { NULL, "TCP_ESTABLISHED", "TCP_SYN_SENT", "TCP_SYN_RECV", "TCP_FIN_WAIT1",
    "TCP_FIN_WAIT2", "TCP_TIME_WAIT", "TCP_CLOSE", "TCP_CLOSE_WAIT", "TCP_LAST_ACK",
    "TCP_LISTEN", "TCP_CLOSING" };


FILE *open_file(const char *filepath)
{
    FILE *ns_file;
    ns_file  = fopen(filepath, "r");
    if (ns_file == NULL)
    {
        printf("failed opening file\n");
        exit(1);
    }
    return ns_file;
}

char *read_file(FILE *file, int bufsz)
{
    char *buf = malloc(sizeof(char) * bufsz);
    memset(buf, '\0', bufsz);

    size_t br = fread(buf, bufsz + 1, 1, file);
    if (br == -1)
    {
        printf("failed reading file\n");
        exit(1);
    }

    return buf;
}

char *ascii_to_hex(char *val)
{
    char *hexstr = malloc(6);
    long hex = strtol(val, NULL, 16);
    snprintf(hexstr, 6, "%ld", hex);
    return hexstr;
}

char *ascii_to_ip(char *val)
{
    struct in_addr *addr = malloc(sizeof(struct in_addr));
    addr->s_addr = (in_addr_t)strtol(val, NULL, 16);
    char *ip = inet_ntoa(*addr);
    free(addr);
    return ip;
}

void parse_data(char *buffer)
{
    int rot = 0;
    char *cur, *cur_copy, *cur_sub, *cur_sub_sub, *cur_sub_copy;
    char *saveptr1, *saveptr2, *saveptr3;
    while (cur = strtok_r(buffer, "\n", &saveptr1))
    {
        if (rot == 0)
        {
            rot++;
            buffer = NULL;
            continue;
        }
        cur_copy = cur;
        for (int x = 0; x < NUM_DES_FIELDS; x++)
        {
            cur_sub = strtok_r(cur_copy, " ", &saveptr2);
            if (x == 0)
            {
                cur_copy = NULL;
                continue;
            }
            cur_sub_copy = cur_sub;
            if (x == 1)
            {
                char *la = ascii_to_ip(strtok_r(cur_sub_copy, ":", &saveptr3));
                char *lp = ascii_to_hex(strtok_r(NULL, ":", &saveptr3));
                printf("====================\n");
                printf("[l] local addr:\t\t %s\n[l] local port:\t\t %s\n", la, lp);
                free(lp);
                continue;
            }
            if (x == 2)
            {
                char *ra = ascii_to_ip(strtok_r(cur_sub_copy, ":", &saveptr3));
                char *rp = ascii_to_hex(strtok_r(NULL, ":", &saveptr3));
                printf("[r] remote addr:\t %s\n[r] remote port:\t %s\n", ra, rp);
                free(rp);
                continue;
            }
            else
            {
                char *st = ascii_to_hex(cur_sub_copy);
                printf("[+] state:\t\t %s\n", STATUS_ID[atoi(st)]);
                free(st);
                continue;
            }
        }   
    }

}


int main(int argc, char **argv)
{

    FILE *ns_file = open_file(FILEPATH);
    char *buf = read_file(ns_file, MAX_DATA);
    
    parse_data(buf);
    
    free(buf);
    fclose(ns_file);

    return 0;
}
