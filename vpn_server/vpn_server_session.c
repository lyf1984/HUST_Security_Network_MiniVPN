#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "vpn_server.h"

session_t session_table[MAX_SESSIONS] = {0};
last_byte_pool valid_IP[MAX_SESSIONS];
int session_count = 0;

void initialize_IP_POOL()
{
    int i;
    for (i = 0; i < MAX_SESSIONS; i++)
    {
        valid_IP[i].last_byte_IP = i + 2;
        valid_IP[i].if_valid = true;
    }
}

int add_session(const char *client_ip, const char *virtual_ip, int socket_fd,SSL* ssl_session)
{
    strncpy(session_table[session_count].client_ip, client_ip, sizeof(session_table[session_count].client_ip));
    strncpy(session_table[session_count].virtual_ip, virtual_ip, sizeof(session_table[session_count].virtual_ip));
    session_table[session_count].socket_fd = socket_fd;
    session_table[session_count].ssl_session = ssl_session;
    session_count++;
    return 0;
}

session_t *find_session(const char *virtual_ip)
{
    int i;
    for (i = 0; i < session_count; i++)
    {
        if (strcmp(session_table[i].virtual_ip, virtual_ip) == 0)
        {
            return &session_table[i];
        }
    }
    return NULL;
}

void remove_session(int client_sock)
{
    int i;
    for (i = 0; i < MAX_SESSIONS; i++)
    {
        if (session_table[i].socket_fd == client_sock)
        {
            session_count--;
            bzero(&session_table[i],sizeof(session_table[i]));
            valid_IP[i].if_valid = true;
            break;
        }
    }
}
