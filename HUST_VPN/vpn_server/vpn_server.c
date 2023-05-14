#include <arpa/inet.h>
#include <crypt.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netdb.h>
#include <pthread.h>
#include <shadow.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "vpn_server.h"
extern session_t session_table[];
extern last_byte_pool valid_IP[];
extern int session_count;

int main()
{
    int err;
    struct sockaddr_in sa_client;
    size_t client_len = sizeof(sa_client);
    /*------ TCP Connect ------*/
    int listen_sock = setupTCPServer();
    if (listen_sock <= 0)
        printf(PREFIX "Create listen_sock failed\n");
    /*------ tunnel init, redirect and forward ------*/
    int tunfd = createTunDevice();
    system("sudo ifconfig tun0 192.168.53.1/24 up");
    system("sudo sysctl net.ipv4.ip_forward=1");
    /*------ Initialize IP pool ------*/
    initialize_IP_POOL();
    /*------ Manage multiple tunnels ------*/
    while (1)
    {
        fd_set readfds;
        int max_fd, i;

        FD_ZERO(&readfds);
        FD_SET(listen_sock, &readfds);
        FD_SET(tunfd, &readfds);
        max_fd = listen_sock;
        for (i = 0; i < MAX_SESSIONS; i++)
        {
            // 将大于0的项加入readfds
            if (session_table[i].socket_fd > 0)
            {
                FD_SET(session_table[i].socket_fd, &readfds);
                if (session_table[i].socket_fd > max_fd)
                    max_fd = session_table[i].socket_fd;
            }
        }
        int ret = select(max_fd + 1, &readfds, NULL, NULL, NULL);
        if (ret <= 0)
            printf(PREFIX "Select fds failed\n");
        // 当有新的客户端连接请求
        if (FD_ISSET(listen_sock, &readfds))
        {
            int new_sock = accept(listen_sock, (struct sockaddr *)&sa_client, &client_len);
            CHK_ERR(new_sock, "accept");
            printf(PREFIX "TCP accept successfully! sock:%d\n", new_sock);
            // 连接的客户端数量达到上限
            if (session_count >= MAX_SESSIONS)
            {
                printf(PREFIX "Client connection full!\n");
                close(new_sock);
                continue;
            }
            //为该会话创建一个新的ssl
            SSL *ssl = setupTLSServer();
            ret = SSL_set_fd(ssl, new_sock);
            if (!ret)
            {
                printf(PREFIX "SSL_set_fd failed\n");
                exit(1);
            }
            int err = SSL_accept(ssl);
            fprintf(stderr, PREFIX "SSL_accept return %d\n", err);
            CHK_SSL(err);
            printf(PREFIX "SSL connection established!\n");
            int ret = verify_user(ssl, sa_client, new_sock);
            if (ret == -1)
                printf(PREFIX "Verify user failed!\n");
        }
        // 从SSL链路接收数据及判断客户端是否断开连接
        for (i = 0; i < MAX_SESSIONS; i++)
        {
            if (session_table[i].socket_fd <= 0)
                continue;
            if (FD_ISSET(session_table[i].socket_fd, &readfds))
            {
                int client_sock = session_table[i].socket_fd;
                SSL* ssl = session_table[i].ssl_session;
                printf(PREFIX "Send packet to sock:%d\n", client_sock);
                sendto_TUN(ssl, client_sock, tunfd);
            }
        }
        // 从tun0接收数据到SSL链路
        if (FD_ISSET(tunfd, &readfds))
        {
            sendto_SSL(tunfd);
        }
    }
}
