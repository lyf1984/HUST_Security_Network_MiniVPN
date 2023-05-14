#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <string.h>
#include <sys/ioctl.h>
#include "vpn_client.h"

int main(int argc, char *argv[])
{
    char hostname[128];
    int port;

    /*------ Destination initialization ------*/
    printf(PREFIX "Enter server name:");
    scanf("%s", hostname);
    printf(PREFIX "Enter port:");
    scanf("%d", &port);
    /*------ TLS initialization ------*/
    SSL *ssl = setupTLSClient(hostname);
    /*------ TCP connection ------*/
    int sockfd = setupTCPClient(hostname, port);
    /*------ TLS handshake ------*/
    SSL_set_fd(ssl, sockfd);
    int err = SSL_connect(ssl);
    CHK_SSL(err);
    printf(PREFIX "SSL connected! \n");
    printf(PREFIX "SSL connection using %s\n", SSL_get_cipher(ssl));
    /*------ Authenticating ------*/
    int ret = try_login(ssl);
    //login failed
    if (ret < 0){
        printf(PREFIX"Login failed!\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
        return 0;
    }
    printf(PREFIX "Login successfully!\n");
    /*------ Allocate IP ------*/
    char client_IP[64] = {0};
    char cmd[100];
    SSL_read(ssl, client_IP, sizeof(client_IP));
    printf(PREFIX "Auto-assigned IP:%s\n", client_IP);
    /*------ Add route ------*/
    int tunfd = createTunDevice();
    sprintf(cmd, "sudo ifconfig tun0 %s/24 up", client_IP);
    system(cmd);
    sprintf(cmd, "sudo route add -net 192.168.60.0/24 tun0");
    system(cmd);
    /*------ Listen sock&tun0 ------*/
    while (1)
    {
        fd_set readFDSet;
        int ret;
        FD_ZERO(&readFDSet);
        FD_SET(sockfd, &readFDSet);
        FD_SET(tunfd, &readFDSet);
        ret = select((sockfd > tunfd ? sockfd : tunfd) + 1, &readFDSet, NULL, NULL, NULL);
        if (FD_ISSET(sockfd, &readFDSet))
        {
            ret = sendto_TUN(ssl, tunfd);
            // 服务端关闭会话
            if (ret == -1)
            {
                printf(PREFIX "Server disconnected!\n");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(sockfd);
            }
        }
        if (FD_ISSET(tunfd, &readFDSet))
            sendto_SSL(ssl, tunfd);
    }
    return 0;
}
