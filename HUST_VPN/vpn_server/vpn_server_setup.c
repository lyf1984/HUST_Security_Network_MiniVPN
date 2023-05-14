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

SSL *setupTLSServer()
{
    SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *ssl;

    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    meth = SSLv23_server_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_load_verify_locations(ctx, CACERT, NULL);
    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(4);
    }
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, PREFIX "Private key does not match the certificate public key\n");
        exit(5);
    }
    ssl = SSL_new(ctx);
    return ssl;
}

int setupTCPServer()
{
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset(&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port = htons(4433);
    int err = bind(listen_sock, (struct sockaddr *)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

int createTunDevice()
{
    int tunfd;
    struct ifreq ifr;
    int ret;

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    tunfd = open("/dev/net/tun", O_RDWR);
    if (tunfd == -1)
    {

        printf(PREFIX "Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    ret = ioctl(tunfd, TUNSETIFF, &ifr);
    if (ret == -1)
    {

        printf(PREFIX "Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }

    printf(PREFIX "Setup TUN interface success!\n");
    return tunfd;
}

int sendto_TUN(SSL *ssl, int client_sock, int tunfd)
{
    char buf[MAX_SIZE] = {0};
    int len = SSL_read(ssl, buf, MAX_SIZE - 1);
    // 客户端断开连接
    if (len == 0)
    {
        // 关闭会话，并从会话表移除
        remove_session(client_sock);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_sock);
        printf(PREFIX "Client: disconnected!\n");
        return -1;
    }
    // 出现错误
    if (len < 0)
    {
        int error = SSL_get_error(ssl, len);
        printf(PREFIX "SSL_read error! error code:%d\n", error);
        unsigned long err = ERR_get_error();
        if (err != 0)
        {
            char err_msg[256];
            ERR_error_string_n(err, err_msg, sizeof(err_msg));
            printf(PREFIX "OpenSSL Error: %s\n", err_msg);
        }
        return -2;
    }
    int ret = write(tunfd, buf, len);
    printf(PREFIX "SSL => TUN: %dbytes\n", ret);
    return 0;
}

void sendto_SSL(int tunfd)
{
    char buf[MAX_SIZE] = {0};
    int len = read(tunfd, buf, MAX_SIZE - 1);
    // 判断是否为ipv4协议包
    if (len >= 20 && buf[0] == 0x45)
    {
        // 获取目标IP地址
        struct iphdr *ip_header = (struct iphdr *)buf;
        struct in_addr client_addr;
        client_addr.s_addr = ip_header->daddr;
        char dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr, dest_ip, INET_ADDRSTRLEN);
        // 从会话表中查询
        session_t *session = find_session(dest_ip);
        if (session == NULL)
        {
            printf(PREFIX "No such session in table!\n");
            return;
        }
        SSL *ssl = session->ssl_session;
        SSL_set_fd(ssl, session->socket_fd);
        int ret = SSL_write(ssl, buf, len);
        printf(PREFIX "TUN => SSL: %dbytes", ret);
        printf(" Destination IP address: %s\n", dest_ip);
    }
}

int login(char *user, char *passwd)
{
    struct spwd *pw;
    char *epasswd;
    pw = getspnam(user);
    if (pw == NULL)
    {
        printf(PREFIX "User not exist!\n");
        return -1;
    }
    printf(PREFIX "Login name: %s\n", pw->sp_namp);
    printf(PREFIX "Passwd : %s\n", pw->sp_pwdp);
    epasswd = crypt(passwd, pw->sp_pwdp);
    if (strcmp(epasswd, pw->sp_pwdp))
    {
        printf(PREFIX "Password not correct\n");
        return -1;
    }
    return 1;
}

// 验证用户并分配虚拟IP
int verify_user(SSL *ssl, struct sockaddr_in client_addr, int sock)
{
    char username[256] = {0};
    char passwd[10] = {0};
    char client_IP[64];
    char virtual_IP[64];
    SSL_read(ssl, username, sizeof(username) - 1);
    SSL_read(ssl, passwd, sizeof(username) - 1);

    if (login(username, passwd) == 1)
    {
        int i;
        inet_ntop(AF_INET, &client_addr.sin_addr, client_IP, sizeof(client_IP));
        for (i = 0; i < MAX_SESSIONS; i++)
        {
            if (valid_IP[i].if_valid)
            {
                sprintf(virtual_IP, "%s%d", BASIC_IP, valid_IP[i].last_byte_IP);
                valid_IP[i].if_valid = false;
                break;
            }
        }
        if (add_session(client_IP, virtual_IP, sock, ssl) < 0)
        {
            printf("Add session failed");
            return -1;
        }
        printf(PREFIX "Assign IP:%s\n", virtual_IP);
        SSL_write(ssl, "yes", strlen("yes")); // send success
        SSL_write(ssl, virtual_IP, strlen(virtual_IP));
        return 0;
    }
    // 验证失败
    else
    {
        SSL_write(ssl, "no", strlen("no")); // send fail
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        return -1;
    }
}
