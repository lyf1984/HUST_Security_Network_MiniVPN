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
#define MAX_SIZE 65496

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char buf[300];

    X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);

    printf(PREFIX "subject = %s\n", buf);

    if (preverify_ok == 1)
    {

        printf(PREFIX "Verification passed.\n");
    }
    else
    {
        int err = X509_STORE_CTX_get_error(x509_ctx);

        printf(PREFIX "Error: Verification failed: %s.\n", X509_verify_cert_error_string(err));
    }

    return preverify_ok;
}

SSL *setupTLSClient(const char *hostname)
{
    // Step 0: OpenSSL library initialization
    // This step is no longer needed as of version 1.1.0.
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *ssl;

    meth = SSLv23_client_method();
    ctx = SSL_CTX_new(meth);

    // 设置为SSL_VERIFY_PEER,即验证服务端证书
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    // 需要验证自己生成的根证书，以信任此CA
    if (SSL_CTX_load_verify_locations(ctx, CACERT, NULL) == 0)
    {
        ERR_print_errors_fp(stderr);
        exit(-2);
    }
    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(-2);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(-3);
    }

    if (!SSL_CTX_check_private_key(ctx))
    {

        printf(PREFIX "Private key does not match the certificate public keyn");
        exit(-4);
    }
    ssl = SSL_new(ctx);

    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);

    X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);
    printf(PREFIX "Set up TLS client successfully!\n");
    return ssl;
}

int setupTCPClient(const char *hostname, int port)
{
    struct sockaddr_in server_addr;
    struct addrinfo hints = {0}, *result;

    hints.ai_family = AF_INET; // AF_INET means IPv4 only addresses
    int error = getaddrinfo(hostname, NULL, &hints, &result);
    if (error)
    {
        fprintf(stderr, PREFIX "getaddrinfo: %s\n", gai_strerror(error));
        exit(1);
    }
    // The result may contain a list of IP address; we take the first one.
    struct sockaddr_in *ip = (struct sockaddr_in *)result->ai_addr;

    printf(PREFIX "Destination IP Address: %s\n", (char *)inet_ntoa(ip->sin_addr));

    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&server_addr, '\0', sizeof(server_addr));
    server_addr.sin_addr.s_addr = inet_addr((char *)inet_ntoa(ip->sin_addr));
    server_addr.sin_port = htons(port);
    server_addr.sin_family = AF_INET;
    int ret = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret == -1)
        printf(PREFIX "TCP connect to server failed\n");
    else
        printf(PREFIX "Set up TCP client successfully!\n");
    return sockfd;
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

void try_login(SSL *ssl)
{
    char username[256];
    char passwd[10];

    printf(PREFIX "Enter Username:");
    scanf("%s", username);
    printf(PREFIX "Enter Password:");
    scanf("%s", passwd);

    SSL_write(ssl, username, strlen(username)); // username
    SSL_write(ssl, passwd, strlen(passwd));     // password
}

void sendto_TUN(SSL *ssl, int tunfd)
{
    char buf[MAX_SIZE] = {0};
    int len = SSL_read(ssl, buf, MAX_SIZE - 1);
    // 服务端断开连接
    if (len == 0)
    {
        // 关闭会话
        return -1;
    }
    // 出现错误
    if (len < 0)
    {
        int error = SSL_get_error(ssl,len);
        printf(PREFIX "SSL_read error! error code:%d\n", error);
        unsigned long err = ERR_get_error();
        if (err != 0)
        {
            char err_msg[256];
            ERR_error_string_n(err, err_msg, sizeof(err_msg));
            printf(PREFIX"OpenSSL Error: %s\n", err_msg);
        }
        return -2;
    }
    int ret = write(tunfd, buf, len);
    printf(PREFIX "SSL => TUN: %dbytes\n", ret);
    return 0;
}



void sendto_SSL(SSL *ssl, int tunfd)
{
    char buf[MAX_SIZE] = {0};
    int len = read(tunfd, buf, MAX_SIZE - 1);
    // 判断是否为ipv4协议包
    if (len >= 20 && buf[0] == 0x45)
    {
        int ret = SSL_write(ssl, buf, len);
        printf(PREFIX"TUN => SSL: %dbytes\n", ret);
    }
}