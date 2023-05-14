#include <stdbool.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
/* define HOME to be dir for key and cert files... */
#define HOME "./ca_server/"
#define PREFIX "\033[0m\033[1;31m[SERVER]\033[0m"

/* Make these what you want for cert & key files */
#define CERTF HOME "server.crt"
#define KEYF HOME "server.key"
#define CACERT HOME "ca.crt"
#define MAX_SIZE 65496
#define CHK_NULL(x)  \
    if ((x) == NULL) \
    exit(1)
#define CHK_ERR(err, s) \
    if ((err) == -1)    \
    {                   \
        perror(s);      \
        exit(1);        \
    }
#define CHK_SSL(err)                 \
    if ((err) == -1)                 \
    {                                \
        ERR_print_errors_fp(stderr); \
        exit(2);                     \
    }
#define BASIC_IP "192.168.53."
#define MAX_SESSIONS 253

typedef struct
{
    char client_ip[16];
    char virtual_ip[16];
    int socket_fd;
    SSL *ssl_session;
} session_t;

typedef struct
{
    int last_byte_IP;
    bool if_valid;
} last_byte_pool;