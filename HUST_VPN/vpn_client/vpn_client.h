#include <netinet/tcp.h>
#include <netinet/ip.h>
#define PREFIX "\033[0m\033[1;31m[CLIENT]\033[0m"
#define CHK_NULL(x)  \
    if ((x) == NULL) \
    exit(1)
#define CHK_SSL(err)                 \
    if ((err) < 1)                   \
    {                                \
        ERR_print_errors_fp(stderr); \
        exit(2);                     \
    }

/* define HOME to be dir for key and cert files... */
#define HOME "./ca_client/"
/* Make these what you want for cert & key files */
#define CERTF HOME "client.crt"
#define KEYF HOME "client.key"
#define CACERT HOME "ca.crt"