#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>     /* getopt, ssize_t */
#include "status.h"

#define SIZE_OF_BUFFER 128

/**
 * List of domain name elements.
 * The domain name will be explain as `dhost`.`dsecond`.`dtop` string.
 * E.x., "www.ncku.com", "mail.david.edu" ...
 *
 * You may add any element to the list manually.
 */
const char *dtop[] = {"com", "org", "edu", "net", "int", "gov"};
const char *dsecond[] = {"david", "ncku", "oslab"};
const char *dhost[] = {"www", "ftp", "mail"};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

/**
 * connect_server - connect to server and get the socket file descriptor
 * @host: server host name
 * @port: server port
 *
 * Return server's socket file descriptor if success, or print stderr 
 * message and exit failure automatically.
 *  
 * Make sure to close the server when necessary.
 * 
 * Note: The code is modefied from the example of getaddrinfo(3) man
 * page.
 */
int connect_server(const char *host, const char *port)
{
        struct addrinfo hints;
        struct addrinfo *result, *rp;
        struct sockaddr *peer_addr;
        socklen_t peer_addr_size;
        int s, sfd, cfd;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
        hints.ai_socktype = SOCK_STREAM; /* Stream socket */
        hints.ai_flags = 0;
        hints.ai_protocol = 0;           /* Any protocol */

        s = getaddrinfo(host, port, &hints, &result);
        if (s != 0) {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
        }

        for (rp = result; rp != NULL; rp = rp->ai_next) {
                sfd = socket(rp->ai_family, rp->ai_socktype,
                                rp->ai_protocol);
                if (sfd == -1)
                        continue;

                if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
                        break;          /* Success */

                close(sfd);
        }

        if (rp == NULL)                 /* No address succeeded */
        {
                fprintf(stderr, "Could not connect to server.\nDid server opened?\n");
                exit(EXIT_FAILURE);
        }        

        freeaddrinfo(result);           /* No longer needed */
        return sfd;
}

/**
 * generate_request
 * @method: specified the method of the return request
 *   1: SET request
 *   2: GET request
 *   3: INTO request
 *   for any other values, it call rand() to create a randomly request
 * @size: size of return request
 * @request: return request
 */
void generate_request(int method, size_t *size, char *request)
{
        if (method <= 0 || method > 3) {/* method mush be 1~3 */
                method = rand() % 10;   /* ratio SET:GET:INFO = 6:3:1 */
                if (method < 6) method = 1;
                else if (method == 9) method = 3;
                else method = 2;
        }
                
        switch (method) {
                case 1:                 /* SET case */
                        *size = sprintf(request, "SET %s.%s.%s 192.168.0.%d", 
                                        dhost[rand() % ARRAY_SIZE(dhost)], 
                                        dsecond[rand() % ARRAY_SIZE(dsecond)],
                                        dtop[rand() % ARRAY_SIZE(dtop)],
                                        rand() % 256);
                        break;
                case 2:                 /* GET case */
                        *size = sprintf(request, "GET %s.%s.%s", 
                                        dhost[rand() % ARRAY_SIZE(dhost)], 
                                        dsecond[rand() % ARRAY_SIZE(dsecond)],
                                        dtop[rand() % ARRAY_SIZE(dtop)]);
                        break;
                case 3:                 /* INFO case */
                        *size = sprintf(request, "INFO");
                        break;
        }
}

static inline int send_request(int sfd, size_t size, const char *request)
{
        if (write(sfd, &size, sizeof(size_t)) == -1)
                return -1;

        if (write(sfd, request, size) == -1)
                return -1;

        return 0;
}

static inline int receive_response(int sfd, size_t *size, char *response)
{
        ssize_t ret;
        ret = read(sfd, size, sizeof(size_t));
        if (ret <= 0)
                return -1;

        ret = read(sfd, response, *size);
        if (ret <= 0)
                return -1;

        return 0;
}

/** 
 * handle_connect
 * @sfd: server's socket file descriptor
 * @run: how many `run`
 * @random: create request by user input or by generate_request()
 * 
 * handle_connect() will execute multipe `run`(s).
 * For each `run`, it will send a request to server.
 * Then, recieve the response message from server.
 *
 * If `random` is false(zero), than user must input request manually.
 * Otherwise, it will create randomly request by calling generate_request().
 */
int handle_connect(int sfd, int run, int random)
{
        size_t size = SIZE_OF_BUFFER;
        size_t size_request, size_response;
        char *inputs;
        char *request = malloc(SIZE_OF_BUFFER);
        char response[SIZE_OF_BUFFER];

        while (run--) {
                if (random == 0) {
                        size_request = getline(&request, &size, stdin); 
                        if (request[size_request - 1] == '\n')
                                request[--size_request] = '\0';
                }
                else
                        generate_request(0, &size_request, request);

                if (send_request(sfd, size_request, request) == -1)
                        return -1;

                request[size_request] = '\0';
                printf("[LOG] send: %s\n", request);

                if (receive_response(sfd, &size_response, response) == -1)
                        return -1;

                response[size_response] = '\0';
                printf("[LOG] receive: %s\n", response);
        }

        free(request);
        return 0;
}

int main(int argc, char *argv[])
{
        int opt, sfd;
        int random = 1, run = 10;
        const char *server = "127.0.0.1", *port = "12345";

        while((opt = getopt(argc, argv, "hur:s:p:")) != -1) {
                switch (opt) {
                        case 'u':
                                random = 0;
                                break;
                        case 'r':
                                run = atoi(optarg);
                                break;
                        case 's':
                                server = optarg;
                                break;
                        case 'p':
                                port = optarg;
                                break;        
                        default:
                                fprintf(stderr, 
                                        "Usage: %s [-u] [-r run] [-s server] [-p port]\n"
                                        "  -u: create request by user input, default: random generation\n"
                                        "  -r run: how many request to send\n"
                                        "  -s server: specify the server name or address, default: 127.0.0.1\n"
                                        "  -p port: specify the server port, default: 12345\n", 
                                        argv[0]);
                                exit(EXIT_FAILURE);
                }
        }

        srand(time(NULL));              // for generate_request()

        sfd = connect_server(server, port);
        
        handle_connect(sfd, run, random);

        close(sfd);
        exit(EXIT_SUCCESS);
}

