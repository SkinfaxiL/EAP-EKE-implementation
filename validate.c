#include "validate.h"

#include <openssl/err.h>

#include <arpa/inet.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

int validate(int result, int use_errno, const char* format, ...)
{
    if (result < 0)
    {
        va_list args;
        va_start(args, format);
        vfprintf(stderr, format, args);
        if (use_errno == 1) {
            fprintf(stderr, ": %s\n", strerror(errno));
        } else if (use_errno == 2) {
            ERR_print_errors_fp(stderr);
        } else {
            fprintf(stderr, "\n");
        }
        fprintf(stderr, "\n");
        va_end(args);
        exit(1);
    }
    return result;
}

void validate_cond(int condition, int use_errno, const char* format, ...)
{
    if (!condition)
    {
        va_list args;
        va_start(args, format);
        vfprintf(stderr, format, args);
        if (use_errno == 1) {
            fprintf(stderr, ": %s\n", strerror(errno));
        } else if (use_errno == 2) {
            ERR_print_errors_fp(stderr);
        } else {
            fprintf(stderr, "\n");
        }
        va_end(args);
        exit(1);
    }
}

int validate_port(int port, int exit_on_error)
{
    if (port > USHRT_MAX || port < 1) {
        fprintf(stderr, "[ERROR] Port number [%d] is not in range [%d, %d]\n", port, 1, USHRT_MAX);
        if (exit_on_error) {
			exit(1);
        }
        return -1;
    }
    return port;
}

struct sockaddr_in validate_sockaddr(in_addr_t address, int port)
{
    validate_cond(address != (in_addr_t)(-1), 0, "Invalid IP Provided");
    validate_port(port, 1);

    struct sockaddr_in sdin;
    memset(&sdin, 0, sizeof(sdin));
    sdin.sin_family = AF_INET;
    sdin.sin_port = htons(port);
    sdin.sin_addr.s_addr = address;

    return sdin;
}

