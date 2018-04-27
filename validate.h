#ifndef VALIDATE_H__
#define VALIDATE_H__

#include <netinet/in.h>

int validate(int result, int use_errno, const char* format, ...);
void validate_cond(int condition, int use_errno, const char* format, ...);
int validate_port(int port, int exit_on_error);
struct sockaddr_in validate_sockaddr(in_addr_t address, int port);

#endif

