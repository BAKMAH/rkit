/*
 * Copyright (C) 2022 0x80000000
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef HOOKS_H
#define HOOKS_H

#include <ctype.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>


/*
    *    src/hooks.h
    *    Date: 04/04/22
    *    Author: 0x80000000
*/


/* Struct that will contain the parsed information from /proc/<pid>/net/tcp! */
typedef struct _tcp {
  int32_t sl;
  int32_t rem_port;
  int32_t local_port;
  int32_t rem_address;
  int32_t local_address;
} tcp_t;

bool check_blacklisted_files(const uint8_t *string);
bool check_blacklisted_strings(const uint8_t *string);
bool check_suspicious_ports(tcp_t *network_information);
bool check_blacklisted_ip_addresses(const uint8_t *string);

bool lookup_socket_inode(const uint8_t *inode);
tcp_t *parse_tcp_data(const uint8_t *string, tcp_t *network_information);

struct dirent *readdir(DIR *dirp);
int open(const char *pathname, int flags);
char *fgets(char *s, int size, FILE *stream);
ssize_t read(int fd, void *buf, size_t count);
FILE *fopen(const char *pathname, const char *mode);
FILE *fopen64(const char *pathname, const char *mode);
int openat(int dirfd, const char *pathname, int flags);
ssize_t write(int filedes, const void *buf, size_t nbytes);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

#endif