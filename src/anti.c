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
#include "utils.h"


/*
    *    src/anti.c
    *    Date: 04/04/22
    *    Author: 0x80000000
*/


const uint8_t *blacklisted_libraries[] = {
  "vlany",
  "inject",
  "rootkit"
};

const uint8_t *functions[] = {
  "write",
  "printf",
  "read",
  "fopen",
  "open",
  "readdir",
  "connect",
  "accept",
  "send",
  "recv",
  "puts",
  "execve"
};

/**
 * @brief Checks for the amount of processors.
 * @returns True if the amount is low, false if otherwise.
 */

bool vm_cpu(void) {
  struct sysinfo info;
  if (sysconf(_SC_NPROCESSORS_CONF) < 2)
    return true;
  return false;
}

/**
 * @brief Checks the uptime of the system.
 * @returns True if the uptime has been less than 600 seconds, false if otherwise.
 */

bool vm_uptime(void) {
  struct sysinfo info;
  sysinfo(&info);

  if (info.uptime < 600)
    return true;

  return false;
}

/**
 * @brief Checks for ptrace.
 * @returns True if ptrace was detected, false if otherwise.
 */

bool ptrace_detection(void) {
  uint8_t buffer[BUFSIZ] = {0};

#ifdef DEBUG
  rkit_log("Checking for ptrace...\n");
#endif

  FILE *file = fopen("/proc/self/status", "r");
  if (!file)
    return false;

  while (fgets(buffer, sizeof(buffer), file)) {
    if (strstr(buffer, "TracerPid:")) {
#ifdef DEBUG
  rkit_log("Ptrace detected!\n");
#endif
      return true;
    }
  }

  fclose(file);
  return true;
}

/**
 * @brief Attempts to check for hypervisors.
 * @returns True if a hypervisor was detected, false if otherwise.
 */

bool DetectHypervisors(void) {
  uint8_t buffer[BUFSIZ] = {0};

#ifdef DEBUG
  rkit_log("Checking for hypervisors...\n");
#endif

  FILE *file = fopen("/proc/cpuinfo", "r");
  if (!file)
    return false;

  /**
   * Reading the file line by line, and checking if the strings "flag:" and "hypervisor" are 
   * in the same line.
   */

  while (fgets(buffer, sizeof(buffer), stdin)) {
    if (strstr(buffer, "flag:") && strstr(buffer, "hypervisor")) {
#ifdef DEBUG
  rkit_log("Hypervisor detected!\n");
#endif
      return true;
    }
  }

  fclose(file);
  return false;
}

/**
 * @brief Iterates over the array of function names, gets the pointer to the symbol, and then checks the bytes.
 * @returns True if a hooked function was detected, false if otherwise.
 */

bool detect_jmp_hook(void) {
  bool ret = false;
  for (int32_t i = 0; i < (sizeof(functions) / sizeof(functions[0])); i++) {
    uint8_t *bytes = (uint8_t *)dlsym(RTLD_NEXT, functions[i]);
    if ((bytes[0] == 0xE9 || bytes[0] == 0xFF) && bytes[1] == 0x25) {
      ret = true;
#ifdef DEBUG
      rkit_log("%s(); has been hooked | JMP Opcode Detected!");
#endif
    }
  }
  return ret;
}

/**
 * @brief Iterates over the array of function names, gets the pointer to the symbol, and then checks the bytes.
 * @param library The library.
 * @returns -1 If LD_PRELOAD has not been set or if the file could not be accessed, 1 if the library was not found, 0 if otherwise.
 */

int32_t check_for_hidden_library(const uint8_t *library) {
  if (!library)
    return -1;

  FILE *mappings;
  uint8_t path[PATH_MAX] = {0}, buffer[BUFSIZ] = {0};

  snprintf(path, PATH_MAX, "/proc/%d/maps", getpid());

  if (!(mappings = fopen(path, "r")))
    return -1;

  while (fgets(buffer, sizeof(buffer), mappings))
    if (strstr(buffer, library))
      return 0;

  fclose(mappings);
  return 1;
}

/**
 * @brief Checks if the library is blacklisted or not.
 * @param library The target library.
 * @returns true if the library is blacklisted, false if it isn't.
 */

bool check_library_name(const uint8_t *library) {
  for (int32_t i = 0; i < (sizeof(blacklisted_libraries) / sizeof(blacklisted_libraries[0])); i++)
    if (strncmp(library, blacklisted_libraries[i], strlen(blacklisted_libraries[i])) == 0)
      return true;
  return false;
}

/**
 * @brief Attempts to display the current loaded shared-object files.
 * @returns False or true.
 */

bool check_dl_information(void) {
  int32_t index = 0;
  struct link_map *map;
  
  if (dlinfo(dlopen(NULL, RTLD_LAZY), 2, &map) == -1)
    return false;

  while (map) {
    if (strlen(map->l_name) > 0) {
#ifdef DEBUG
      printf("[%s] -------------> [%p]\n", map->l_name, (void *)map->l_addr);
#endif
      if (check_for_hidden_library(map->l_name) == 1) {
#ifdef DEBUG
      rkit_log("Library '%s' is hidden!\n", map->l_name);
#endif
      }
      
      if (check_library_name(map->l_name))
        return true;
      index++;
    }
    map = map->l_next;
  }

  putchar('\n');
  return false;
}

/**
 * @brief Attempts to detect function hooking via shared libraries.
 * @returns False if a handle could be opened, true if otherwise.
 */

bool dl_detect_function_hooking(void) {
  uint8_t *function;
  int32_t counter = 0, index = 0;

  Dl_info info_func, info_temp;
  void *temp, *handle, *original_function;

  if (!(handle = dlopen("libc.so.6", RTLD_LAZY)))
    return false;

  while ((function = functions[index++])) {
    original_function = dlsym(handle, function);
    temp = dlsym(RTLD_NEXT, function);

    if (original_function != temp) {
      dladdr(original_function, &info_func);
      dladdr(temp, &info_temp);

#ifdef DEBUG
      rkit_log("%s(); has been hooked!\n", function); 
#endif
      counter++;
    }
  }

  if (counter > 0)
    return true;

  return false;
}