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

#ifndef ANTI_H
#define ANTI_H

#include <link.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>


/*
    *    src/anti.h
    *    Date: 04/04/22
    *    Author: 0x80000000
*/


bool vm_cpu(void);
bool vm_uptime(void);
bool detect_jmp_hook(void);
bool ptrace_detection(void);
bool DetectHypervisors(void);
bool check_dl_information(void);
bool dl_detect_function_hooking(void);
bool check_library_name(const uint8_t *library);
int32_t check_for_hidden_library(const uint8_t *library);

#endif