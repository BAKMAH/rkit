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

#include "utils.h"


/*
    *    src/utils.c
    *    Date: 04/04/22
    *    Author: 0x80000000
*/


/**
 * @brief Checks if the given string only contains digits.
 * @param string The string.
 * @returns True if the string only contains digits, false if otherwise.
 */

bool check_digit(const uint8_t *string) {
  while (*string)
    if (!isdigit(*string++))
      return false;
  return true;
}

/**
 * @brief Outputs a log.
 * @param message The message that will be printed to the screen.
 */

void rkit_log(const uint8_t *message, ...) {
  va_list arguments;

  va_start(arguments, message);
  printf("[rkit]: ");

  vprintf(message, arguments); 
  va_end(arguments);
}