/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <hicn/platforms/windows/win_portability.h>
#include <hicn/util/sstrncpy.h>

int getline(char **lineptr, size_t *n, FILE *stream) {
  static char line[256];
  char *ptr;
  unsigned int len;
  int rc;

  if (lineptr == NULL || n == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (ferror(stream)) return -1;

  if (feof(stream)) return -1;

  fgets(line, 256, stream);

  ptr = strchr(line, '\n');
  if (ptr) *ptr = '\0';

  len = (unsigned int)strlen(line);

  if ((len + 1) < 256) {
    ptr = (char *)realloc(*lineptr, 256);
    if (ptr == NULL) return (-1);
    *lineptr = ptr;
    *n = 256;
  }

  rc = strcpy_s(*lineptr, 256, line);
  if (rc != EOK) return -1;

  return (len);
}