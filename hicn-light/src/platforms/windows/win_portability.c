#pragma once

#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#include <assert.h>
#include <errno.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>

int getline(char **lineptr, size_t *n, FILE *stream) {
  static char line[256];
  char *ptr;
  unsigned int len;

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

  strcpy(*lineptr, line);
  return (len);
}