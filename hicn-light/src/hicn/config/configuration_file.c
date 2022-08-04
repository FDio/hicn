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

#ifndef _WIN32
#include <unistd.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <hicn/ctrl/hicn-light.h>
#include <hicn/config/configuration_file.h>
#include <hicn/util/sstrncpy.h>

#include "commands.h"
#include <hicn/ctrl/parse.h>

#define BUFFERLEN 2048

static char *_trim(char *str) {
  char *end;

  // Trim leading space
  while (isspace((unsigned char)*str)) str++;

  if (*str == 0)  // All spaces?
    return str;

  // Trim trailing space
  end = str + strnlen_s(str, BUFFERLEN) - 1;
  while (end > str && isspace((unsigned char)*end)) end--;

  // Write new null terminator character
  end[1] = '\0';

  return str;
}

bool configuration_file_process(forwarder_t *forwarder, const char *filename) {
  assert(forwarder);
  assert(filename);

  int linesRead = 0;
  FILE *f = fopen(filename, "r");
  if (!f) {
    ERROR("Could not open configuration file %s: (%d) %s", filename, errno,
          strerror(errno));
    goto ERR_OPEN;
  }
  DEBUG("Opening configuration file %s", filename);

  char buffer[BUFFERLEN];
  bool success = true;

#if 0
  // TODO(eloparco): We could use a fake socket since we only need the vft
  hc_sock_t *s = hc_sock_create(FORWARDER_TYPE_HICNLIGHT, NULL);
  if (!s) {
    ERROR("Could not create socket");
    goto ERR_SOCK;
  }
#else
  hc_sock_initialize_module(NULL);
#endif

  while (success && fgets(buffer, BUFFERLEN, f) != NULL) {
    linesRead++;

    char *cmd = _trim(buffer);
    if (strnlen_s(cmd, BUFFERLEN) <= 0) continue;
    if (cmd[0] == '#') continue;

    INFO("Processing command: %s", cmd);
    hc_command_t command = {};
    if (parse(cmd, &command) < 0) {
      ERROR("Error parsing command : '%s'", cmd);
      continue;
    }

    /* Serialize request into message */
    // hc_msg_t msg;
    uint8_t msg[1024];
    ssize_t msg_len = hc_light_command_serialize(
        command.action, command.object_type, &command.object, msg);
    switch (msg_len) {
      case -1:
      case -2:
        ERROR("Command '%s' not supported", cmd);
        continue;
      case -3:
        ERROR("Error during command serialization '%s'", cmd);
        continue;
      default:
        break;
    }

    size_t _unused;
    command_process(forwarder, (uint8_t *)msg, CONNECTION_ID_UNDEFINED,
                    &_unused);
  }

#if 0
  hc_sock_free(s);
#endif

  if (ferror(f)) {
    ERROR("Error on input file %s line %d: (%d) %s", filename, linesRead, errno,
          strerror(errno));
    goto ERR_READ;
  }
  fclose(f);
  return true;

#if 0
ERR_SOCK:
  hc_sock_free(s);
#endif
ERR_READ:
  fclose(f);
ERR_OPEN:
  return false;
}
