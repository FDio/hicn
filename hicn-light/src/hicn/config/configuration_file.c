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
#include <hicn/config/configuration_file.h>
#include <hicn/util/sstrncpy.h>

#include "commands.h"
#include "parse.h"

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
  // TODO(eloparco): We could use a fake socket since we only need the vft
  hc_sock_t *s = hc_sock_create_forwarder(HICNLIGHT_NG);
  if (!s) {
    ERROR("Could not create socket");
    goto ERR_SOCK;
  }

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

    // TODO(eloparco): Handle all commands
    hc_result_t *result = NULL;
    if (command.action == ACTION_CREATE) {
      if (command.object.type == OBJECT_LISTENER) {
        result = hc_listener_create_conf(s, &command.object.listener);
      } else if (command.object.type == OBJECT_CONNECTION) {
        result = hc_connection_create_conf(s, &command.object.connection);
      } else if (command.object.type == OBJECT_ROUTE) {
        result = hc_route_create_conf(s, &command.object.route);
      } else if (command.object.type == OBJECT_LOCAL_PREFIX) {
        result = hc_strategy_add_local_prefix_conf(s, &command.object.strategy);
      }
    } else if (command.action == ACTION_SET) {
      if (command.object.type == OBJECT_STRATEGY) {
        result = hc_strategy_set_conf(s, &command.object.strategy);
      }
    }
    if (result == NULL) {
      ERROR("Command '%s' not supported", cmd);
      continue;
    }

    size_t _unused;
    hc_msg_t *msg = hc_result_get_msg(s, result);
    command_type_t cmd_id = hc_result_get_cmd_id(s, result);
    bool success = hc_result_get_success(s, result);
    if (success == false) {
      ERROR("Error serializing command : '%s'", cmd);
      continue;
    }

    command_process(forwarder, (uint8_t *)msg, cmd_id, CONNECTION_ID_UNDEFINED,
                    &_unused);
    hc_result_free(result);
  }
  hc_sock_free(s);

  if (ferror(f)) {
    ERROR("Error on input file %s line %d: (%d) %s", filename, linesRead, errno,
          strerror(errno));
    goto ERR_READ;
  }
  fclose(f);
  return true;

ERR_SOCK:
  hc_sock_free(s);
ERR_READ:
  fclose(f);
ERR_OPEN:
  return false;
}
