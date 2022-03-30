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

/**
 * \file examples/update_priority.c
 * \brief libhicnctrl sample code : face priority update
 */

#include <stdlib.h>
#include <stdio.h>

#include <hicn/ctrl.h>
#include <hicn/util/log.h>

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s FACE_ID PRIORITY\n", argv[0]);
    exit(EXIT_FAILURE);
  }
  unsigned face_id = atoi(argv[1]);
  unsigned priority = atoi(argv[2]);
  char face_id_s[SYMBOLIC_NAME_LEN];

  hc_sock_t *socket = hc_sock_create();
  if (!socket) {
    DEBUG("Error creating libhicnctrl socket");
    goto ERR_SOCK;
  }

  if (hc_sock_connect(socket) < 0) {
    DEBUG("Error connecting to forwarder");
    goto ERR;
  }

  snprintf(face_id_s, SYMBOLIC_NAME_LEN, "%d", face_id);
  if (hc_face_set_priority(socket, face_id_s, priority) < 0) {
    DEBUG("Error setting face priority");
    goto ERR;
  }

  DEBUG("Face priority updated successfully");

ERR:
  hc_sock_free(socket);
ERR_SOCK:
  return 0;
}
