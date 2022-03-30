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
 * \file interface.c
 * \brief Implementation of interface base class.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <hicn/facemgr/facelet.h>
#include <hicn/facemgr/loop.h> /* *_callback_data_t */
#include <hicn/util/map.h>

#include "interface.h"

TYPEDEF_MAP_H(interface_ops_map, const char *, const interface_ops_t *);
TYPEDEF_MAP(interface_ops_map, const char *, const interface_ops_t *, strcmp,
            string_snprintf, generic_snprintf);

static interface_ops_map_t *interface_ops_map = NULL;

int interface_register(const interface_ops_t *ops) {
  if (!interface_ops_map) {
    interface_ops_map = interface_ops_map_create();
    if (!interface_ops_map) return -1;
  }
  interface_ops_map_add(interface_ops_map, ops->type, ops);
  return 0;
}

int interface_unregister_all() {
  int ret = 0;
  const char **ops_name_array = NULL;
  int n = interface_ops_map_get_key_array(interface_ops_map, &ops_name_array);
  if (n < 0) {
    ERROR("[interface_unregister_all] Could not get interface ops array");
    return -1;
  }

  for (unsigned i = 0; i < n; i++) {
    const char *ops_name = ops_name_array[i];
    if (interface_ops_map_remove(interface_ops_map, ops_name, NULL) < 0) {
      ERROR(
          "[interface_unregister_all] Could not remove %s from interface ops "
          "map",
          ops_name);
      ret = -1;
    }
  }
  free(ops_name_array);

  interface_ops_map_free(interface_ops_map);
  interface_ops_map = NULL;

  return ret;
}

interface_t *interface_create(const char *name, const char *type) {
  const interface_ops_t *ops = NULL;
  int rc = interface_ops_map_get(interface_ops_map, type, &ops);
  if (rc < 0) {
    printf("Interface type not found %s\n", type);
    return NULL;
  }

  interface_t *interface = malloc(sizeof(interface_t));
  if (!interface) return NULL;

  interface->name = strdup(name);
  /* this should use type */
  interface->ops = ops;
  interface->callback = NULL;
  interface->callback_owner = NULL;
  interface->data = NULL;

  return interface;
}

void interface_free(interface_t *interface) {
  free(interface->name);
  free(interface);
}

void interface_set_callback(interface_t *interface, void *callback_owner,
                            interface_cb_t callback) {
  interface->callback = callback;
  interface->callback_owner = callback_owner;
}

int interface_initialize(interface_t *interface, void *cfg) {
  if (!interface->ops->initialize) return -1;
  return interface->ops->initialize(interface, cfg);
}

int interface_finalize(interface_t *interface) {
  if (!interface->ops->finalize) return -1;
  return interface->ops->finalize(interface);
}

int interface_on_event(interface_t *interface, facelet_t *facelet) {
  if (!interface->ops->on_event) return -1;
  return interface->ops->on_event(interface, facelet);
}

int interface_raise_event(interface_t *interface, facelet_t *facelet) {
  assert(interface->callback);
  return interface->callback(interface->callback_owner,
                             INTERFACE_CB_TYPE_RAISE_EVENT, facelet);
}

int interface_register_fd(interface_t *interface, int fd, void *data) {
  assert(interface->callback);
  fd_callback_data_t fd_callback = {
      .fd = fd,
      .owner = interface,
      .callback = (fd_callback_t)interface->ops->callback,
      .data = data,
  };
  return interface->callback(interface->callback_owner,
                             INTERFACE_CB_TYPE_REGISTER_FD, &fd_callback);
}

int interface_unregister_fd(interface_t *interface, int fd) {
  assert(interface->callback);
  fd_callback_data_t fd_callback = {
      .fd = fd,
      .owner = interface,
      .callback = NULL,
      .data = NULL,
  };
  return interface->callback(interface->callback_owner,
                             INTERFACE_CB_TYPE_UNREGISTER_FD, &fd_callback);
}

typedef int (*interface_fd_callback_t)(interface_t *interface, int fd,
                                       void *unused);

int interface_register_timer(interface_t *interface, unsigned delay_ms,
                             interface_fd_callback_t callback, void *data) {
  assert(interface->callback);
  timer_callback_data_t timer_callback = {
      .delay_ms = delay_ms,
      .owner = interface,
      .callback = (fd_callback_t)callback,
      .data = data,
  };
  int rc =
      interface->callback(interface->callback_owner,
                          INTERFACE_CB_TYPE_REGISTER_TIMER, &timer_callback);
  return rc;
}

int interface_unregister_timer(interface_t *interface, int fd) {
  assert(interface->callback);
  return interface->callback(interface->callback_owner,
                             INTERFACE_CB_TYPE_UNREGISTER_TIMER, &fd);
}
