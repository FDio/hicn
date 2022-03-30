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
 * \file loop_dispatcher.c
 * \brief Implementation of facemgr main loop using Apple Dispatcher framework
 */

#ifndef __APPLE__
#error "This implementation only supports Apple platforms"
#endif /* __APPLE__ */

#ifdef WITH_THREAD
#error "Multithreaded implementation is not (yet) supported on Apple platforms"
#endif /* WITH_THREAD */

#include <stdlib.h>

#include <Dispatch/Dispatch.h>

#include <hicn/facemgr/loop.h>
#include <hicn/util/log.h>

struct loop_s {};

loop_t* loop_create() {
  loop_t* loop = malloc(sizeof(loop_t));
  if (!loop) {
    ERROR("[loop_create] Failed to allocate memory");
    goto ERR_MALLOC;
  }
  return loop;

ERR_MALLOC:
  return NULL;
}

void loop_free(loop_t* loop) { /* Nothing to do */
}

int loop_dispatch(loop_t* loop) {
  dispatch_main();
  return 0;
}

int loop_undispatch(loop_t* loop) {
  /* Nothing to do */
  return 0;
}

void loop_break(loop_t* loop) { exit(0); }

int loop_callback(loop_t* loop, facemgr_cb_type_t type, void* data) {
  INFO("loop_callback not (yet) implemented");
  return 0;
}
