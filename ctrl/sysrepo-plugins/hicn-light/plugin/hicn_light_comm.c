/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#include "hicn_light_comm.h"

hc_sock_t * hsocket;

int hicn_connect_light() {

    hsocket = hc_sock_create();
    if (!hsocket)
      HICN_LOG_ERR_MSG("Error creating socket\n");
    if (hc_sock_connect(hsocket) < 0)
      HICN_LOG_ERR_MSG("Error connecting to the forwarder\n");
    return 0;

}

int hicn_disconnect_light() {
     hc_sock_free(hsocket);
  return 0;
}