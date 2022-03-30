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
 * @file listener_vft.c
 * @brief Implementation of listener VFT
 */

#include "listener_vft.h"

#ifdef __linux__
extern listener_ops_t listener_hicn;
#endif
extern listener_ops_t listener_tcp;
extern listener_ops_t listener_udp;

const listener_ops_t* listener_vft[] = {
#ifdef __linux__
    [FACE_PROTOCOL_HICN] = &listener_hicn,
#endif

    [FACE_PROTOCOL_TCP] = &listener_tcp,
    [FACE_PROTOCOL_UDP] = &listener_udp,
};
