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
 * @file connection_vft.c
 * @brief Implementation of connection VFT
 */

#include "connection_vft.h"

#ifdef __linux
extern connection_ops_t connection_hicn;
#endif

extern connection_ops_t connection_tcp;
extern connection_ops_t connection_udp;

const connection_ops_t *connection_vft[] = {
#ifdef __linux
    [FACE_PROTOCOL_HICN] = &connection_hicn,
#endif

    [FACE_PROTOCOL_TCP] = &connection_tcp,
    [FACE_PROTOCOL_UDP] = &connection_udp,
};
