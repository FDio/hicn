/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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
 * @file message_packet_type_h
 * @brief Defines the packet type for a HICN message
 *
 */

#ifndef message_packet_type_h
#define message_packet_type_h

typedef enum message_type {
    MESSAGE_TYPE_UNDEFINED,
    MESSAGE_TYPE_INTEREST,
    MESSAGE_TYPE_DATA,
    MESSAGE_TYPE_WLDR_NOTIFICATION,
    MESSAGE_TYPE_MAPME,
    MESSAGE_TYPE_COMMAND,
    MESSAGE_TYPE_N,
} MessagePacketType;

#endif  // message_packet_type_h
