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
 * \file interfaces/bonjour/bonjour.h
 * \brief Bonjour interface
 *
 * NOTES:
 *  - shall we support multiple service names, or instanciate multiple instances
 *  of the interface ?
 *  - interface list ?
 *  - ideally we should register here events that will trigger bonjour
 *  queries...
 */

#include <hicn/face.h> /* netdevice_t */

typedef struct {
    netdevice_t netdevice;
    char * service_name;
    char * service_protocol;
    char * service_domain;
} bonjour_cfg_t;
