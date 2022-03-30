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
 * \file android/android.h
 * \brief Android utility.
 */

#ifndef FACEMGR_INTERFACE_ANDROID_H
#define FACEMGR_INTERFACE_ANDROID_H

#ifdef __ANDROID__

#include <jni.h>
#include "../../interface.h"

typedef struct {
  JavaVM *jvm;
} android_cfg_t;

int android_on_network_event(interface_t *interface, const char *interface_name,
                             netdevice_type_t netdevice_type, bool up,
                             int family, const char *ip_address);

#endif /* __ANDROID__ */

#endif /* FACEMGR_INTERFACE_ANDROID_H */
