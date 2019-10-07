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
 * \file android_utility/android_utility.h
 * \brief Android utility.
 *
 * This class relies on a small utility wrapper shipped with the Android
 * application to access to Java SDK APIs for information not available to
 * native code.
 *
 * For instance, we currently don't have on Linux any mean to get the type
 * associated to an interface, especially for cellular interfaces. WiFi and
 * Bluetooth information is for instance available through specific netlink
 * subsystems, or by means of a support library, but cellular detection mostly
 * relies on heuristics based on interface names (eg. in network manager).
 *
 * Android ship a Radio Interface Layer (RIL) daemon that exposes a control
 * socket to the Java API to control the radio layer, but there is no working
 * code exploiting it and no proper documentation.
 */

#ifndef FACEMGR_INTERFACE_ANDROID_UTILITY_H
#define FACEMGR_INTERFACE_ANDROID_UTILITY_H

#ifdef __ANDROID__

#include <jni.h>

typedef struct {
    JavaVM *jvm;
} android_utility_cfg_t;

#endif /* __ANDROID__ */

#endif /* FACEMGR_INTERFACE_ANDROID_UTILITY_H */
