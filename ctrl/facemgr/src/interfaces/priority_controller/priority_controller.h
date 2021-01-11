/*
 * Copyright (c) 2017-2020 Cisco and/or its affiliates.
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
 * \file priority_controller.h
 * \brief Priority Controller interface
 */

#ifndef FACEMGR_INTERFACE_PRIORITY_CONTROLLER
#define FACEMGR_INTERFACE_PRIORITY_CONTROLLER

#define FACEMGR_ANDROID_UTILITY_CLASS "com/cisco/hicn/forwarder/supportlibrary/AndroidUtility"

/*
 * Uncomment this line to use a Priority controller interface internal to the
 * face manager (only available in Android).
 */
// #define PRIORITY_CONTROLLER_INTERNAL

#ifdef __ANDROID__
#include <jni.h>
#endif /* __ANDROID__ */

typedef struct {
#ifdef __ANDROID__
#ifdef PRIORITY_CONTROLLER_INTERNAL
    JavaVM * jvm;
#endif /* PRIORITY_CONTROLLER_INTERNAL */
#endif /* __ANDROID__ */
} priority_controller_cfg_t;


#endif /* FACEMGR_INTERFACE_PRIORITY_CONTROLLER */
