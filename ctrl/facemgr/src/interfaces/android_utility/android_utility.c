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
 * \file interfaces/android_utility/android_utility.c
 * \brief Implementation of Android utility.
 */

#include <assert.h>

#include <hicn/facemgr.h>
#include <hicn/ctrl/face.h>
#include <hicn/util/log.h>
#include "../../common.h"
#include "../../interface.h"

#include "android_utility.h"

#define FACEMGR_ANDROID_UTILITY_CLASS "com/cisco/hicn/forwarder/supportlibrary/AndroidUtility"


#define AU_INTERFACE_TYPE_UNDEFINED 0
#define AU_INTERFACE_TYPE_WIRED     1
#define AU_INTERFACE_TYPE_WIFI      2
#define AU_INTERFACE_TYPE_CELLULAR  3
#define AU_INTERFACE_TYPE_LOOPBACK  4
#define AU_INTERFACE_TYPE_UNAVAILABLE 5

#define ERR_STR_JAVA "Java VM parameters are required in the interface configuration."

typedef struct {
    android_utility_cfg_t cfg;
} au_data_t;

int au_initialize(interface_t * interface, void * cfg)
{
    au_data_t * data = malloc(sizeof(au_data_t));
    if (!data)
        return -1;
    interface->data = data;

    if (!cfg)
        goto ERR_CFG;

    data->cfg = * (android_utility_cfg_t *) cfg;

    if (!data->cfg.jvm)
        goto ERR_CFG;

    return 0;

ERR_CFG:
        fprintf(stderr, ERR_STR_JAVA);
        return -1;
}

int au_finalize(interface_t * interface)
{
    /* Nothing to do */
    return 0;
}

int au_on_event(interface_t * interface, facelet_t * facelet)
{
    /*
     * This function is responsible to annotate every face we receive with the
     * correct interface type, based on the value returned by the Android
     * utility shipped with the Android forwarder.
     */
    au_data_t * data = (au_data_t*)interface->data;

    netdevice_t netdevice = NETDEVICE_EMPTY;
    int rc = facelet_get_netdevice(facelet, &netdevice);
    if (rc < 0)
        return -1;

    JNIEnv *env;
    JavaVM *jvm = data->cfg.jvm;
    (*jvm)->AttachCurrentThread(jvm, &env, NULL);
    jclass cls = (*env)->FindClass(env, FACEMGR_ANDROID_UTILITY_CLASS);
    jmethodID getNetworkType = (*env)->GetStaticMethodID(env, cls,
            "getNetworkType", "(Ljava/lang/String;)I");
    jint interface_type = (*env)->CallStaticIntMethod(env, cls, getNetworkType,
            (*env)->NewStringUTF(env, netdevice.name));

    netdevice_type_t netdevice_type = AU_INTERFACE_TYPE_UNDEFINED;
    switch(interface_type) {
        case AU_INTERFACE_TYPE_UNDEFINED:
            break;
        case AU_INTERFACE_TYPE_WIRED:
            netdevice_type = NETDEVICE_TYPE_WIRED;
            break;
        case AU_INTERFACE_TYPE_WIFI:
            netdevice_type = NETDEVICE_TYPE_WIFI;
            break;
        case AU_INTERFACE_TYPE_CELLULAR:
            netdevice_type = NETDEVICE_TYPE_CELLULAR;
            break;
        case AU_INTERFACE_TYPE_LOOPBACK:
            netdevice_type = NETDEVICE_TYPE_LOOPBACK;
            break;
        default:
            DEBUG("AU RETURNED ERROR");
            return -1;
    }

    DEBUG("AU RETURNED %s : %s", netdevice.name, netdevice_type_str[netdevice_type]);

    facelet_t * facelet_new = facelet_create();
    facelet_set_netdevice(facelet_new, netdevice);
    facelet_set_attr_clean(facelet_new);
    facelet_set_netdevice_type(facelet_new, netdevice_type);

    facelet_set_event(facelet_new, FACELET_EVENT_UPDATE);
    interface_raise_event(interface, facelet_new);

    return 0;
}

const interface_ops_t android_utility_ops = {
    .type = "android_utility",
    .initialize = au_initialize,
    .finalize = au_finalize,
    .callback = NULL,
    .on_event = au_on_event,
};
