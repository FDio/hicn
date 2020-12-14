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
 * \file priority_controller.c
 * \brief Implementation of Priority Controller interface
 */

#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <hicn/facemgr.h>

#include "priority_controller.h"
#include "../../common.h"
#include "../../interface.h"

#define PC_DEFAULT_PORT 9533

typedef struct {
    priority_controller_cfg_t cfg;
    int fd;
#ifdef PRIORITY_CONTROLLER_INTERNAL
    unsigned state;
    JNIEnv * env;
    jclass cls;
    jmethodID mid;
#endif /* PRIORITY_CONTROLLER_INTERNAL */
} pc_data_t;

#ifdef PRIORITY_CONTROLLER_INTERNAL
#include <jni.h>

#define ERR_STR_JAVA "Java VM parameters are required in the interface configuration."

#define PREFER_CELLULAR 0
#define PREFER_WIFI 1
#define PREFER_BOTH 2

#define INTERVAL_MS 500

const char * prefer_str[] = { "Cellular", "WiFi", "both" };

jclass find_class_global(JNIEnv* env, const char *name){
    jclass c = (*env)->FindClass(env, name);
    jclass c_global = 0;
    if (c){
        c_global = (jclass)(*env)->NewGlobalRef(env, c);
        (*env)->DeleteLocalRef(env, c);
    }
    return c_global;
}


int priority_controller_tick(interface_t * interface, int fd, void * unused)
{
    pc_data_t * data = (pc_data_t*)interface->data;
    unsigned new_state = PREFER_BOTH;

    jint rssi = (*data->env)->CallStaticIntMethod(data->env, data->cls, data->mid);
    DEBUG("[priority_controller_tick] rssi=%d\n", rssi);
    if (rssi > -67) {
        new_state = PREFER_WIFI;

#if 0
    } else if ((rssi < -67) && (rssi > -70)) {
        new_state = PREFER_BOTH;
#endif

    } else { /* rssi < -70 */
        new_state = PREFER_CELLULAR;
    }

    if (new_state == data->state)
        return 0;

    ERROR("[priority_controller_tick] Setting priority to %s", prefer_str[new_state]);

    /* XXX Factor this */

    facelet_t * facelet_w = facelet_create();
    facelet_t * facelet_c = facelet_create();
    facelet_set_netdevice_type(facelet_w, NETDEVICE_TYPE_WIFI);
    facelet_set_netdevice_type(facelet_c, NETDEVICE_TYPE_CELLULAR);
    facelet_set_attr_clean(facelet_w);
    facelet_set_attr_clean(facelet_c);

    switch(new_state) {
        case PREFER_CELLULAR:
            facelet_set_priority(facelet_w, 0);
            facelet_set_priority(facelet_c, 10);
            break;
        case PREFER_WIFI:
            facelet_set_priority(facelet_w, 10);
            facelet_set_priority(facelet_c, 0);
            break;
        case PREFER_BOTH:
            facelet_set_priority(facelet_w, 0);
            facelet_set_priority(facelet_c, 0);
            break;
    }

    facelet_set_event(facelet_w, FACELET_EVENT_UPDATE);
    facelet_set_event(facelet_c, FACELET_EVENT_UPDATE);

    interface_raise_event(interface, facelet_w);
    interface_raise_event(interface, facelet_c);

    data->state = new_state;

    return 0;
}
#endif /* PRIORITY_CONTROLLER_INTERNAL */

int priority_controller_initialize(interface_t * interface, void * cfg)
{
    INFO("Initializing priority controller");

    pc_data_t * data = malloc(sizeof(pc_data_t));
    if (!data) {
        INFO("Priority controller data memory allocation error");
        goto ERR_MALLOC;
    }

    interface->data = data;

    data->cfg = * (priority_controller_cfg_t *) cfg;

#ifdef PRIORITY_CONTROLLER_INTERNAL

    if (!cfg) {
        ERROR(ERR_STR_JAVA);
        goto ERR_CFG;
    }

    /* Retrieve RSSI information from SDK through AndroidUtility class */
    (*data->cfg.jvm)->AttachCurrentThread(data->cfg.jvm, &data->env, NULL);
    data->cls = find_class_global(data->env, FACEMGR_ANDROID_UTILITY_CLASS);
    if (data->cls == 0)
        goto ERR_JAVA;
    data->mid = (*data->env)->GetStaticMethodID(data->env, data->cls, "getWifiRSSI", "()I");

    data->fd = interface_register_timer(interface, INTERVAL_MS,
            priority_controller_tick, interface);
    if (data->fd < 0) {
        ERROR("[priority_controller_initialize] Could not initialize timer");
        goto ERR_FD;
    }
    data->state = PREFER_BOTH;

#else /* PRIORITY_CONTROLLER_INTERNAL */
    struct sockaddr_in addr;

    data->fd = socket(AF_INET, SOCK_DGRAM, 0);
    //data->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (data->fd < 0) {
        INFO("Priority controller socket error");
        perror("socket error");
        goto ERR_SOCKET;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(PC_DEFAULT_PORT);

    if (bind(data->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        INFO("Priority controller socket bind error");
        perror("bind error");
        goto ERR_BIND;
    }

    DEBUG("[priority_controller_initialize] register fd");
    if (interface_register_fd(interface, data->fd, NULL) < 0) {
        ERROR("[priority_controller_initialize] Error registering fd");
        goto ERR_FD;
    }

#endif /* PRIORITY_CONTROLLER_INTERNAL */

    INFO("Priority controller successfully initialized");
    return 0;

#ifdef PRIORITY_CONTROLLER_INTERNAL
ERR_CFG:
ERR_JAVA:
#endif /* PRIORITY_CONTROLLER_INTERNAL */
ERR_FD:
#ifndef PRIORITY_CONTROLLER_INTERNAL
ERR_BIND:
    close(data->fd);
ERR_SOCKET:
#endif /* ! PRIORITY_CONTROLLER_INTERNAL */
    free(data);
ERR_MALLOC:
    return -1;
}

int priority_controller_finalize(interface_t * interface)
{
    pc_data_t * data = (pc_data_t*)interface->data;

#ifdef PRIORITY_CONTROLLER_INTERNAL
    DEBUG("[priority_controller_finalize] unregister timer");
    interface_unregister_timer(interface, data->fd);
#else
    if (data->fd > 0) {
        interface_unregister_fd(interface, data->fd);
        close(data->fd);
    }
    free(data);
#endif /* PRIORITY_CONTROLLER_INTERNAL */

    return 0;
}

#ifndef PRIORITY_CONTROLLER_INTERNAL
int priority_controller_callback(interface_t * interface, int fd, void * unused)
{
    pc_data_t * data = (pc_data_t*)interface->data;
    char buf[100];
    int rc;

    INFO("Priority controller receiving command");

    rc = recv(data->fd, buf, 100, 0);

    if (rc < 0) {
        INFO("Priority controller read error");
        return -1;
    }

    INFO("Priority controller received command: %02X", buf[0]);

    facelet_t * facelet_w = facelet_create();
    facelet_t * facelet_c = facelet_create();
    facelet_set_netdevice_type(facelet_w, NETDEVICE_TYPE_WIFI);
    facelet_set_netdevice_type(facelet_c, NETDEVICE_TYPE_CELLULAR);
    facelet_set_attr_clean(facelet_w);
    facelet_set_attr_clean(facelet_c);
    switch(buf[0]) {
        case '\0':
            facelet_set_priority(facelet_w, 0);
            facelet_set_priority(facelet_c, 10);
            INFO("Priority controller configuring Cellular preferred");
            break;
        case '\1':
            facelet_set_priority(facelet_w, 10);
            facelet_set_priority(facelet_c, 0);
            INFO("Priority controller configuring Wi-Fi preferred");
            break;
        case '\2':
            facelet_set_priority(facelet_w, 0);
            facelet_set_priority(facelet_c, 0);
            INFO("Priority controller configuring both Cellular and Wi-Fi preferred");
            break;
        default:
            INFO("Priority controller invalid data received from updown server. Ignoring...");
            facelet_free(facelet_w);
            facelet_free(facelet_c);
            return 0;
    }

    facelet_set_event(facelet_w, FACELET_EVENT_UPDATE);
    facelet_set_event(facelet_c, FACELET_EVENT_UPDATE);

    interface_raise_event(interface, facelet_w);
    interface_raise_event(interface, facelet_c);

    return 0;
}
#endif /* ! PRIORITY_CONTROLLER_INTERNAL */

interface_ops_t priority_controller_ops = {
    .type = "priority_controller",
    .initialize = priority_controller_initialize,
    .finalize = priority_controller_finalize,
#ifndef PRIORITY_CONTROLLER_INTERNAL
    .callback = priority_controller_callback,
#endif /* ! PRIORITY_CONTROLLER_INTERNAL */
};
