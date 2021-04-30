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
 * \file updown.c
 * \brief Implementation of Example updown interface
 */

#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <hicn/facemgr.h>

#include "../../common.h"
#include "../../interface.h"

/**
 * \brief Default unix socket path (the leading \0 means using the abstract
 * namespace instead of the filesystem).
 */
#define UNIX_PATH "\0updownsrv"

typedef struct {
    int fd; /* Unix client socket */
} updown_data_t;

int updown_initialize(interface_t * interface, void * cfg)
{
    struct sockaddr_un addr;
    char * socket_path = UNIX_PATH;

    updown_data_t * data = malloc(sizeof(updown_data_t));
    if (!data)
        goto ERR_MALLOC;
    interface->data = data;

    data->fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (data->fd == -1) {
        perror("socket error");
        goto ERR_SOCKET;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (*socket_path == '\0') {
        *addr.sun_path = '\0';
        strncpy(addr.sun_path+1, socket_path+1, sizeof(addr.sun_path)-2);
    } else {
        strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
    }

    if (connect(data->fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("connect error");
        goto ERR_CONNECT;
    }

    if (interface_register_fd(interface, data->fd, NULL) < 0) {
        ERROR("[updown_initialize] Error registering fd");
        goto ERR_FD;
    }

    return 0;

ERR_FD:
ERR_CONNECT:
    close(data->fd);
ERR_SOCKET:
    free(data);
ERR_MALLOC:
    return -1;
}

int updown_finalize(interface_t * interface)
{
    updown_data_t * data = (updown_data_t*)interface->data;

    if (data->fd > 0)
        close(data->fd);
    free(data);

    return 0;
}

int updown_callback(interface_t * interface, int fd, void * unused)
{
    updown_data_t * data = (updown_data_t*)interface->data;
    char buf[100];
    int rc;

    rc = read(data->fd, buf, sizeof(buf));
    if (rc < 0)
        return -1;

    /*
     * If the process is paused (eg. in a debugger, we might have more than one
     * read.
     * XXX how big is the buffer
     * XXX shall we drain the queue if it exceeds buffer size ?
     */
    //assert(rc == 1);

    /* Raise facelet update event */
    facelet_t * facelet = facelet_create();
    facelet_set_netdevice_type(facelet, NETDEVICE_TYPE_WIFI); //CELLULAR);
    facelet_set_attr_clean(facelet);
    switch(buf[0]) {
        case '\0':
            facelet_set_admin_state(facelet, FACE_STATE_DOWN);
            break;
        case '\1':
            facelet_set_admin_state(facelet, FACE_STATE_UP);
            break;
            break;
        default:
            ERROR("Invalid data received from updown server. Ignoring...");
            facelet_free(facelet);
            return -1;
    }

    facelet_set_event(facelet, FACELET_EVENT_UPDATE);

    interface_raise_event(interface, facelet);

    return 0;
}

interface_ops_t updown_ops = {
    .type = "updown",
    .initialize = updown_initialize,
    .finalize = updown_finalize,
    .callback = updown_callback,
};
