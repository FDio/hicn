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
 * \file dummy.c
 * \brief Implementation of Dummy interface
 */

#include <stdlib.h>
#include <unistd.h> // close

#include <hicn/facemgr.h>

#include "../../common.h"
#include "../../interface.h"

#include "dummy.h"

#define DEFAULT_PORT 9695

#define UNUSED(x) ((void)x)

/*
 * Internal data
 */
typedef struct {
    /* The configuration data will likely be allocated on the stack (or should
     * be freed) by the caller, we recommend to make a copy of this data.
     * This copy can further be altered with default values.
     */
    dummy_cfg_t cfg;

    /* ... */

    int fd; /* Sample internal data: file descriptor */
} dummy_data_t;

int dummy_initialize(interface_t * interface, void * cfg)
{
    dummy_data_t * data = malloc(sizeof(dummy_data_t));
    if (!data)
        goto ERR_MALLOC;
    interface->data = data;

    /* Use default values for unspecified configuration parameters */
    if (cfg) {
        data->cfg = *(dummy_cfg_t *)cfg;
    } else {
        memset(&data->cfg, 0, sizeof(data->cfg));
    }

    /* ... */

    data->fd = 0;
#if 0
    if (interface_register_fd(interface, data->fd, NULL) < 0) {
        ERROR("[dummy_initialize] Error registering fd");
        goto ERR_FD;
    }
#endif

    /* ... */

    /*
     * We should return a negative value in case of error, and a positive value
     * otherwise:
     *  - a file descriptor (>0) will be added to the event loop; or
     *  - 0 if we don't use any file descriptor
     */
    return 0;

ERR_FD:
ERR_MALLOC:
    return -1;
}

int dummy_finalize(interface_t * interface)
{
    dummy_data_t * data = (dummy_data_t*)interface->data;

    if (data->fd > 0)
        close(data->fd);

    return 0;
}

int dummy_callback(interface_t * interface)
{
    dummy_data_t * data = (dummy_data_t*)interface->data;
    UNUSED(data);

    /* ... */

    return 0;
}

int dummy_on_event(interface_t * interface, facelet_t * facelet)
{
    dummy_data_t * data = (dummy_data_t*)interface->data;
    UNUSED(data);

    /* ... */

    return 0;
}

interface_ops_t dummy_ops = {
    .type = "dummy",
    .initialize = dummy_initialize,
    .finalize = dummy_finalize,
    .callback = dummy_callback,
    .on_event = dummy_on_event,
};
