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
 * \file event.h
 * \brief Implementatino of face events
 */

#include "common.h"
#include "event.h"
#include "interface.h"
#include "util/token.h"

const char * event_type_str[] = {
#define _(x) [EVENT_TYPE_ ## x] = STRINGIZE(x),
foreach_event_type
#undef _
};

int
event_raise(event_type_t type, const face_t * face, const interface_t * interface)
{
    event_t event = { .type = type, .face = face };
    if (interface->callback)
        interface->callback(interface->callback_data, &event);
    return FACEMGR_SUCCESS;
}
