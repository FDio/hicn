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

#ifndef FACEMGR_ERROR_H
#define FACEMGR_ERROR_H

#define foreach_facemgr_error                           \
_(NONE,         0,      "OK")                           \


typedef enum {
#define _(a,b,c) FACEMGR_ERROR_##a = (-b),
    foreach_facemgr_error
#undef _
    FACEMGR_ERROR_N,
} facemgr_error_t;

extern const char *HICN_LIB_ERROR_STRING[];

#define hicn_strerror(errno) (char *)(HICN_LIB_ERROR_STRING[-errno])

#endif /* FACEMGR_ERROR_H */
