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

#ifndef TRANSPORT_INTERFACES_C_API_ERRORS
#define TRANSPORT_INTERFACES_C_API_ERRORS

#ifdef __cplusplus
extern "C" {
#endif

#define foreach_c_api_error                                            \
  _(NONE, 0, "Ok")                                                     \
  _(UNSPECIFIED, -128, "Unspecified Error")                            \
  _(UNEXPECTED_DOMAIN, -129, "Specified socket domain not supported.") \
  _(UNEXPECTED_SOCKET_TYPE, -130, "Socket type not supported")         \
  _(UNEXPECTED_PROTOCOL, -131, "Protocol not supported")               \
  _(NOT_IMPLEMENTED, -132, "Feature not implemented")                 \
  _(SOCKET_NOT_FOUND, -133, "Socket not found")

typedef enum {
#define _(a, b, c) C_API_ERROR_##a = (b),
  foreach_c_api_error
#undef _
      C_API_ERROR,
} c_api_error_t;

extern const char *C_API_ERROR_STRING[];

#define get_c_api_error_string(errno)                 \
  (char *)(errno ? C_API_ERROR_STRING[(-errno) - 127] \
                 : C_API_ERROR_STRING[errno])

#ifdef __cplusplus
}  // extern "C"
#endif

#endif