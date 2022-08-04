/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
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
 * @file error.h
 * @brief Error management functions.
 */
#ifndef HICN_ERROR_H
#define HICN_ERROR_H

/******************************************************************************
 * Error definitions
 ******************************************************************************/

#define foreach_libhicn_error                                                 \
  _ (NONE, 0, "OK")                                                           \
  _ (UNSPECIFIED, 128, "Unspecified Error")                                   \
  _ (NOT_IMPLEMENTED, 180, "Function not yet implemented")                    \
  _ (NOT_HICN, 202, "Non hICN packet")                                        \
  _ (UNKNOWN_ADDRESS, 210, "Unknown address")                                 \
  _ (INVALID_PARAMETER, 220, "Invalid parameter")                             \
  _ (INVALID_IP_ADDRESS, 221, "Invalid IP address")                           \
  _ (CORRUPTED_PACKET, 222, "Corrupted packet ")                              \
  _ (REWRITE_CKSUM_REQUIRED, 223,                                             \
     "Incremental csum calculation error: cksum required.")                   \
  _ (UNEXPECTED, 298, "Unexpected error")

typedef enum
{
#define _(a, b, c) HICN_LIB_ERROR_##a = (-b),
  foreach_libhicn_error
#undef _
    HICN_LIB_N_ERROR,
} hicn_lib_error_t;

extern const char *HICN_LIB_ERROR_STRING[];

#define HICN_LIB_IS_ERROR(rc) (rc < 0)

#define hicn_strerror(errno) (char *) (HICN_LIB_ERROR_STRING[-errno])

#endif /* HICN_ERROR_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
