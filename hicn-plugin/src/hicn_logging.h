/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#ifndef __HICN_DEBUG_H__
#define __HICN_DEBUG_H__

#ifdef HICN_DDEBUG
#define HICN_DEBUG(...)                                                       \
  do                                                                          \
    {                                                                         \
      clib_warning (__VA_ARGS__);                                             \
    }                                                                         \
  while (0)
#else
#define HICN_DEBUG(...)
#endif /* HICN_DEBUG */

#define HICN_ERROR(...) clib_error_return (0, __VA_ARGS__)

#endif /* __HICN_DEBUG_H__ */