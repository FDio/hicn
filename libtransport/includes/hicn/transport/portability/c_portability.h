/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Copyright 2017 Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

// noinline
#ifdef _MSC_VER
#define TRANSPORT_NOINLINE __declspec(noinline)
#elif defined(__clang__) || defined(__GNUC__)
#define TRANSPORT_NOINLINE __attribute__((__noinline__))
#else
#define TRANSPORT_NOINLINE
#endif

// always inline
#ifdef _MSC_VER
#define TRANSPORT_ALWAYS_INLINE __forceinline
#elif defined(__clang__) || defined(__GNUC__)
#define TRANSPORT_ALWAYS_INLINE inline __attribute__((__always_inline__))
#else
#define TRANSPORT_ALWAYS_INLINE inline
#endif

// Unused
#ifdef UNUSED
#elif defined(__GNUC__) || defined(__clang__)
#define UNUSED(x) (void)x
#else
#define UNUSED(x) x
#endif
