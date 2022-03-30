/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#if defined(__aarch64__) && defined(__ARM_NEON) || defined(__i686__)
#define TRANSPORT_HAVE_VEC128
#endif

#if defined(__SSE4_2__) && __GNUC__ >= 4
#define TRANSPORT_HAVE_VEC128
#endif

#if defined(__ALTIVEC__)
#define TRANSPORT_HAVE_VEC128
#endif

#if defined(__AVX2__)
#define TRANSPORT_HAVE_VEC256
#if defined(__clang__) && __clang_major__ < 4
#undef TRANSPORT_HAVE_VEC256
#endif
#endif

#if defined(__AVX512BITALG__)
#define TRANSPORT_HAVE_VEC512
#endif
