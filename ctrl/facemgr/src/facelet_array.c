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

/**
 * \file facelet_array.c
 * \brief Implementation of facelet array
 */

#include <hicn/facemgr/facelet.h>
#include <hicn/util/array.h>
#include "facelet_array.h"

TYPEDEF_ARRAY(facelet_array, facelet_t *, facelet_equals, facelet_snprintf);
