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

#ifndef FACE_RULES_H
#define FACE_RULES_H

#include "util/map.h"
#include "util/policy.h"

/*
 * Face creation rules
 *
 * For now, face creations rules are very simple and consist in a map between
 * the physical interface name, and the associated list of tags that will
 * preempt those assigned by the system.
 */
TYPEDEF_MAP_H(face_rules, const char *, policy_tags_t);

#endif /* FACE_RULES_H */
