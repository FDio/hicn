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
 * \file face.h
 * \brief Face.
 */

#ifndef HICNCTRL_IMPL_OBJECTS_FACE_H
#define HICNCTRL_IMPL_OBJECTS_FACE_H

#include "../object_vft.h"

int hc_face_validate(const hc_face_t *face, bool allow_partial);

DECLARE_OBJECT_OPS_H(OBJECT_TYPE_FACE, face);

#endif /* HICNCTRL_IMPL_OBJECTS_FACE_H */
