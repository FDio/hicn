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
 * \file objects/face.h
 * \brief Face.
 *
 * A face is an abstraction introduced by the control library to abstract the
 * forwarder implementation details. It encompasses connections and listeners
 * and ensures the right dependencies are enforced, eg that we always have a
 * listener when a connection is created.
 */

#ifndef HICNCTRL_OBJECTS_FACE_H
#define HICNCTRL_OBJECTS_FACE_H

#include <hicn/face.h>

#include "base.h"

typedef face_t hc_face_t;

#define foreach_face(VAR, data) foreach_type(hc_face_t, VAR, data)

#define MAX_FACE_ID 255
#define MAXSZ_FACE_ID_ 3
#define MAXSZ_FACE_ID MAXSZ_FACE_ID_ + NULLTERM
#define MAXSZ_FACE_NAME_ SYMBOLIC_NAME_LEN
#define MAXSZ_FACE_NAME MAXSZ_FACE_NAME_ + NULLTERM

#define MAXSZ_HC_FACE_ \
  MAXSZ_FACE_ID_ + MAXSZ_FACE_NAME_ + MAXSZ_FACE_ + 5 + HOTFIXMARGIN
#define MAXSZ_HC_FACE MAXSZ_HC_FACE_ + NULLTERM

int hc_face_snprintf(char *s, size_t size, const hc_face_t *face);

#endif /* HICNCTRL_OBJECTS_FACE_H */
