/**
 * \file fib_policy.h
 * \brief FIB policy description to be stored in FIB entries.
 */
#ifndef HICN_FIB_POLICY_H
#define HICN_FIB_POLICY_H

#include "face.h"

typedef struct {
    face_tags_t allow;
    face_tags_t prohibit;
    face_tags_t prefer;
    face_tags_t avoid;
} fib_policy_t;

static const fib_policy_t FIB_POLICY_NONE = {
    .allow    = FACE_TAGS_EMPTY,
    .prohibit = FACE_TAGS_EMPTY,
    .prefer   = FACE_TAGS_EMPTY,
    .avoid    = FACE_TAGS_EMPTY,
};

#endif /* HICN_FIB_POLICY_H */
