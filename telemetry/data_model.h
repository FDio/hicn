/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
 */

#include "utils/common/common.h"

#define KAFKA_TOPIC_KEY "_TOPIC"
#define KAFKA_STREAM_TOPIC "stream"
#define KAFKA_METADATA_TOPIC "metadata"

/************** DATA SOURCES ******************************/
data_source_t packets_dsrc[1] = {
    {"packets", DS_TYPE_GAUGE, 0, NAN},
};

data_source_t interests_dsrc[1] = {
    {"interests", DS_TYPE_GAUGE, 0, NAN},
};

data_source_t data_dsrc[1] = {
    {"data", DS_TYPE_GAUGE, 0, NAN},
};

data_source_t combined_dsrc[2] = {
    {"packets", DS_TYPE_DERIVE, 0, NAN},
    {"bytes", DS_TYPE_DERIVE, 0, NAN},
};

/************** DATA SETS NODE ****************************/
data_set_t pkts_processed_ds = {
    "pkts_processed",
    STATIC_ARRAY_SIZE(packets_dsrc),
    packets_dsrc,
};

data_set_t pkts_interest_count_ds = {
    "pkts_interest_count",
    STATIC_ARRAY_SIZE(packets_dsrc),
    packets_dsrc,
};

data_set_t pkts_data_count_ds = {
    "pkts_data_count",
    STATIC_ARRAY_SIZE(packets_dsrc),
    packets_dsrc,
};

data_set_t pkts_from_cache_count_ds = {
    "pkts_from_cache_count",
    STATIC_ARRAY_SIZE(packets_dsrc),
    packets_dsrc,
};

data_set_t pkts_no_pit_count_ds = {
    "pkts_no_pit_count",
    STATIC_ARRAY_SIZE(packets_dsrc),
    packets_dsrc,
};

data_set_t pit_expired_count_ds = {
    "pit_expired_count",
    STATIC_ARRAY_SIZE(interests_dsrc),
    interests_dsrc,
};

data_set_t cs_expired_count_ds = {
    "cs_expired_count",
    STATIC_ARRAY_SIZE(data_dsrc),
    data_dsrc,
};

data_set_t cs_lru_count_ds = {
    "cs_lru_count",
    STATIC_ARRAY_SIZE(data_dsrc),
    data_dsrc,
};

data_set_t pkts_drop_no_buf_ds = {
    "pkts_drop_no_buf",
    STATIC_ARRAY_SIZE(packets_dsrc),
    packets_dsrc,
};

data_set_t interests_aggregated_ds = {
    "interests_aggregated",
    STATIC_ARRAY_SIZE(interests_dsrc),
    interests_dsrc,
};

data_set_t interests_retx_ds = {
    "interests_retx",
    STATIC_ARRAY_SIZE(interests_dsrc),
    interests_dsrc,
};

data_set_t interests_hash_collision_ds = {
    "interests_hash_collision",
    STATIC_ARRAY_SIZE(interests_dsrc),
    interests_dsrc,
};

data_set_t pit_entries_count_ds = {
    "pit_entries_count",
    STATIC_ARRAY_SIZE(interests_dsrc),
    interests_dsrc,
};

data_set_t cs_entries_count_ds = {
    "cs_entries_count",
    STATIC_ARRAY_SIZE(data_dsrc),
    data_dsrc,
};

data_set_t cs_entries_ntw_count_ds = {
    "cs_entries_ntw_count",
    STATIC_ARRAY_SIZE(data_dsrc),
    data_dsrc,
};

/************** DATA SETS FACE ****************************/
data_set_t irx_ds = {
    "irx",
    STATIC_ARRAY_SIZE(combined_dsrc),
    combined_dsrc,
};

data_set_t itx_ds = {
    "itx",
    STATIC_ARRAY_SIZE(combined_dsrc),
    combined_dsrc,
};

data_set_t drx_ds = {
    "drx",
    STATIC_ARRAY_SIZE(combined_dsrc),
    combined_dsrc,
};

data_set_t dtx_ds = {
    "dtx",
    STATIC_ARRAY_SIZE(combined_dsrc),
    combined_dsrc,
};
