#ifndef HICNLIGHT_CS_H
#define HICNLIGHT_CS_H

#include <hicn/util/pool.h>
#include "../content_store/lru.h"
#include "msgbuf_pool.h"

#define INVALID_ENTRY_ID ~0ul /* off_t */
#define DEFAULT_CS_SIZE 256   // Fixed CS size

typedef struct {
  off_t msgbuf_id;
  struct {
    off_t prev;
    off_t next;
  } lru;
} cs_entry_t;

#define cs_entry_get_msgbuf_id(entry) ((entry)->msgbuf_id)

typedef enum {
  CS_TYPE_UNDEFINED,
  CS_TYPE_LRU,
  CS_TYPE_N,
} cs_type_t;

#define CS_TYPE_VALID(type) (type != CS_TYPE_UNDEFINED) && (type != CS_TYPE_N)

typedef struct {
  /* The maximum allowed expiry time (will never be exceeded). */
  uint64_t max_expiry_time;  // XXX part of lru ?
} cs_options_t;

typedef struct {
  cs_type_t type;
  int num_entries;
  size_t max_size;
  cs_lru_state_t lru;
  union {
    cs_lru_stats_t lru;
  } stats;
} cs_t;

/**
 * @brief Create a new content store  (extended parameters).
 *
 * @param[in] type Content store type
 * @param[in] max_size Maximum size (0 = use default value)
 *
 * @return cs_t* - The newly created content store
 */
cs_t *_cs_create(cs_type_t type, size_t max_size);

/**
 * @brief Create a new content store
 *
 * @param[in] size Maximum content store size
 *
 * @return cs_t* - The newly created content store
 */
#define cs_create(size) _cs_create(CS_TYPE_LRU, (size))

/**
 * @brief Free a content store data structure.
 *
 * @param[in] pool_ptr Pointer to the content store to free
 */
void cs_free(cs_t *cs);

/**
 * @brief Clear the content of the content store (helper).
 *
 * @param[in, out] cs Pointer to the content store to clear
 */
void _cs_clear(cs_t **cs);

/**
 * @brief Clear the content of the content store.
 *
 * @param[in, out] cs Pointer to the content store to clear
 */
#define cs_clear(cs) _cs_clear((cs_t **)&cs);

/**
 * @brief Update content store statistics upon CS hit event.
 *
 * @param[in] cs Pointer to the content store to use
 */
void cs_hit(cs_t *cs);

/**
 * @brief Update content store statistics upon CS miss event.
 *
 * @param[in] cs Pointer to the content store to use
 */
void cs_miss(cs_t *cs);

/**
 * @brief Log content store statistics, e.g. the CS current and maximum size,
 * the number of matches, misses, add operations, update operations, evictions.
 *
 * @param cs Pointer to the CS data structure to use
 */
void cs_log(cs_t *cs);

#endif /* HICNLIGHT_CS_H */
