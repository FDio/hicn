#ifndef HICNLIGHT_CS_H
#define HICNLIGHT_CS_H

#include "msgbuf.h"
#include "msgbuf_pool.h"
#include "name.h"
#include "../base/khash.h"
#include "../base/pool.h"
#include "../content_store/lru.h"

#define INVALID_ENTRY_ID ~0ul /* off_t */

typedef struct {
    off_t msgbuf_id;
    //ListLruEntry *lruEntry;
    bool hasExpiryTimeTicks;
    uint64_t expiryTimeTicks; // single value for both ? 0 allowed ?
    union {
        off_t prev;
        off_t next;
    } lru;
} cs_entry_t;

#define cs_entry_get_msgbuf_id(entry) ((entry)->msgbuf_id)
#define cs_entry_has_expiry_time(entry) ((entry)->hasExpiryTimeTicks)
#define cs_entry_get_expiry_time(entry) ((entry)->expiryTimeTicks)

typedef enum {
    CS_TYPE_UNDEFINED,
    CS_TYPE_LRU,
    CS_TYPE_N,
} cs_type_t;

#define CS_TYPE_VALID(type)          \
    (type != CS_TYPE_UNDEFINED) &&   \
    (type != CS_TYPE_N)

typedef struct {
    /* The maximum allowed expiry time (will never be exceeded). */
    uint64_t max_expiry_time; // XXX part of lru ?
} cs_options_t;

// XXX TODO
#define name_hash(name) (name_HashCode(name))
#define name_hash_eq(a, b) (name_hash(b) == name_hash(a))

KHASH_INIT(cs_name, const Name *, unsigned, 1, name_hash, name_hash_eq);

typedef struct {
    cs_type_t type;

    // XXX TODO api to dynamically set max size
    cs_entry_t * entries; // pool

    kh_cs_name_t * index_by_name;

#if 0
    void * index_by_expiry_time;
#endif

    void * data; // per cs type data
    void * options;

    union {
        cs_lru_stats_t lru;
    } stats;


    union {
        cs_lru_state_t lru;
    };
} cs_t;

/**
 * @brief Create a new content store (extended parameters)
 *
 * @param[in] type Content store type
 * @param[in] init_size Initially allocated size (hint, 0 = use default value)
 * @param[in] max_size Maximum size (0 = unlimited)
 *
 * @return cs_t* - The newly created content store
 */
cs_t * _cs_create(cs_type_t type, size_t init_size, size_t max_size);

/**
 * @brief Create a new content store
 *
 * @param[in] type Content store type
 *
 * @return cs_t* - The newly created content store
 */
#define cs_create(TYPE) _cs_create((TYPE), 0, 0)

void cs_free(cs_t * cs);

void cs_clear(cs_t * cs);

off_t cs_match(cs_t * cs, msgbuf_pool_t * msgbuf_pool, off_t msgbuf_id, uint64_t now);

cs_entry_t * cs_add(cs_t * cs, msgbuf_pool_t * msgbuf_pool, off_t msgbuf_id, uint64_t now);

int cs_remove_entry(cs_t * cs, msgbuf_pool_t * msgbuf_pool, cs_entry_t * entry);

bool cs_remove(cs_t * cs, msgbuf_pool_t * msgbuf_pool, msgbuf_t * msgbuf);

#define cs_size(content_store) (pool_len(cs->entries))

void cs_purge_entry(cs_t * cs, cs_entry_t * entry);

#define cs_get_entry_id(cs, entry) (entry - cs->entries)

#define cs_entry_at(cs, id) (&(cs)->entries[id])

typedef struct {

    const char * name;

    void (*initialize)(cs_t * cs);

    void (*finalize)(cs_t * cs);

    /**
     * Place a Message representing a ContentObject into the ContentStore. If
     * necessary to make room, remove expired content or content that has exceeded
     * the Recommended Cache Time.
     *
     * @param storeImpl - a pointer to this ContentStoreInterface instance.
     * @param content - a pointer to a `Message` to place in the store.
     * @param currentTimeTicks - the current time, in hicn-light ticks, since the
     * UTC epoch.
     */
    // XXX Do we always get now before adding ?
    int (*add_entry)(cs_t * cs, off_t entry_id);

    /**
     * The function to call to remove content from the ContentStore.
     * It will Release any references that were created when the content was
     * placed into the ContentStore.
     *
     * @param storeImpl - a pointer to this ContentStoreInterface instance.
     * @param content - a pointer to a `Message` to remove from the store.
     */
    int (*remove_entry)(cs_t * cs, cs_entry_t * entry);

} cs_ops_t;

extern const cs_ops_t * const cs_vft[];

#define DECLARE_CS(NAME)                                 \
    const cs_ops_t cs_ ## NAME = {            \
        .name = #NAME,                                              \
        .initialize = cs_ ## NAME ## _initialize,        \
        .finalize = cs_ ## NAME ## _finalize,            \
        .add_entry = cs_ ## NAME ## _add_entry,          \
        .remove_entry = cs_ ## NAME ## _remove_entry,    \
    }

#endif /* HICNLIGHT_CS_H */
