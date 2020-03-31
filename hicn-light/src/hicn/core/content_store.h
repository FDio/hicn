#ifndef HICNLIGHT_CONTENT_STORE_H
#define HICNLIGHT_CONTENT_STORE_H

#include <hicn/base/khash.h>
#include <hicn/base/pool.h>
#include <hicn/core/msgbuf.h>
#include <hicn/core/name.h>
#include <hicn/content_store/lru.h>

typedef struct {
    msgbuf_t * message;
    //ListLruEntry *lruEntry;
    bool hasExpiryTimeTicks;
    uint64_t expiryTimeTicks; // single value for both ? 0 allowed ?
} content_store_entry_t;

#define content_store_entry_message(entry) ((entry)->message)
#define content_store_entry_has_expiry_time(entry) ((entry)->hasExpiryTimeTicks)
#define content_store_entry_expiry_time(entry) ((entry)->expiryTimeTicks)

typedef enum {
    CONTENT_STORE_TYPE_UNDEFINED,
    CONTENT_STORE_TYPE_LRU,
    CONTENT_STORE_TYPE_N,
} content_store_type_t;

#define CONTENT_STORE_TYPE_VALID(type)          \
    (type != CONTENT_STORE_TYPE_UNDEFINED) &&   \
    (type != CONTENT_STORE_TYPE_N)

typedef struct {
    /* The maximum allowed expiry time (will never be exceeded). */
    uint64_t max_expiry_time; // XXX part of lru ?
} content_store_options_t;

typedef union {
    content_store_lru_stats_t lru;
} content_store_stats_t;

// XXX TODO
#define name_hash(name) (name_HashCode(name))
#define name_hash_eq(a, b) (name_hash(b) - name_hash(a))

KHASH_INIT(cs_name, const Name *, unsigned, 0, name_hash, name_hash_eq);

typedef struct {
    content_store_type_t type;

    // XXX TODO api to dynamically set max size
    content_store_entry_t * entries; // pool

    kh_cs_name_t * index_by_name;

    void * index_by_expiry_time;
    //ListTimeOrdered *indexByExpirationTime;


    void * data; // per cs type data
    void * options;
    content_store_stats_t stats;
} content_store_t;

content_store_t * content_store_create(content_store_type_t type, size_t max_elts);

void content_store_free(content_store_t * cs);

void content_store_clear(content_store_t * cs);

msgbuf_t * content_store_match(content_store_t * cs, msgbuf_t * msgbuf, uint64_t now);

void content_store_add(content_store_t * cs, msgbuf_t * msgbuf, uint64_t now);

void content_store_remove_entry(content_store_t * cs, content_store_entry_t * entry);

bool content_store_remove(content_store_t * cs, msgbuf_t * msgbuf);

#define content_store_size(content_store) (pool_elts(cs->entries))

void content_store_purge_entry(content_store_t * cs, content_store_entry_t * entry);

typedef struct {

    const char * name;

    void (*initialize)(content_store_t * cs);

    void (*finalize)(content_store_t * cs);

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
    bool (*add_entry)(content_store_t * cs, content_store_entry_t * entry);

    /**
     * The function to call to remove content from the ContentStore.
     * It will Release any references that were created when the content was
     * placed into the ContentStore.
     *
     * @param storeImpl - a pointer to this ContentStoreInterface instance.
     * @param content - a pointer to a `Message` to remove from the store.
     */
    void (*remove_entry)(content_store_t * cs, content_store_entry_t * entry);

} content_store_ops_t;

extern const content_store_ops_t * const content_store_vft[];

#define DECLARE_CONTENT_STORE(NAME)                                 \
    const content_store_ops_t content_store_ ## NAME = {            \
        .name = #NAME,                                              \
        .initialize = content_store_ ## NAME ## _initialize,        \
        .finalize = content_store_ ## NAME ## _finalize,            \
        .add_entry = content_store_ ## NAME ## _add_entry,          \
        .remove_entry = content_store_ ## NAME ## _remove_entry,    \
    }

#endif /* HICNLIGHT_CONTENT_STORE_H */
