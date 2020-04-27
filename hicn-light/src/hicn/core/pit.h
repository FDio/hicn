#ifndef HICNLIGHT_PIT_H
#define HICNLIGHT_PIT_H


#include <hicn/base/khash.h>
#include <hicn/core/nexthops.h>
#include <hicn/core/msgbuf.h>
#include <hicn/core/fib.h>
#include <hicn/core/name.h>
#include <hicn/core/ticks.h>

typedef struct  {
  msgbuf_t * msgbuf;
  nexthops_t ingressIdSet;
  nexthops_t egressIdSet;

  fib_entry_t * fib_entry;

  Ticks creation_time;
  Ticks expiry_time;
} pit_entry_t;

typedef enum {
    PIT_VERDICT_FORWARD,
    PIT_VERDICT_AGGREGATE,
    PIT_VERDICT_RETRANSMIT,
} pit_verdict_t;

#define pit_entry_get_ingress(E) (&((E)->ingressIdSet))
#define pit_entry_get_egress(E) (&((E)->egressIdSet))
#define pit_entry_get_fib_entry(E) ((E)->fib_entry)
#define pit_entry_set_fib_entry(E, FIB_ENTRY) ((E)->fib_entry = FIB_ENTRY)
#define pit_entry_get_creation_time(E) ((E)->creation_time)
#define pit_entry_get_expiry_time(E) ((E)->expiry_time)
#define pit_entry_set_expiry_time(E, EXPIRY_TIME) \
    (entry)->expiry_time = EXPIRY_TIME

#define pit_entry_ingress_add(E, NH) \
    nexthops_add(pit_entry_get_ingress(E), (NH))

#define pit_entry_ingress_contains(E, NH) \
    nexthops_contains(pit_entry_get_ingress(E), (NH))

#define pit_entry_egress_add(E, NH) \
    nexthops_add(pit_entry_get_egress(E), (NH))

#define pit_entry_from_msgbuf(E, MSGBUF, EXPIRY_TIME, CREATION_TIME)        \
do {                                                                        \
    E->msgbuf = MSGBUF;                                                     \
    pit_entry_ingress_add(E, msgbuf_get_connection_id(MSGBUF));             \
    E->fib_entry = NULL;                                                    \
    E->creation_time = CREATION_TIME;                                       \
    E->expiry_time = EXPIRY_TIME;                                           \
} while(0)

#define name_hash(name) (name_HashCode(name))
#define name_hash_eq(a, b) (name_hash(b) - name_hash(a))

KHASH_INIT(pit_name, const Name *, unsigned, 0, name_hash, name_hash_eq);

typedef struct {
    pit_entry_t * entries; // pool
    kh_pit_name_t * index_by_name;
} pit_t;

pit_t * pit_create(size_t max_elts);

void pit_free(pit_t * pit);

#define _pit_var(x) _pit_ ## x

#define pit_allocate(pit, entry, msgbuf)                                        \
do {                                                                            \
    pool_get(pit->entries, entry);                                              \
    unsigned _pit_var(id) = entry - pit->entries;                               \
    int _pit_var(res);                                                          \
    khiter_t _pit_var(k) = kh_put(pit_name, pit->index_by_name,                 \
            msgbuf_get_name(msgbuf), &_pit_var(res));                           \
    kh_value(pit->index_by_name, _pit_var(k)) = _pit_var(id);                   \
} while(0)

#define pit_at(pit, i) (pit->entries + i)

pit_verdict_t pit_on_interest(pit_t * pit, msgbuf_t * msgbuf);

nexthops_t * pit_on_data(pit_t * pit, const msgbuf_t * msgbuf);

void pit_remove(pit_t * pit, const msgbuf_t * msgbuf);

pit_entry_t * pit_lookup(const pit_t * pit, const msgbuf_t * msgbuf);

#endif /* HICNLIGHT_PIT_H */
