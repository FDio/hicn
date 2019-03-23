#ifndef UTIL_TYPES
#define UTIL_TYPES

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* Helper for avoiding warnings about type-punning */
#define UNION_CAST(x, destType) \
   (((union {__typeof__(x) a; destType b;})x).b)

typedef unsigned int hash_t;

typedef int (*cmp_t)(const void *, const void *);

/* Enums */

#define IS_VALID_ENUM_TYPE(NAME, x) ((x > NAME ## _UNDEFINED) && (x < NAME ## _N))

#endif /* UTIL_TYPES */
