#ifndef HICNCTRL_OBJECT_PRIVATE_H
#define HICNCTRL_OBJECT_PRIVATE_H

#define INT_CMP(x, y) ((x > y) ? 1 : (x < y) ? -1 : 0)

// XXX Those are always true
#define IS_VALID_ADDRESS(x) (1)
#define IS_VALID_CONNECTION_ID(x) (1)  // XXX ID
#define IS_VALID_ROUTE_COST(x) (1)
#define IS_VALID_PREFIX_LEN(x) (1)
#define IS_VALID_POLICY(x) (1)
#define IS_VALID_ID(x) (1)
#define IS_VALID_INTERFACE_NAME(x) (1)
#define IS_VALID_NAME(x) (1)
#define IS_VALID_TYPE(x) IS_VALID_ENUM_TYPE(FACE_TYPE, x)
#define IS_VALID_FACE_STATE(x) (1)

#define IS_VALID_ADDR_TYPE(x) ((x >= ADDR_INET) && (x <= ADDR_UNIX))

#define IS_VALID_CONNECTION_TYPE(x) IS_VALID_ENUM_TYPE(CONNECTION_TYPE, x)

#define GENERATE_FIND(TYPE)                                           \
  int hc_##TYPE##_find(hc_data_t *data, const hc_##TYPE##_t *element, \
                       hc_##TYPE##_t **found) {                       \
    foreach_type(hc_##TYPE##_t, x, data) {                            \
      if (hc_##TYPE##_cmp(x, element) == 0) {                         \
        *found = x;                                                   \
        return 0;                                                     \
      }                                                               \
    };                                                                \
    *found = NULL; /* this is optional */                             \
    return 0;                                                         \
  }

#endif /* HICNCTRL_OBJECT_PRIVATE_H */
