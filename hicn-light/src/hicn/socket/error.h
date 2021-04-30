#ifndef HICN_SOCKET_ERROR_H
#define HICN_SOCKET_ERROR_H

#define foreach_hicn_socket_error                                             \
  _(NONE, 0, "OK")                                                            \
  _(UNSPEC, 1, "unspecified error")                                           \
  _(NOT_HICN, 2, "not a hICN paclet")                                         \
  _(UNKNOWN_ADDRESS, 10, "unknown address")                                   \
  _(INVALID_PARAMETER, 20, "invalid parameter")                               \
  _(INVALID_IP_ADDRESS, 21, "invalid IP address")                             \
  _(CORRUPTED_PACKET, 22, "corrupted packet")                                 \
  _(UNEXPECTED, 98, "unexpected error")                                       \
  _(NOT_IMPLEMENTED, 99, "not implemented")                                   \
  _(SOCKET_LOCAL_NULL_ADDRESS, 101, "empty local address")                    \
  _(SOCKET_LOCAL_REPR, 102, "cannot represent local address")                 \
  _(SOCKET_LOCAL_HEURISTIC, 103, "error finding local address")               \
  _(SOCKET_LOCAL_SET_TUN_IP, 104, "cannot set local IP to TUN")               \
  _(BIND_SOCKET_NOT_FOUND, 301, "bind: socket not found")                     \
  _(BIND_SOCKET_ALREADY_BOUND, 302, "bind: socket already bound")             \
  _(BIND_REMOTE_INTERFACE, 303, "bind: no interface towards gateway")         \
  _(BIND_REMOTE_NETMASK, 304, "bind: no local IP with netmask < 128")         \
  _(BIND_REMOTE_REPR, 305, "bind: error representing local IP")               \
  _(BIND_REMOTE_LOCAL_NULL_ADDR, 306, "bind: could not set local endpoint")   \
  _(BIND_REMOTE_LOCAL_REPR, 307, "bind: error representing remote IP")        \
  _(BIND_REMOTE_LOCAL_HEURISTIC, 308, "bind: could not apply heuristic")      \
  _(BIND_REMOTE_LOCAL_SET_TUN_IP, 309, "bind: error setting local IP to TUN") \
  _(BIND_NDP, 310, "bind: could not enable NDP proxy")                        \
  _(BIND_NEIGH_PROXY, 311, "bind: could not neighbour")                       \
  _(BIND_REPR, 312, "bind: error represeting IP")                             \
  _(BIND_LO, 313, "bind: could not remove local route")                       \
  _(BIND_RULE, 314, "bind: could not add rule")                               \
  _(BIND_ROUTE, 315, "bind: could not add output route")

typedef enum {
#define _(a, b, c) HICN_SOCKET_ERROR_##a = (-b),
  foreach_hicn_socket_error
#undef _
      HICN_SOCKET_N_ERROR,
} hicn_socket_error_t;

extern const char *HICN_SOCKET_ERROR_STRING[];

#define hicn_socket_strerror(errno) (char *)(HICN_SOCKET_ERROR_STRING[-errno])

#endif /* HICN_SOCKET_ERROR_H */
