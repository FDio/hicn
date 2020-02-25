# Face Manager

## Overview

The architecture of the face manager is built around the concept of interfaces,
which allows for a modular and extensible deployment.

Interfaces are used to implement in isolation various sources of information
which help with the construction of faces (such as network interface and service
discovery), and with handling the heterogeneity of host platforms.

### Platform and supported interfaces

Currently, Android, Linux and MacOS are supported through the following
interfaces:

- hicn-light [Linux, Android, MacOS, iOS]
    An interface to the hicn-light forwarder, and more specifically to the Face
    Table and FIB data structures. This component is responsible to effectively
    create, update and delete faces in the forwarder, based on the information
    provided by third party interfaces, plus adding default routes for each of
    the newly created face. The communication with the forwarder is based on the
    hicn control library (`libhicnctrl`).

- netlink [Linux, Android]
    The default interface on Linux systems (including Android) to communicate
    with the kernel and receive information from various sources, including link
    and address information (both IPv4 and IPv6) about network interfaces.

- android\_utility [Android only]
    Information available through Netlink is limited with respect to cellular
    interfaces. This component allows querying the Android layer through SDK
    functions to get the type of a given network interface (Wired, WiFi or
    Cellular).

- bonjour [Linux, Android]
    This component performs remote service discovery based on the bonjour
    protocol to discover a remote hICN forwarder that might be needed to
    establish overlay faces.

- network_framework [MacOS, iOS]

    This component uses the recommended Network framework on Apple devices,
    which provided all required information to query faces in a unified API:
    link and address information, interface types, and bonjour service
    discovery.

### Architectural overview

#### Facelets

TODO:

```text
- Key attributes (netdevice and protocol family)
- Facelet API
```

#### Events

TODO

#### Facelet cache & event scheduling

TODO:

```text
 - Facelet cache
 - Joins
 - How synchronization work
```

### Interface API

TODO

## Developing a new interface

### Dummy template

The face manager source code includes a template that can be used as a skeleton
to develop new faces. It can be found in `src/interface/dummy/dummy.{h,c}`. Both
include guard and specific interface functions are prefixed by a (short)
identifier which acts as a namespace for interface specific code (in our case
the string 'dummy_').

Registration and instantiation of the different interfaces is currently done at
compile time in the file `src/api.c`, and the appropriate hooks to use the dummy
interface are available in the code between `#if 0/#endif` tags.

#### Interface template header; configuration parameters

All interfaces have a standard interface defined in `src/interface.{h,c}`, and
as such the header file is only used to specify the configuration parameters of
the interface, if any.

In the template, these configuration options are empty:

```C
/*
 * Configuration data
 */
typedef struct {
    /* ... */
} dummy_cfg_t;
```

#### Overview of the interface template

The file starts with useful includes:

```text
- the global include `<hicn/facemgr.h>` : this provides public facing elements
    of the face manager, such the standard definition of faces (`face_t` from
    `libhicnctrl`), helper classes (such as `ip_address_t` from `libhicn`), etc.
- common.h
- facelet.h : facelets are the basic unit of communication between the face
manager and the different interfaces. They are used to construct the faces
incrementally.
- interface.h : the parent class of interfaces, such as the current dummy
interface.
```

Each interface can hold a pointer to an internal data structure, which is
declared as follows:

```C
/*
 * Internal data
 */
typedef struct {
    /* The configuration data will likely be allocated on the stack (or should
     * be freed) by the caller, we recommend to make a copy of this data.
     * This copy can further be altered with default values.
     */
    dummy_cfg_t cfg;

    /* ... */

    int fd; /* Sample internal data: file descriptor */
} dummy_data_t;
```

We find here a copy of the configuration settings (which allows the called to
instantiate the structure on the stack), as well as a file descriptor
(assuming most interfaces will react on events on a file descriptor).

The rest of the file consists in the implementation of the interface, in
particular the different function required by the registration of a new
interface to the system. They are grouped as part of the `interface_ops_t` data
structure declared at the end of the file:

```C
interface_ops_t dummy_ops = {
    .type = "dummy",
    .initialize = dummy_initialize,
    .finalize = dummy_finalize,
    .callback = dummy_callback,
    .on_event = dummy_on_event,
};
```

The structure itself is declared and documented in `src/interface.h`

```C
/**
 * \brief Interface operations
 */
typedef struct {
    /** The type given to the interfaces */
    char * type;
    /* Constructor */
    int (*initialize)(struct interface_s * interface, void * cfg);
    /* Destructor */
    int (*finalize)(struct interface_s * interface);
    /* Callback upon file descriptor event (iif previously registered) */
    int (*callback)(struct interface_s * interface);
    /* Callback upon facelet events coming from the face manager */
    int (*on_event)(struct interface_s * interface, const struct facelet_s * facelet);
} interface_ops_t;
```

Such an interface has to be registered first, then one (or multiple) instance(s)
can be created (see `src/interface.c` for the function prototypes, and
`src/api.c` for their usage).

- interface registration:

```text
extern interface\_ops\_t dummy\_ops;

/* [...] */

rc = interface\_register(&dummy\_ops);
if (rc < 0)
    goto ERR_REGISTER;
```

- interface instantiation:

```C
#include "interfaces/dummy/dummy.h"

/* [...] */

rc = facemgr_create_interface(facemgr, "dummy0", "dummy", &facemgr->dummy);
if (rc < 0) {
    ERROR("Error creating 'Dummy' interface\n");
    goto ERR_DUMMY_CREATE;
}
```

#### Implementation of the Interface API

We now quickly go other the different functions, but their usage will be better
understood through the hands-on example treated in the following section.

In the template, the constructor is the most involved as it need to:

- initialize the internal data structure:

```C
    dummy_data_t * data = malloc(sizeof(dummy_data_t));
    if (!data)
        goto ERR_MALLOC;
    interface->data = data;
```

- process configuration parameters, eventually setting some default values:

```C
    /* Use default values for unspecified configuration parameters */
    if (cfg) {
        data->cfg = *(dummy_cfg_t *)cfg;
    } else {
        memset(&data->cfg, 0, sizeof(data->cfg));
    }
```

- open an eventually required file descriptor

For the sake of simplicity, the current API only supports a single file
descriptor per-interface, and it has to be created in the constructor, and
set as the return value so as to be registered by the system, and added to the
event loop for read events. A return value of 0 means the interface does not
require any file descriptor. As usual, a negative return value indicates an
error.

```C
    data->fd = 0;

    /* ... */

    /*
     * We should return a negative value in case of error, and a positive value
     * otherwise:
     *  - a file descriptor (>0) will be added to the event loop; or
     *  - 0 if we don't use any file descriptor
     */
    return data->fd;
```

While support for multiple file descriptors might be added in the future, an
alternative short-term implementation might consider the instanciation of
multiple interface, as is done for Bonjour in the current codebase, in
`src/api.c`.

Data reception on the file descriptor will get the callback function called, in
our case `dummy_callback`. Finally, the destructor `dummy_finalize` should close
an eventual open file descriptor.

In order to retrieve the internal data structure, that should in particular
store such a file descriptor, all other function but the constructor can
dereference it from the interface pointer they receive as parameter:

```C
dummy_data_t * data = (dummy_data_t*)interface->data;
```

#### Raising and Receiving Events

An interface will receive events in the form of a facelet through the `*_on_event`
function. It can then use the facelet API we have described above to read
information about the face.

As this information is declared const, the interface can either create a new
facelet (identified by the same netdevice and protocol family), or eventually
clone it.

The facelet event can then be defined and raised to the face manager for further
processing through the following code:

```C
    facelet_set_event(facelet, EVENT_TYPE_CREATE);
    interface_raise_event(interface, facelet);
```

Here the event is a facelet creation (`EVENT_TYPE_CREATE`). The full facelet API
and the list of possible event types is available in `src/facelet.h`

#### Integration in the Build System

The build system is based on CMake. Each interface should declare its source
files, private and public header files, as well as link dependencies in the
local `CMakeLists.txt` file.

TODO: detail the structure of the file

### Hands-On

#### Architecture

In order to better illustrate the development of a new interface, we will
consider the integration of a sample server providing a signal instructing the
face manager to alternatively use either the WiFi or the LTE interface. The code
of this server is available in the folder `examples/updownsrv/`, and the
corresponding client code in `examples/updowncli`.

Communication between client and server is done through unix sockets over an
abstract namespace (thereby not using the file system, which would cause issues
on Android). The server listens for client connections, and periodically
broadcast a binary information to all connected clients, in the form of one byte
equal to either \0 (which we might interpret as enable LTE, disable WiFi), or \1
(enable WiFi, disable LTE).

Our objective is to develop a new face manager interface that would listen to
such event in order to update the administrative status of the current faces.
This would thus alternatively set the different interfaces administratively up
and down (which takes precedence over the actual status of the interface when
the forwarder establishes the set of available next hops for a given prefix).
The actual realization of such queries will be ultimately performed by the
hicn-light interface.

#### Sample Server and Client

In the folder containing the source code of hICN, the following commands allow
to run the sample server:

```bash
cd ctrl/facemgr/examples/updownsrv
make
./updownsrv
```

The server should display "Waiting for clients..."

Similar commands allow to run the sample client:

```bash
cd ctrl/facemgr/examples/updowncli
make
./updowncli
```

The client should display "Waiting for server data...", then every couple of
seconds display either "WiFi" or "LTE".

#### Face Manager Interface

An example illustrating how to connect to the dummy service from `updownsrv` is
provided as the `updown` interface in the facemgr source code.

This interface periodically swaps the status of the LTE interface up and down.
It is instantiated as part of the facemgr codebase when the code is compiled
with the ``-DWITH_EXAMPLE_UPDOWN` cmake option.
