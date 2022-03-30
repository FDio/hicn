# Data identifiers and locators

Hybrid ICN makes use of data identifiers to name the data produced by an end
host. Data identifiers are encoded using a routable name prefix and a non
routable name suffix to provide the ability to index a single IP packet in an
prefix is unambigous manner. A full data name is composed of 160 bits. A
routable name prefix in IPv4 network is 32 bits long while in IPv6 is 128 bits
long. A name prefix is a valid IPv4 or IPv6 address. The 32 rightmost bits are
used by the applications to index data within the same stream.

A data source that is using the hicn stack is reacheable through IP routing
where a producer socket is listening as the producer name prefix is IP routable.

Locators are IP interface identifiers and are IPv4 or IPv6 addresses. Data
consumers are reacheable through IP routing over their locators.

For requests, the name prefix is stored in the destination address field of the
IP header while the source address field stored the locator of the consumer.


# Producer/Consumer Architecture
Applications make use of the hicn network architecture by using a Prod/Cons API.
Each communication socket is connection-less as a data producer makes data
available to data consumer by pushing data into a named buffer. Consumers are
responsible for pulling data from data producers by sending requests indexing
the full data name which index a single MTU sized data packet. The core

# Packet forwarding
Packet forwarding leverages IP routing as requests are forwarded using name
prefixes and replies using locators.

# Relay nodes
A relay node is implemented by using a packet cache which is used to temporarily
store requests and replies. The relay node acts as a virtual proxy for the data
producers as it caches data packets which can be sent back to data consumer by
using the full name as an index. Requests must be cached and forwarded upstream
towards data producers which will be able reach back the relay nodes by using
the IP locators of the relays. Cached requests store all locators as currently
written in the source address field of the request while requests forwarded
upstream will get the source address rewritten with the relay node locator. Data
packets can reach the original consumers via the relay nodes by using the
requence of cached locators.
