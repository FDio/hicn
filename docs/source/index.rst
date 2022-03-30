Hybrid Information-Centric Networking
=====================================

Hybrid Information-Centric Networking (hICN) is a network architecture that
makes use of IPv6 or IPv4 to implement location-independent communications. It
is largely inspired by the pioneer work of Van Jacobson on Content-Centric
Networking (RFC 8569, RFC 8609) that is a clean-slate architecture. hICN is
based on the Internet protocol and easyier to deploy in today networks and
applications. hICN brings many-to-many communications, multi-homing, multi-path,
multi-source, group communications to the Internet protocol. The current code
implements also transport protocols, with a socket API, for real-time and
capacity seeking applications. A scalable stack is available based on VPP and a
client stack is provided to support  mobile and desktop operating systems.

A detailed description of the architecture is described in the paper

Giovanna Carofiglio, Luca Muscariello, Jordan Augé, Michele Papalini, Mauro
Sardara, and Alberto Compagno. 2019. Enabling ICN in the Internet Protocol:
Analysis and Evaluation of the Hybrid-ICN Architecture. In Proceedings of the
6th ACM SIGCOMM Conference on Information-Centric Networking (ICN '19).
Association for Computing Machinery, New York, NY, USA, 55–66. DOI:
https://doi.org/10.1145/3357150.3357394

The project wiki page is full of resources  https://wiki.fd.io/view/HICN

.. toctree::
   :caption: Architecture

   1-architecture


.. toctree::
   :caption: Getting started
   :maxdepth: 1

   started

.. toctree::
   :caption: Core library
   :maxdepth: 1

   lib

.. toctree::
   :caption: The VPP Plugin
   :maxdepth: 1

   vpp-plugin

.. toctree::
   :caption: The Transport Library
   :maxdepth: 1

   transport

.. toctree::
   :caption: The Portable Forwarder
   :maxdepth: 1

   hicn-light

.. toctree::
   :caption: Network Control and Management
   :maxdepth: 1

   interface
   control
   telemetry

.. toctree::
   :caption: Applications and Tools
   :maxdepth: 1

   utils
   apps
   packethicn