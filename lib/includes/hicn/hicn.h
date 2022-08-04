/*
 * Copyright (c) 2021-2022 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file hicn.h
 * @brief hICN master include file.
 *
 * Reference: https://tools.ietf.org/html/draft-muscariello-intarea-hicn
 *
 * This file is the entry point for projects to libhicn, which provides a
 * reference implementation for hICN specifications [1], including:
 *  - naming
 *  - packet headers
 *  - protocol mappings (IPv4, IPv6, TCP, ICMP, AH)
 *  - protocol independent packet operations
 *  - helpers for additional features such as Wireless Loss Detection and
 *    Recovery (WLDR) [2], Anchorless Mobility Management (hICN-AMM) [3],
 *    including MAP-Me producer mobility mechanisms [4].
 *
 * Other hICN constructs such as faces, policies and stategies are not included
 * in this header, but available separately in :
 *  - hicn/face.h
 *  - hicn/policy.h
 *  - hicn/strategy.h
 *
 * REFERENCES
 *
 *  [1] Hybrid Information-Centric Networking
 *      L. Muscariello, G. Carofiglio, J. Augé, M. Papalini
 *      IETF draft (intarea) @
 * https://tools.ietf.org/html/draft-muscariello-intarea-hicn
 *
 *  [2] Leveraging ICN in-network control for loss detection and recovery in
 * wireless mobile networks G. Carofiglio, L. Muscariello, M. Papalini, N.
 * Rozhnova, X. Zeng In proc. ICN'2016, Kyoto, JP
 *
 *  [3] Anchorless mobility through hICN
 *      J. Augé, G. Carofiglio, L. Muscariello, M. Papalini
 *      IETF draft (DMM) @
 * https://tools.ietf.org/html/draft-auge-dmm-hicn-mobility
 *
 *
 *  [4] MAP-Me : Managing Anchorless Mobility in Content Centric Networking
 *      J. Augé, G. Carofiglio, L. Muscariello, M. Papalini
 *      IRTF draft (ICNRG) @ https://tools.ietf.org/html/draft-irtf-icnrg-mapme
 */

#ifndef HICN__H
#define HICN__H

/* Base data structures */
#include <hicn/base.h>

/* Names */
#include <hicn/name.h>

/* Packet operations */
#include <hicn/packet.h>

/* MAP-Me : mobility management operations */
#include <hicn/mapme.h>

/* Error management */
#ifndef HICN_VPP_PLUGIN
#include <hicn/error.h>
#endif

#endif /* HICN__H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
