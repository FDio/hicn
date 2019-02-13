[33mcommit 2faefd51283555bd3bda56739642b7fc760359d8[m[33m ([m[1;36mHEAD -> [m[1;32mreview/masoud_hemmatpour/17569[m[33m)[m
Author: Masoud Hemmatpour <mhemmatp@cisco.com>
Date:   Wed Feb 13 15:46:22 2019 +0100

    [HICN-5] hicn sysrepo plugin initial
    
    Change-Id: I4713465c39abd00fac709cfc908b9384ea75532f
    Signed-off-by: Masoud Hemmatpour <mhemmatp@cisco.com>
    Signed-off-by: Luca Muscariello <lumuscar+fdio@cisco.com>
    Signed-off-by: Masoud Hemmatpour <mhemmatp@cisco.com>

[33mcommit bb428fc90f2623bdf35c53e62bf2aaeba2d1e0b7[m[33m ([m[1;31mgerrit/master[m[33m)[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Fri Feb 22 18:09:48 2019 +0100

    [HICN-83] Added cmake flag "-DENABLE_PUNTING=[ON|OFF]" for enabling/disabling punting in hicnLightDaemon.
    
    Change-Id: I14f5e1ce21f2c2381359fa6184671d3cbe43b808
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit fccece7f012c209f04d9f9be4a10073536091914[m
Merge: f7b5ee1 5c77476
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Fri Feb 22 16:54:25 2019 +0000

    Merge "[HICN-80] Avoid segfault when deleting memif interface on VPP."

[33mcommit f7b5ee120520802c7009f6925b91c9262fde49a1[m
Merge: 9c88e58 157c561
Author: Mauro Sardara <msardara@cisco.com>
Date:   Fri Feb 22 16:54:22 2019 +0000

    Merge "[HICN-79] epoll timeout is now set to 1 second"

[33mcommit 9c88e58ffe33a869caf63d5cc72ae1bdd6411ba9[m
Merge: a41f31d 880795d
Author: Mauro Sardara <msardara@cisco.com>
Date:   Fri Feb 22 16:48:54 2019 +0000

    Merge "[HICN-81] UDP face data dropped due to struct sockaddr inconsistency"

[33mcommit a41f31d2c8610cf458bbb3b6279dc27954b1f73f[m
Merge: 6570a74 ccbccd6
Author: Mauro Sardara <msardara@cisco.com>
Date:   Fri Feb 22 16:21:34 2019 +0000

    Merge "[HICN-78] Added option -l to set data lifetime. If not set the data never expires."

[33mcommit 880795dec24dc966f8196e66b0fa1dd6debd958f[m
Author: michele papalini <micpapal@cisco.com>
Date:   Fri Feb 22 17:18:52 2019 +0100

    [HICN-81] UDP face data dropped due to struct sockaddr inconsistency
    
    Change-Id: I174b2b9beaaee8cab89044a1d9ad3aa686da6ca3
    Signed-off-by: michele papalini <micpapal@cisco.com>

[33mcommit 5c774765616b219ddb293ebf37ba79a806523f11[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Fri Feb 22 12:20:19 2019 +0100

    [HICN-80] Avoid segfault when deleting memif interface on VPP.
    
    Change-Id: Ie36cfc0ade82b38815d61a7ead2c72fc640236ed
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit ccbccd6acccb2f6e862f198c61401b454056a919[m
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Fri Feb 22 10:32:48 2019 +0100

    [HICN-78] Added option -l to set data lifetime. If not set the data never expires.
    
    Change-Id: I7f0734a4e29826f276cfab1c83d5878bfab5c900
    Signed-off-by: Alberto Compagno <acompagn+fdio@cisco.com>

[33mcommit 157c561e1b7c6b339c6774fec48a34c43fb272c1[m
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Fri Feb 22 10:18:53 2019 +0100

    [HICN-79] epoll timeout is now set to 1 second
    
    Change-Id: Ibec7ff2064ac69833e9c1bb1d8aaa064c02e64be
    Signed-off-by: Alberto Compagno <acompagn+fdio@cisco.com>

[33mcommit 6570a746680fb9f99718183157909acfd2c85cad[m
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Fri Feb 22 10:06:58 2019 +0100

    [HICN-74] Data with lifetime 0 are never cached in the CS. When such data is received the PIT entry is removed.
    If the data comes from the push node the data is dropped.
    
    Change-Id: I8780e16cca30ad8298f1a494f1138f8b35ae0fab
    Signed-off-by: Alberto Compagno <acompagn+fdio@cisco.com>

[33mcommit 1e2e32c281ddb053d03efd74eea660dfb0b6316f[m
Merge: 837def2 a7b633f
Author: Mauro Sardara <msardara@cisco.com>
Date:   Thu Feb 21 13:48:42 2019 +0000

    Merge "[HICN-75] fixed forwarding issue in udp face and improved packet tracing to show the hicn name"

[33mcommit 837def2658716940633d39429619b9c2bd8d9b12[m
Author: Luca Muscariello <lumuscar+fdio@cisco.com>
Date:   Thu Feb 21 14:13:19 2019 +0100

    [HICN-77] adding sonarcube support
    
    Change-Id: Id0436d4688c747679acb41167528f828f7cf6805
    Signed-off-by: Luca Muscariello <lumuscar+fdio@cisco.com>

[33mcommit a7b633f4c8b4d7245c4411cdf249f6e0809fb60b[m
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Thu Feb 21 11:40:21 2019 +0100

    [HICN-75] fixed forwarding issue in udp face and improved packet tracing to show the hicn name
    
    Change-Id: I74426c541324d66c2d1b0353afcca17c5aedceba
    Signed-off-by: Alberto Compagno <acompagn+fdio@cisco.com>

[33mcommit 0d0e74ffb9207cb56fcf4d5b034906a406c1bffa[m
Merge: 7734174 1c5106f
Author: Luca Muscariello <lumuscar+fdio@cisco.com>
Date:   Thu Feb 21 08:43:48 2019 +0000

    Merge "[HICN-71] - Handling the case in which a pushed data hit an existing pit entry (created after the data has gone through the data_pcslookup_node). In this case the data packet is forwarded to the data_fwd_node - Handling the case in which the hash table (in pcs) is full and it is not possible to allocate another bucket. In this case the packet is dropped. - Copying packets whose length is less than 128B. VPP prevents to create a chain of vlib_buffer where the first, or middle, vlib_buffer are holding less then 128B."

[33mcommit 1c5106f66a6749266cb1d228eda98413c80cbf1f[m
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Tue Feb 19 18:46:36 2019 +0100

    [HICN-71]
    - Handling the case in which a pushed data hit an existing pit entry (created after the data has gone through the data_pcslookup_node). In this case the data packet is forwarded to the data_fwd_node
    - Handling the case in which the hash table (in pcs) is full and it is not possible to allocate another bucket. In this case the packet is dropped.
    - Copying packets whose length is less than 128B. VPP prevents to create a chain of vlib_buffer where the first, or middle, vlib_buffer are holding less then 128B.
    
    [HICN-72]
    - Assign a /128 subnet to the producer app face.
    
    Change-Id: I6c19d6d127774a7f59ac69ac965d4bcd6a72becc
    Signed-off-by: Alberto Compagno <acompagn+fdio@cisco.com>

[33mcommit 7734174f81412b1544243d1d358ee2641dcdb3dd[m
Author: michele papalini <micpapal@cisco.com>
Date:   Tue Feb 19 17:51:28 2019 +0100

    [HICN-70] remove double htons in addListener
    
    Change-Id: Iaf65c52ec45c737f3bb6cc85a66c0f1521921e5f
    Signed-off-by: michele papalini <micpapal@cisco.com>

[33mcommit 286fd55fc0cf620747209570a32b79d97d50d9b4[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Tue Feb 19 10:15:43 2019 +0100

    [HICN-69] Include libtransport config file in raw_socket_connector.h.
    
    Change-Id: Ieac743f5c46edd6568d48e689216bb8723d44e2c
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit dd81185294bdda4203c747a9ce5c19a63c55dbd4[m
Author: michele papalini <micpapal@cisco.com>
Date:   Mon Feb 18 16:12:36 2019 +0100

    [HICN-69] add compiler definitions for programs using hicn
    
    Change-Id: If20c1e487ca4d9c00ffeebe09f31b475b354e293
    Signed-off-by: michele papalini <micpapal@cisco.com>

[33mcommit 63140cf46b43824d77206402cef13f01c2b9cdde[m
Author: michele papalini <micpapal@cisco.com>
Date:   Mon Feb 18 15:11:14 2019 +0100

    [HICN-68] remove compiling warnign on MAC-OS
    
    Change-Id: I6e238cd3ae20e081cfedec8c249eebec38af2028
    Signed-off-by: michele papalini <micpapal@cisco.com>

[33mcommit 2fd90aea1831942cda49d6635e95c86d8e494966[m
Merge: 7465d7e 79e0d4f
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Mon Feb 18 10:56:49 2019 +0000

    Merge "[HICN-50] Added udp application connector."

[33mcommit 79e0d4f89c4d532189aae06cc5dfbc14e3269703[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Mon Feb 11 10:44:29 2019 +0100

    [HICN-50] Added udp application connector.
    
    Change-Id: I0c5afad4b404ec485f50b1342b81e70ef85a5163
    Signed-off-by: Mauro Sardara <msardara@cisco.com>
    Signed-off-by: michele papalini <micpapal@cisco.com>

[33mcommit 7465d7ee3fbae80d24342930ad78682a6e674bb9[m
Merge: 75af120 bbb74d3
Author: Mauro Sardara <msardara@cisco.com>
Date:   Mon Feb 18 10:44:04 2019 +0000

    Merge "[HICN-67] add interest callback in RTC producer socket"

[33mcommit bbb74d387bf983351d1d4106d31f0c8068ce52ca[m
Author: michele papalini <micpapal@cisco.com>
Date:   Mon Feb 18 11:18:03 2019 +0100

    [HICN-67] add interest callback in RTC producer socket
    
    Change-Id: I8b2075d71f272956e213b0b1505d7af46844d387
    Signed-off-by: michele papalini <micpapal@cisco.com>

[33mcommit 75af12024ef5c33040e0771972e3fce01e48a9e4[m
Author: Luca Muscariello <lumuscar+fdio@cisco.com>
Date:   Fri Feb 15 21:19:02 2019 +0100

    [HICN-35] add vapi
    
    Change-Id: I34dfeb05b2d2796129e68c3f38d73f1ec49699a1
    Signed-off-by: Luca Muscariello <lumuscar+fdio@cisco.com>

[33mcommit 7d2b217bd01a8da1a2ac57aaad59b3179c7af916[m
Merge: 2ba6db7 f8c0d76
Author: Mauro Sardara <msardara@cisco.com>
Date:   Thu Feb 14 12:22:19 2019 +0000

    Merge "- [HICN-65] Populating hash map of handler and crc in api_main - Added possibility to start the forwarder from binary api without setting any parameters - Changed pit lifetime values from seconds to milliseconds"

[33mcommit f8c0d76eaff9c256804a4825301af4b9056f77d3[m
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Thu Feb 14 12:14:51 2019 +0100

    - [HICN-65] Populating hash map of handler and crc in api_main
    - Added possibility to start the forwarder from binary api without setting any parameters
    - Changed pit lifetime values from seconds to milliseconds
    
    Change-Id: I83706f22ddd8e825c1021fe70d4bf52e1b929be8
    Signed-off-by: Alberto Compagno <acompagn+fdio@cisco.com>

[33mcommit 2ba6db73e9a319b665853d65682230be98dde8d9[m
Author: Angelo Mantellini <manangel@cisco.com>
Date:   Wed Feb 13 17:27:33 2019 +0100

    [HICN-61] Compile Error in libtransport in windows environment
    
    Change-Id: I25642a194996e449b91d492b22a379466c524940
    Signed-off-by: Angelo Mantellini <manangel@cisco.com>

[33mcommit 2f039d41169b95fa1ee9b1be9fbdc8e899707d25[m
Merge: d1dedcb ba47e02
Author: Mauro Sardara <msardara@cisco.com>
Date:   Wed Feb 13 17:03:49 2019 +0000

    Merge "[HICN-62] Using the new API in libparc to remove a per-packet copy of the signature"

[33mcommit ba47e022facc1fe7b9f71b29289539a33d377b6e[m
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Wed Feb 13 17:45:14 2019 +0100

    [HICN-62] Using the new API in libparc to remove a per-packet copy of the signature
    
    Change-Id: I4d2dee75d7ba3ed94a1676fd4ab892c6bcad958a
    Signed-off-by: Alberto Compagno <acompagn+fdio@cisco.com>

[33mcommit d1dedcb21e7ba074a0a83fad09a742e54a8d1525[m
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Wed Feb 13 15:06:23 2019 +0100

    [HICN-60] Solved concurrent memory access which was leading to seg-fault
    
    Change-Id: I7b9fcf79bb97650346f7d92af8cbb419f0a5cb95
    Signed-off-by: Alberto Compagno <acompagn+fdio@cisco.com>

[33mcommit 13fccc2bb1c2317061e6bf985c87bca647fb3b6f[m[33m ([m[1;31morigin/master[m[33m, [m[1;31morigin/HEAD[m[33m)[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Wed Feb 13 11:50:10 2019 +0100

    [HICN-59] Do not call clear on membuf sharing same underlying memory. Use trimEnd instead.
    
    Change-Id: I69463ede2b32f1d625b6161fabd08daca41c3483
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit cf3c377193654f2d8eda8a42d51a9c9363e9bd9e[m
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Tue Feb 12 17:38:51 2019 +0100

    [HICN-54] Fixed udp face visualization
    
    Change-Id: Id6bb058bfb54e76ab08afae89db8cf489629f306
    Signed-off-by: Alberto Compagno <acompagn+fdio@cisco.com>

[33mcommit 45ae2768f2842cc55f153a71fa66b1d3e25e9ab7[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Tue Feb 12 00:07:11 2019 +0100

    [HICN-52] Fix signature computation and verification in libtransport
    
    Change-Id: I9b30a9c9e95e2cb2f135fe7efd43e633235196d9
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit fbd4dd9c5eba6f8f10bcc0db30a72ea3378c149b[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Mon Feb 11 23:50:45 2019 +0100

    [HICN-51] Add static assert for ensuring correct struct size in libhicn definitions.
    
    Change-Id: Ib41e9cbdd2ea84a40eb4e7b01da131cbad9575c4
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit f126f86da5acf088f24e97ecb32f9ba5a1789aa4[m
Author: Angelo Mantellini <manangel@cisco.com>
Date:   Fri Feb 8 15:11:57 2019 +0100

    [HICN-44] Remove warnings libhicn (lib) on windows
    
    Change-Id: I637e9c1e05de8a9e6743ea729b62d3eedd6ca54b
    Signed-off-by: Angelo Mantellini <manangel@cisco.com>

[33mcommit 3447d02974947d10440e4aa5627318c29be95c01[m
Merge: 86d5757 3c9836d
Author: Mauro Sardara <msardara@cisco.com>
Date:   Mon Feb 11 13:49:41 2019 +0000

    Merge "[HICN-47] Remove warnings utils on windows"

[33mcommit 86d5757be30d1d696b85cbc22e471158b9a19090[m
Merge: 6248a13 4c88764
Author: Mauro Sardara <msardara@cisco.com>
Date:   Mon Feb 11 13:47:45 2019 +0000

    Merge "[HICN-46] Remove warnings libtransport on windows"

[33mcommit 3c9836d46747358fa73e0eb818d95b7907967cb2[m
Author: Angelo Mantellini <manangel@cisco.com>
Date:   Sat Feb 9 10:49:35 2019 +0100

    [HICN-47] Remove warnings utils on windows
    
    Change-Id: Id8616bc6b68ec2854078ecfe3b30f4573e7d7c6c
    Signed-off-by: Angelo Mantellini <manangel@cisco.com>

[33mcommit 4c8876424cca41c8ce8ce67c1c0a394932cbdd58[m
Author: Angelo Mantellini <manangel@cisco.com>
Date:   Sun Feb 10 12:49:21 2019 +0100

    [HICN-46] Remove warnings libtransport on windows
    
    Change-Id: I09456770dcbca979491cdcadb310eab95a0dea17
    Signed-off-by: Angelo Mantellini <manangel@cisco.com>

[33mcommit 6248a13f86d0f04051539321ae63c910cd533a0e[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Mon Feb 11 14:13:35 2019 +0100

    [HICN-43] Fix AH_FLAG set during packet forging.
    
    Change-Id: I6aa224b17e9e1ec30d6f7d263ddaf628f179a5f0
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit b98d1bb135b617bf28202d328c44ed7a6eff025c[m
Merge: 731e118 1ac41cb
Author: Michele Papalini <micpapal@cisco.com>
Date:   Sun Feb 10 13:34:16 2019 +0000

    Merge "[HICN-49] Remove warnings hicn-light on windows"

[33mcommit 1ac41cb08281bf5460dfea5fc40ff6f8e14873a1[m
Author: Angelo Mantellini <manangel@cisco.com>
Date:   Sun Feb 10 13:34:22 2019 +0100

    [HICN-49] Remove warnings hicn-light on windows
    
    Change-Id: I106713c285ad5cc47cb5ae3aaf9c837685156e36
    Signed-off-by: Angelo Mantellini <manangel@cisco.com>

[33mcommit 731e1188262be87d962f5694022fc74928d889b0[m
Author: michele papalini <micpapal@cisco.com>
Date:   Sun Feb 10 12:38:19 2019 +0100

    [HICN-48] remove hole detection in RTC
    
    Change-Id: I5e8700b6e26660acbe5e9a7a6716d322acb03466
    Signed-off-by: michele papalini <micpapal@cisco.com>

[33mcommit 13ec18b4b3ec8455daad674a0c0e616885b83608[m
Merge: d6c91e0 1e1d08d
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Fri Feb 8 14:04:40 2019 +0000

    Merge "[HICN-43] Fixed packet lifetime and setting AH flag when a data packet carries a signature"

[33mcommit d6c91e037e394bd61dfa8a3f904199a6aeb1bd45[m
Merge: 4741be2 c93d090
Author: Mauro Sardara <msardara@cisco.com>
Date:   Fri Feb 8 11:06:06 2019 +0000

    Merge "[HICN-42] reuse HICN_MAX_LIFETIME in messageHandler"

[33mcommit 1e1d08d94bb39e2de79d7182e5598fc5fa5e9fce[m
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Fri Feb 8 12:00:25 2019 +0100

    [HICN-43] Fixed packet lifetime and setting AH flag when a data packet carries a signature
    
    Change-Id: I5e14716bc9bfcd8ffc3ab8cda8aa9ba0ca5c6d82
    Signed-off-by: Alberto Compagno <acompagn+fdio@cisco.com>

[33mcommit c93d0904254871ec3c8563559bc157ad5a11f3e0[m
Author: michele papalini <micpapal@cisco.com>
Date:   Fri Feb 8 11:43:58 2019 +0100

    [HICN-42] reuse HICN_MAX_LIFETIME in messageHandler
    
    Change-Id: Ie47a1ce333f833de82205d6d686f5cfd31b4d662
    Signed-off-by: michele papalini <micpapal@cisco.com>

[33mcommit 4741be2a5d7d6d0dd79dab0ea372c47f97f48719[m
Merge: 0942608 046eb92
Author: Luca Muscariello <lumuscar+fdio@cisco.com>
Date:   Fri Feb 8 08:52:06 2019 +0000

    Merge "[HICN-33] Hicn Fdio logo for windows"

[33mcommit 09426081c8fd671e77e4545d9098a3f1f359e032[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Thu Feb 7 19:54:45 2019 +0100

    Removed useless lines from CMakeLists
    
    Change-Id: Ifa9a98b411dae4718b4f0ec5cc80f11254f408d6
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit 3f0e792ab647ad79cab3e2282ab5d4c33a4c5de1[m
Author: michele papalini <micpapal@cisco.com>
Date:   Thu Feb 7 18:40:38 2019 +0100

    [HICN-41] rename define variables in rtc transport
    
    Change-Id: I2235f319a02aed43657db4954b68f00a28b0c9d8
    Signed-off-by: michele papalini <micpapal@cisco.com>

[33mcommit 046eb92603cf61ee0f44f426e19021f44a06377a[m
Author: Angelo Mantellini <manangel@cisco.com>
Date:   Tue Feb 5 12:59:15 2019 +0100

    [HICN-33] Hicn Fdio logo for windows
    
    Change-Id: I1c68da4462f4ccb627419a9a8073a3fe11d36cf6
    Signed-off-by: Angelo Mantellini <manangel@cisco.com>

[33mcommit db1afad8749fce983636456c16c9df9c24d73af4[m
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Thu Feb 7 13:12:19 2019 +0100

    [HICN-39] Added api that return a pointer to the signature hold in a packet
    [HICN-40] Fixed signature calculation by allocating a contiguous portion of
    memory that holds the entire hICN header (IP+TCP+AH)
    
    Change-Id: I9d40bab0e3ecb82949b8b3a00e2cc1214457e4e3
    Signed-off-by: Alberto Compagno <acompagn+fdio@cisco.com>

[33mcommit 216e35ba535efa00af39b7624f363ca832836e3f[m
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Tue Feb 5 22:32:48 2019 +0100

    [HICN-34] Fixed bug on struct size and implemented initialization method
    
    Change-Id: I975fce31c2da5ad42d6787b0c5f305c60390d68c
    Signed-off-by: Alberto Compagno <acompagn+fdio@cisco.com>

[33mcommit 7f4916ae09e89aadfc2029ffbe81231ba1ea8016[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Tue Feb 5 13:45:46 2019 +0100

    [HICN-25] Revert to previous build-packages.sh
    
    Change-Id: I9bd77da03f82a2c4c6a3045184112f76762dda07
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit fb0c4afe09d2804e8121d3d917dcb42f37a03e31[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Tue Feb 5 13:17:18 2019 +0100

    [HICN-25] Temporarily push docs from package merge jobs.
    
    Change-Id: I9cf7009daa124210901dfd89e1bdf4b1eaaee308
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit fbfee6c0b8b40540affa6cd7c8b4947a206fec70[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Tue Feb 5 10:02:16 2019 +0100

    [HICN-25] Test docs script.
    
    Change-Id: I37cb7b34a737323862619c198ff4e3b570217887
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit 7b7a5cfb320f3cb4ac541a6e95ae949c4e4fa3fc[m
Merge: c02c87f 83ef24a
Author: Michele Papalini <micpapal@cisco.com>
Date:   Mon Feb 4 17:02:40 2019 +0000

    Merge "[HICN-30] Removed wrong string that was appearing on the producer face"

[33mcommit 83ef24a70ddbeb9daa9c12a68464cc3b8349bd4f[m
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Mon Feb 4 17:51:11 2019 +0100

    [HICN-30] Removed wrong string that was appearing on the producer face
    
    Change-Id: Ifa215f861836e560995df7503d41ea5e9df42def
    Signed-off-by: Alberto Compagno <acompagn+fdio@cisco.com>

[33mcommit c02c87fca9a3bc59eab6950389e89618f4ec4245[m
Author: michele papalini <micpapal@cisco.com>
Date:   Mon Feb 4 17:45:47 2019 +0100

    [HICN-29] fixed consumer socket connection
    
    Change-Id: Id2214262196999fedeb46d3cddbe543e1b181a46
    Signed-off-by: michele papalini <micpapal@cisco.com>

[33mcommit 030bb23078a3ecb4dc48e0af0da4ad9d6d10ff7e[m
Author: Angelo Mantellini <manangel@cisco.com>
Date:   Mon Feb 4 16:43:27 2019 +0100

    [HICN-28] Error in hicn-light with udp tunnel
    
    Change-Id: Ia3efb22ec521f7a47636bc5e3da2f88601fbeec2
    Signed-off-by: Angelo Mantellini <manangel@cisco.com>

[33mcommit e18973968f360e7750b87d2713033960565d87b0[m
Merge: e5d186c 6b43f54
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Mon Feb 4 13:47:00 2019 +0000

    Merge "[HICN-27] Removed libhicn dependency in hicn-plugin [deb/rpm] package."

[33mcommit e5d186cd59f471ef8c97ce341e231c7663ac92b9[m
Merge: 9a7a239 7cf1f75
Author: Jordan Augé <jordan.auge+fdio@cisco.com>
Date:   Mon Feb 4 13:33:33 2019 +0000

    Merge "[HICN-9] Fix version number in libhicn doc."

[33mcommit 6b43f544d2dcff6ad67950de4cd3eed1536f8d5b[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Mon Feb 4 14:25:59 2019 +0100

    [HICN-27] Removed libhicn dependency in hicn-plugin [deb/rpm] package.
    
    Change-Id: I5e694e87c322d78b9f1d15d3811abc260f5d5d85
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit 9a7a239ed9d70513580d2104f2a70e77d03d91be[m
Merge: 9eefff3 1dc1d5d
Author: Mauro Sardara <msardara@cisco.com>
Date:   Mon Feb 4 13:23:58 2019 +0000

    Merge "Update on README.me after 19.01 release, information about VPP sync."

[33mcommit 7cf1f75bb113353f9a35b0d20302a9d32383154e[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Mon Feb 4 14:06:58 2019 +0100

    [HICN-9] Fix version number in libhicn doc.
    
    Change-Id: I7b136665e12951604da2a08ae0af5fe506fa62dd
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit 1dc1d5d8ea61ef50165bcc17c2d0af86cf032a47[m
Author: Luca Muscariello <lumuscar+fdio@cisco.com>
Date:   Sat Feb 2 17:03:38 2019 +0100

    Update on README.me after 19.01 release, information about VPP sync.
    
    Change-Id: Ib072d624a61fbebafb6bd7f7aa9622ce09ed2fff
    Signed-off-by: Luca Muscariello <lumuscar+fdio@cisco.com>

[33mcommit 9eefff3b484dd46e1244d0201844fc91e2b78a62[m
Merge: 79f9c33 cddd3c8
Author: Mauro Sardara <msardara@cisco.com>
Date:   Mon Feb 4 09:48:29 2019 +0000

    Merge "[HICN-10] Remove temporary files generated by CPack[Deb/Rpm]."

[33mcommit cddd3c895a6b7c29bdf7d8d54e97921d9c6c395c[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Mon Feb 4 10:39:27 2019 +0100

    [HICN-10] Remove temporary files generated by CPack[Deb/Rpm].
    
    Change-Id: I05fc7d917970a0b9780c667aa5e818cbc1d3240a
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit 79f9c336d9d8af63e322e3c52f09fec3d7cb3c2b[m
Merge: e8fabe3 f5a0b8a
Author: Luca Muscariello <lumuscar+fdio@cisco.com>
Date:   Fri Feb 1 20:00:21 2019 +0000

    Merge "[HICN24] Windows compatibility for hicn-light"

[33mcommit e8fabe3f6313a3b9050fe16458e4714d9dce426e[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Fri Feb 1 17:12:38 2019 +0100

    [HICN-10] Compile libtransport with libmemif support
    
    Change-Id: I81d1cb4d5f16a61c35f66fe347985f05d8c97383
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit f5a0b8a5e24cede05e15ab696f0e15257a503525[m
Author: Angelo Mantellini <manangel@cisco.com>
Date:   Thu Jan 31 18:20:48 2019 +0100

    [HICN24] Windows compatibility for hicn-light
    
    Change-Id: I8e19e52c9b4ec0fcbd7344c28765f5da1937569c
    Signed-off-by: Angelo Mantellini <manangel@cisco.com>

[33mcommit c00bc6fc2af9a54fe339f8d6a3ec1ab889c2931e[m
Merge: 107e05e 1dea17f
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Fri Feb 1 10:16:50 2019 +0000

    Merge "[HICN-10] Add support for building hicn-plugin packages. Do not build packages for components without name."

[33mcommit 1dea17fe921e1f94db63e4c563fe08dd25734900[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Fri Feb 1 09:40:26 2019 +0000

    [HICN-10] Add support for building hicn-plugin packages. Do not build packages for components without name.
    
    Change-Id: I11eff1b9dc6e71e079baf65703192a7cbfb565e8
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit 107e05eab1d032b9ac741f88a3bec8e60b22efc9[m
Merge: c793ea8 73a3218
Author: Jordan Augé <jordan.auge+fdio@cisco.com>
Date:   Fri Feb 1 09:42:21 2019 +0000

    Merge "Minor cleanup"

[33mcommit c793ea85f8375013abaf2c6fb43347f935558276[m
Merge: bf29f9a 159b18d
Author: Luca Muscariello <lumuscar+fdio@cisco.com>
Date:   Thu Jan 31 20:18:18 2019 +0000

    Merge "[HICN-23] Fix ICMP types for MAP-Me Ack"

[33mcommit 73a32185fcff046606af68f916ab3d474d9ca765[m
Author: Jordan Augé <jordan.auge+fdio@cisco.com>
Date:   Thu Jan 31 17:56:09 2019 +0100

    Minor cleanup
    
    Change-Id: Ic4197900ca835414e2550de6fc1e4a098a91e620
    Signed-off-by: Jordan Augé <jordan.auge+fdio@cisco.com>

[33mcommit bf29f9a52ffa3a1f32f700e4fd36ea53885d83aa[m
Merge: 4d3c71e 2d2552c
Author: Mauro Sardara <msardara@cisco.com>
Date:   Thu Jan 31 16:56:40 2019 +0000

    Merge "HICN-9 make doc lib"

[33mcommit 2d2552c4f907a25255b1b6b8071b7e58b1c23515[m
Author: Jordan Augé <jordan.auge+fdio@cisco.com>
Date:   Thu Jan 31 17:19:26 2019 +0100

    HICN-9 make doc lib
    
    Change-Id: I349c53b527df2445cd2d521555ff64af2400a8b2
    Signed-off-by: Jordan Augé <jordan.auge+fdio@cisco.com>

[33mcommit 159b18d6875bc2f9df66c78d1b71aa07930666af[m
Author: Jordan Augé <jordan.auge+fdio@cisco.com>
Date:   Thu Jan 31 17:26:36 2019 +0100

    [HICN-23] Fix ICMP types for MAP-Me Ack
    
    Change-Id: Ieb9fcb87f75be62270df6e2f599182fd9fba5e5b
    Signed-off-by: Jordan Augé <jordan.auge+fdio@cisco.com>

[33mcommit 4d3c71e9ae772d020220596636bc6e3ea07741e5[m
Author: Angelo Mantellini <manangel@cisco.com>
Date:   Thu Jan 31 12:01:24 2019 +0100

    [HICN-20] Windows compatibility for ping_client, ping_server and hiperf
    
    Change-Id: I15df978e9e4320f7e6b7c5b3f7db025dcfd6aa06
    Signed-off-by: Angelo Mantellini <manangel@cisco.com>

[33mcommit 7b61129b2ed89d2cc3ca5560f55c26c6c347a215[m
Author: Angelo Mantellini <manangel@cisco.com>
Date:   Thu Jan 31 10:36:54 2019 +0100

    [HICN-20] This source upgrade allows to compile ping_client, ping_server and hiperf (utils folder) in Windows.
    
    Change-Id: I8253aa9aa640644b0daffd95dff202956371d814
    Signed-off-by: Angelo Mantellini <manangel@cisco.com>

[33mcommit 67371907c2433f5233d4a669a1c9176539e9928f[m
Author: Angelo Mantellini <manangel@cisco.com>
Date:   Wed Jan 30 16:47:41 2019 +0100

    [HICN-19] Add support for Windows 10 x64 for libhicn (lib)
    
    Change-Id: I5109d5ce293265fca557c2ef952fcb1c13b9d816
    Signed-off-by: Angelo Mantellini <manangel@cisco.com>

[33mcommit e5145b878f9de35676085409878a66899d2ee4f2[m
Author: Angelo Mantellini <manangel@cisco.com>
Date:   Wed Jan 30 12:11:34 2019 +0100

    [HICN-18] first commit of libtransport for windows
    
    Change-Id: I3a43b22194aa13ae5de1746e3d4bd9a275070261
    Signed-off-by: Angelo Mantellini <manangel@cisco.com>

[33mcommit 30061551cd39c9f30280bfa0cf3cc909f4fac015[m
Merge: 51ff9b6 03f086e
Author: Luca Muscariello <lumuscar+fdio@cisco.com>
Date:   Tue Jan 29 19:53:08 2019 +0000

    Merge "Add INFO.yaml file"

[33mcommit 51ff9b669dff18c9300b9fe5bdef91e7040edac0[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Tue Jan 29 15:49:15 2019 +0100

    [HICN-17] Add possibility to destroy connection directly from stopEventsLoop with an additional parameter.
    
    Change-Id: I869a079a7b2f436768a62de66fd9281a7d1243cd
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit a2e898eae8086cded2acfa96347184b3aa88d316[m
Merge: fce54a7 92bce60
Author: Mauro Sardara <msardara@cisco.com>
Date:   Tue Jan 29 16:32:54 2019 +0000

    Merge "[HICN-10] Treat warning as errors in compilation during verify jobs."

[33mcommit 92bce6034ead88d1a11b5bdacd975a9d4cbec795[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Tue Jan 29 16:39:50 2019 +0100

    [HICN-10] Treat warning as errors in compilation during verify jobs.
    
    Change-Id: Iab6deb14157f81c9f2f8ba6762e93e9860b108bd
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit fce54a724e80c7442c98da8bf491ce60eb762db1[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Tue Jan 29 13:48:05 2019 +0100

    [HICN-10] Fix check of environment variable BUILD_NUMBER
    
    Change-Id: Ic6e6a2137cbdf7fb29b62c5e2d2a051a9e8aae1b
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit 72f060e86926fa25955bd31157086ca4f0889940[m
Merge: 317c2f8 07db199
Author: Mauro Sardara <msardara@cisco.com>
Date:   Tue Jan 29 09:36:03 2019 +0000

    Merge "[HICN-16] File Descriptors fixes for list commands"

[33mcommit 07db19960166bd7241836b858ecf41420dafc63e[m
Author: Giovanni Conte <gconte@cisco.com>
Date:   Mon Jan 28 15:08:16 2019 +0100

    [HICN-16] File Descriptors fixes for list commands
    
    Change-Id: I052013d0d8c6c2bd4b7631c68065bca91024646b
    Signed-off-by: Giovanni Conte <gconte@cisco.com>

[33mcommit 317c2f8e695de186487347117296faa04ed42269[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Mon Jan 28 16:17:56 2019 +0100

    [HICN-10] Fix for build number retrieval from CMake
    
    Change-Id: I511df63962dda9ec53117a9a380cb5ac05a0b10b
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit 015dd3fa693039acd08171e8a8d27b3776670a41[m
Merge: 88dbf13 fe84f93
Author: Mauro Sardara <msardara@cisco.com>
Date:   Mon Jan 28 13:56:17 2019 +0000

    Merge "[HICN-10] First version of build script."

[33mcommit fe84f9382a015b079fbcbb22d37be23e21e2bdff[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Tue Jan 22 19:06:55 2019 +0100

    [HICN-10] First version of build script.
    
    Change-Id: Iaddb38e56280ddb6cddf3b2186a206c58fd45233
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit 88dbf13b799e0e429be79dd7a03217c3b1b3814f[m
Author: michele papalini <micpapal+fdio@cisco.com>
Date:   Mon Jan 28 14:16:15 2019 +0100

    [HICN-15] add include in socket_connector
    
    Change-Id: I362fdde5004a0ec36ca4a256a10d005592b2ac61
    Signed-off-by: michele papalini <micpapal+fdio@cisco.com>

[33mcommit 03371e2e47523dcbadb9a4a79969ecd225b3ff3d[m
Author: michele papalini <micpapal+fdio@cisco.com>
Date:   Fri Jan 25 14:58:31 2019 +0100

    [HICN-13] sendInterest with customized callbacks
    
    Change-Id: Ie4b2aac7f5f356f8afc7aaf83b723596dcbb4532
    Signed-off-by: michele papalini <micpapal+fdio@cisco.com>

[33mcommit e718d5b93c9856d38b358fbb256327c8c76d387f[m
Author: michele papalini <micpapal+fdio@cisco.com>
Date:   Thu Jan 24 16:04:03 2019 +0100

    new constructors for RTC producer/consumer sockets
    
    Change-Id: Icb982937e1f4cb38a2487f17c5a6b0cb1ef89cc2
    Signed-off-by: michele papalini <micpapal+fdio@cisco.com>

[33mcommit 9f9be9f2b6027be75395bd09d47f70e7ccce0e7f[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Thu Jan 24 13:43:28 2019 +0100

    Fix format string for printing size_t type
    
    Change-Id: Iee4ea1fbb4f9f1f68dbced2d11030dde2d3d88fb
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit 31e45f091ead0360afdd564e54a07dd963f296d4[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Thu Jan 24 10:19:54 2019 +0100

    Fix typo.
    
    Change-Id: I1300f848a22ef20a8f4a76f2a4bd504031b321cf
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit 03f086e80c92d047705b8fb8aa65ce6f0c3fa5e5[m
Author: Vanessa Rene Valderrama <vvalderrama@linuxfoundation.org>
Date:   Tue Jan 22 14:25:41 2019 -0600

    Add INFO.yaml file
    
    Add INFO.yaml to list:
    - Project description
    - Properties
    - Issue Tracking
    - Contacts
    - PTL information
    - Meeting information
    - Committer information
    
    Change-Id: I9abb77a927c517aa7af1f8c1136bea022457f462
    Signed-off-by: Vanessa Rene Valderrama <vvalderrama@linuxfoundation.org>

[33mcommit bed18df840364847e378d1ce2dea2fbace029720[m
Merge: 471bcdc 211b6a8
Author: Luca Muscariello <lumuscar+fdio@cisco.com>
Date:   Tue Jan 22 17:50:52 2019 +0000

    Merge "[HICN-3] First version of packaging system based on cmake."

[33mcommit 211b6a8bc6d959a874a43f28d4cda43eae48200d[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Tue Jan 22 00:02:05 2019 +0100

    [HICN-3] First version of packaging system based on cmake.
    
    Change-Id: I576f84f4c12f932e17e9169f2c6ffdaed128ca10
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit 471bcdc47dce89394a724e96f7c4bd6f242b6a31[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Tue Jan 22 11:42:51 2019 +0100

    [HICN-4] Fix semicolumn typo in lib/src/base.h
    
    Change-Id: Iffe3c24d8e254e939411a5e6014b4447eb874914
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit b8bd68b9544b7e4463178f54b54850cc44f2cb0e[m
Author: michele papalini <micpapal+fdio@cisco.com>
Date:   Tue Jan 22 10:16:53 2019 +0100

    jira issue HICN-7
    
    Change-Id: Id07bd589e06852f0788b823735af1b95e09bba0a
    Signed-off-by: michele papalini <micpapal+fdio@cisco.com>

[33mcommit 7d710d62fcb2a15505a7a0fc8feb91b8342fafd6[m
Author: michele papalini <micpapal+fdio@cisco.com>
Date:   Mon Jan 21 19:32:37 2019 +0100

    add include path
    
    Change-Id: I03c50a3aa98b96f686fedf548c543df3a0696b67
    Signed-off-by: michele papalini <micpapal+fdio@cisco.com>

[33mcommit 8a2e408a3fc20f1055a8ca796a4d32ebc9fb9aa0[m
Author: Jordan Augé <jordan.auge+fdio@cisco.com>
Date:   Mon Jan 21 13:25:59 2019 +0100

    HICN-4 - Fix Windows compilation issue with named struct initializers
    
    Change-Id: I9c9e8780ec1132d3d74b6202b9b142ed64b4e13f
    Signed-off-by: Jordan Augé <jordan.auge+fdio@cisco.com>

[33mcommit 29fb58203e5a44dbfafc6b788f50ca412c5f3c4b[m
Merge: c7f9421 9e5f41e
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Mon Jan 21 12:03:14 2019 +0000

    Merge "- Code style fix - Improved vpp binary api interface - Correction in object pool destructor - Fix error in Memif Connector"

[33mcommit 9e5f41ed6ebe64a789916794626485460078c420[m
Author: Mauro Sardara <msardara@cisco.com>
Date:   Sat Jan 19 01:29:33 2019 +0100

    - Code style fix
    - Improved vpp binary api interface
    - Correction in object pool destructor
    - Fix error in Memif Connector
    
    Change-Id: Id1dd9219fc1ac0b3717ae019ebff17373bebc635
    Signed-off-by: Mauro Sardara <msardara@cisco.com>

[33mcommit c7f942175b8c25c77ddc21561b52e3e6b5620b80[m
Author: Alberto Compagno <acompagn+fdio@cisco.com>
Date:   Sat Jan 19 17:28:57 2019 +0100

    Improved performance on data-fwd node:
    
     - Removed full pit entry initialization in favor of a lighter initialization on few fields
     - Squeezed pit entry size in order to store only the number of incomplete faces (as set in HICN_PARAM_PIT_ENTRY_PHOPS_MAX). The bitmap size is now determined by HICN_PARAM_FACES_MAX and optimized to do a fast lookup
    
    Replaced the field is_appface with the field flags in the hicn_buffer_t:
    
     - is_appface is now a flag with value 0x01 (HICN_BUFFER_FLAGS_FACE_IS_APP)
     - Added flag HICN_BUFFER_FLAGS_PKT_LESS_TWO_CL (0x02) to handle the copy of pkt with length < than 2*CACHE_LINES (in this case cloning is prevented by the cloning function in vpp). Such flag is initialized by the incoming face of the pkt.
    
    Change-Id: Ia956fd5719a28ee29f7fa2fd23d283964743efd8
    Signed-off-by: Alberto Compagno <acompagn+fdio@cisco.com>

[33mcommit d13d37534d9449dd54277af664310d5f957dc44a[m
Author: Mauro Sardara <msardara+fdio@cisco.com>
Date:   Thu Jan 17 17:10:44 2019 +0100

    Set C style to C11 for hicn-light forwarder
    
    Change-Id: I5377ad182f940dcb37e8fd1645dfcce2a3c3dd2a
    Signed-off-by: Mauro Sardara <msardara+fdio@cisco.com>

[33mcommit bac3da61644515f05663789b122554dc77549286[m[33m ([m[1;33mtag: v19.01[m[33m)[m
Author: Luca Muscariello <lumuscar+fdio@cisco.com>
Date:   Thu Jan 17 13:47:57 2019 +0100

    This is the first commit of the hicn project
    
    Change-Id: I6f2544ad9b9f8891c88cc4bcce3cf19bd3cc863f
    Signed-off-by: Luca Muscariello <lumuscar+fdio@cisco.com>

[33mcommit d5165246787301d0f13b646fda5e8a8567aef5ac[m
Author: Eric Ball <eball@linuxfoundation.org>
Date:   Tue Jan 15 16:41:41 2019 +0000

    Initial empty repository
