# Sysrepo plugin for hicn-plugin  (2019)

This plugin serves as a data management agent. It provides yang models via NETCONF to allow the management of hicn-plugin which runs in VPP instance from out-of-box.

## Software Requirement

- VPP

- hicn-plugin

- sysrepo

## hICN yang model

You can install the yang model using the following bash script:

EXIT_CODE=0
command -v sysrepoctl > /dev/null
if [ $? != 0 ]; then
    echo "Could not find command \"sysrepoctl\"."
     exit ${EXIT_CODE}
else
sysrepoctl --install --yang=path_to_hicn_yang_model
fi

hicn.yang can be found under plugin/yang/model/hicn.yang. It consists of two container nodes: hicn-conf and hicn-state. One is used to hold the
configuration data (i.e., hicn-conf) and one for providing the state data (i.e., hicn-state). The hicn-conf has one node, params, which contains the hICN configuration parameters. Controler can configure these parameters through the edit-config RPC call. This node can be used to enable and to initialize the hicn-plugin in VPP instance. Hicn-state container is used to provide the state data to the controler. It consists of state, strategy, strategies, route, and face-ip-params nodes with the coresponding leaves. In hicn model variety of RPCs are provided to allow controler to communicate with hicn-plugin as well as update the state data in hicn-state. Here you can find the schematic view of the described hicn model:


module: hicn
  +--rw hicn-conf
  |  +--rw params
  |     +--rw enable_disable?          boolean
  |     +--rw pit_max_size?            int32
  |     +--rw cs_max_size?             int32
  |     +--rw cs_reserved_app?         int32
  |     +--rw pit_dflt_lifetime_sec?   float
  |     +--rw pit_max_lifetime_sec?    float
  |     +--rw pit_min_lifetime_sec?    float
  +--ro hicn-state
     +--ro states
     |  +--ro pkts_processed?             uint64
     |  +--ro pkts_interest_count?        uint64
     |  +--ro pkts_data_count?            uint64
     |  +--ro pkts_from_cache_count?      uint64
     |  +--ro pkts_no_pit_count?          uint64
     |  +--ro pit_expired_count?          uint64
     |  +--ro cs_expired_count?           uint64
     |  +--ro cs_lru_count?               uint64
     |  +--ro pkts_drop_no_buf?           uint64
     |  +--ro interests_aggregated?       uint64
     |  +--ro interests_retx?             uint64
     |  +--ro interests_hash_collision?   uint64
     |  +--ro pit_entries_count?          uint64
     |  +--ro cs_entries_count?           uint64
     |  +--ro cs_entries_ntw_count?       uint64
     +--ro strategy
     |  +--ro description?   uint8
     +--ro route
     |  +--ro faceids?       uint16
     |  +--ro strategy_id?   uint32
     +--ro strategies
     |  +--ro n_strategies?   uint8
     |  +--ro strategy_id?    uint32
     +--ro face-ip-params
        +--ro nh_addr?   uint64
        +--ro swif?      uint32
        +--ro flags?     uint32


To setup the startup configuration you can use the following script:

EXIT_CODE=0
command -v sysrepocfg > /dev/null
if [ $? != 0 ]; then
    echo "Could not find command \"sysrepocfg\"."
     exit ${EXIT_CODE}
else
sysrepocfg -d startup -i path_to_startup_xml -f xml hicn
fi


startup.xml is placed under plugin/yang/. Here you can find the content:

<hicn-conf  xmlns="urn:sysrepo:hicn">
<params>
    <enable_disable>false</enable_disable>
    <pit_max_size>-1</pit_max_size>
    <cs_max_size>-1</cs_max_size>
    <cs_reserved_app>-1</cs_reserved_app>
    <pit_dflt_lifetime_sec>-1</pit_dflt_lifetime_sec>
    <pit_max_lifetime_sec>-1</pit_max_lifetime_sec>
    <pit_min_lifetime_sec>-1</pit_min_lifetime_sec>
</params>
</hicn-conf>

As can be seen, it contains the leaves of the params in hicn-conf node which is used as the startup configuration. This configuration can be changed through the controler by subscribing which changes the target to the running state. hicn yang model provides a list of RPCs which allows controler to communicate directly with the hicn-plugin. This RPCs may also cause the modification in state data. Here you can find the list of RPCs:

  rpcs:
    +---x node-params-set
    |  +---w input
    |     +---w enable_disable?          boolean
    |     +---w pit_max_size?            int32
    |     +---w cs_max_size?             int32
    |     +---w cs_reserved_app?         int32
    |     +---w pit_dflt_lifetime_sec?   float
    |     +---w pit_max_lifetime_sec?    float
    |     +---w pit_min_lifetime_sec?    float
    +---x node-params-get
    +---x node-stat-get
    +---x strategy-get
    |  +---w input
    |     +---w strategy_id?   uint32
    +---x strategies-get
    +---x route-get
    |  +---w input
    |     +---w prefix0?   uint64
    |     +---w prefix1?   uint64
    |     +---w len?       uint8
    +---x route-del
    |  +---w input
    |     +---w prefix0?   uint64
    |     +---w prefix1?   uint64
    |     +---w len?       uint8
    +---x route-nhops-add
    |  +---w input
    |     +---w prefix0?     uint64
    |     +---w prefix1?     uint64
    |     +---w len?         uint8
    |     +---w face_ids0?   uint32
    |     +---w face_ids1?   uint32
    |     +---w face_ids2?   uint32
    |     +---w face_ids3?   uint32
    |     +---w face_ids4?   uint32
    |     +---w face_ids5?   uint32
    |     +---w face_ids6?   uint32
    |     +---w n_faces?     uint8
    +---x route-nhops-del
    |  +---w input
    |     +---w prefix0?   uint64
    |     +---w prefix1?   uint64
    |     +---w len?       uint8
    |     +---w faceid?    uint16
    +---x face-ip-params-get
    |  +---w input
    |     +---w faceid?   uint16
    +---x face-ip-add
    |  +---w input
    |     +---w nh_addr0?   uint64
    |     +---w nh_addr1?   uint64
    |     +---w swif?       uint32
    +---x face-ip-del
    |  +---w input
    |     +---w faceid?   uint16
    +---x punting-add
    |  +---w input
    |     +---w prefix0?   uint64
    |     +---w prefix1?   uint64
    |     +---w len?       uint8
    |     +---w swif?      uint32
    +---x punting-del
       +---w input
          +---w prefix0?   uint64
          +---w prefix1?   uint64
          +---w len?       uint8
          +---w swif?      uint32


In order to run different RPCs from controler you can use the examples in the controler_rpcs_instances.xml under plugin/yang/. Here you can find the content:

<node-params-get xmlns="urn:sysrepo:hicn"/>

<node-stat-get xmlns="urn:sysrepo:hicn"/>

<strategy-get xmlns="urn:sysrepo:hicn">
    <strategy_id>0</strategy_id>
</strategy-get>

<strategies-get xmlns="urn:sysrepo:hicn"/>


<route-get xmlns="urn:sysrepo:hicn">
    <prefix0>10</prefix0>
    <prefix1>20</prefix1>
    <len>30</len>
</route-get>

<route-del xmlns="urn:sysrepo:hicn">
    <prefix0>10</prefix0>
    <prefix1>20</prefix1>
    <len>30</len>
</route-del>

<route-nhops-add xmlns="urn:sysrepo:hicn">
    <prefix0>10</prefix0>
    <prefix1>20</prefix1>
    <len>30</len>
    <face_ids0>40</face_ids0>
    <face_ids1>50</face_ids1>
    <face_ids2>60</face_ids2>
    <face_ids3>70</face_ids3>
    <face_ids4>80</face_ids4>
    <face_ids5>90</face_ids5>
    <face_ids6>100</face_ids6>
    <n_faces>110</n_faces>
</route-nhops-add>

<route-nhops-del xmlns="urn:sysrepo:hicn">
    <prefix0>10</prefix0>
    <prefix1>20</prefix1>
    <len>30</len>
    <faceid>40</faceid>
</route-nhops-del>


<face-ip-params-get xmlns="urn:sysrepo:hicn">
    <faceid>10</faceid>
</face-ip-params-get>

<face-ip-add xmlns="urn:sysrepo:hicn">
    <nh_addr0>10</nh_addr0>
    <nh_addr1>20</nh_addr1>
    <swif>30</swif>
</face-ip-add>

<face-ip-del xmlns="urn:sysrepo:hicn">
    <faceid>0</faceid>
</face-ip-del>

<punting-add xmlns="urn:sysrepo:hicn">
    <prefix0>10</prefix0>
    <prefix1>20</prefix1>
    <len>30</len>
    <swif>40</swif>
</punting-add>


<punting-del xmlns="urn:sysrepo:hicn">
    <prefix0>10</prefix0>
    <prefix1>20</prefix1>
    <len>30</len>
    <swif>40</swif>
</punting-del>


## Run the plugin

Firstly, verify the plugin and binary libraries are located correctly, then run the vpp through (service vpp start). Next, run the sysrepo daemon (sysrepod), for debug mode: sysrepo -d -l 4 which runs with high verbosity. Then, run the sysrepo plugin (sysrepo-plugind), for debug mode: sysrep-plugind -d -l 4 which runs with high verbosity. Now, the hicn sysrepo plugin is loaded. Then, run the netopeer2-server which serves as NETCONF server.

## Connect from netopeer2-cli

In order to connect through the netopeer client run the netopeer2-cli. Then, follow these steps:

connect --host XXX --login XXX
--> get (you can get the configuration and operational data)
--> get-config (you can get the configuratoin data)
--> edit-config --target running --config (you can modify the configuration but it needs an xml configuration input. For example,
<hicn-conf  xmlns="urn:sysrepo:hicn">
<params>
    <enable_disable>false</enable_disable>
    <pit_max_size>-1</pit_max_size>
    <cs_max_size>-1</cs_max_size>
    <cs_reserved_app>-1</cs_reserved_app>
    <pit_dflt_lifetime_sec>-1</pit_dflt_lifetime_sec>
    <pit_max_lifetime_sec>-1</pit_max_lifetime_sec>
    <pit_min_lifetime_sec>-1</pit_min_lifetime_sec>
</params>
</hicn-conf>
)
--> user-rpc (you can call one of the rpc proposed by hicn model but it needs an xml input, you can pick one in controler_rpcs_instances.xml)

## Connect from OpenDayligh (ODL) controller

In order to connect througt the OpenDaylight follow these procedure:

- run karaf distribution (./opendayligh_installation_folder/bin/karaf)
- install the required feature list in DOL (feature:install odl-netconf-server odl-netconf-connector odl-restconf-all odl-netconf-topology or
  odl-netconf-clustered-topology)
- run a rest client program (e.g., postman or RESTClient)
- mount the remote netopeer2-server to the OpenDaylight by the following REST API:

PUT http://localhost:8181/restconf/config/network-topology:network-topology/topology/topology-netconf/node/hicn-node

with the following body

 <node xmlns="urn:TBD:params:xml:ns:yang:network-topology">
   <node-id>hicn-node</node-id>
   <host xmlns="urn:opendaylight:netconf-node-topology">Remote_NETCONF_SERVER_IP</host>
   <port xmlns="urn:opendaylight:netconf-node-topology">830</port>
   <username xmlns="urn:opendaylight:netconf-node-topology">username</username>
   <password xmlns="urn:opendaylight:netconf-node-topology">password</password>
   <tcp-only xmlns="urn:opendaylight:netconf-node-topology">false</tcp-only>
   <keepalive-delay xmlns="urn:opendaylight:netconf-node-topology">1</keepalive-delay>
 </node>

Note that the header files must be set to Content-Type: application/xml, Accept: application/xml. There are more options which can be set but for simplicity we keep a short configuration to mount the remote node.

- send the operation through the following REST API:

POST http://localhost:8181/restconf/operations/network-topology:network-topology/topology/topology-netconf/node/hicn-node/yang-ext:mount/ietf-netconf:edit-config

The body can be used the same as edit-config in netopeer2-cli.

## Connect from Network Services Orchestrator (NSO)

To connect NSO to the netopeer2-server, first, you need to write a NED package for your device. The procudeure to create NED for hicn is explaned in the following:

Place hicn.yang model in a folder called hicn-yang-model, and follow these steps:

- ncs-make-package --netconf-ned ./hicn-yang-model ./hicn-nso
- cd hicn-nso/src; make
- ncs-setup --ned-package ./hicn-nso --dest ./hicn-nso-project
- cd hicn-nso-project
- ncs
- ncs_cli -C -u admin
- configure
- devices authgroups group authhicn default-map remote-name user_name remote-password password
- devices device hicn address IP_device port 830 authgroup authhicn device-type netconf
- state admin-state unlocked
- commit
- ssh fetch-host-keys

At this point, we are able to connect to the remote device.


## Release note

The current version is compatible with the 19.01 VPP stable and sysrepo 0.7.7.