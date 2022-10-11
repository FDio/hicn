*** Settings ***
Resource            ../resources/libraries/robot/runtest.robot
Resource            ../resources/libraries/robot/common.robot

Suite Setup         Run Keywords
...                     Build Topology
...                     2-nodes
...                     vpp-memif-replication
...                     AND
...                     Check Environment
Suite Teardown      Run Keywords
...                     Destroy Topology


*** Test Cases ***
Throughput Testing Raaqm Server VPP memif replication
    Run Throughput Test Raaqm
    ...    2-nodes
    ...    vpp-memif-replication
    ...    500
    ...    500
    ...    500

Throughput Testing CBR Server VPP memif
    Run Throughput Test CBR
    ...    2-nodes
    ...    vpp-memif-replication
    ...    2000
    ...    2000
    ...    2000

RTC Testing Server VPP memif replication
    Run RTC Test
    ...    2-nodes
    ...    vpp-memif-replication
    ...    4
    ...    4
    ...    4

Latency Testing Server VPP memif replication
    Run Latency Test
    ...    2-nodes
    ...    vpp-memif-replication
    ...    3000
    ...    3000
    ...    3000
