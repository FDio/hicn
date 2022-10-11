*** Settings ***
Resource            ../resources/libraries/robot/runtest.robot
Resource            ../resources/libraries/robot/common.robot

Suite Setup         Run Keywords
...                     Build Topology
...                     2-nodes
...                     vpp-bridge
...                     AND
...                     Check Environment
Suite Teardown      Run Keywords
...                     Destroy Topology


*** Test Cases ***
Throughput Testing Raaqm Server VPP bridge
    Run Throughput Test Raaqm
    ...    2-nodes
    ...    vpp-bridge
    ...    500
    ...    500
    ...    500

Throughput Testing CBR Server VPP bridge
    Run Throughput Test CBR
    ...    2-nodes
    ...    vpp-bridge
    ...    1000
    ...    1300
    ...    1200

RTC Testing Server VPP bridge
    Run RTC Test
    ...    2-nodes
    ...    vpp-bridge
    ...    4
    ...    4
    ...    4

Latency Testing Server VPP bridge
    Set Link
    ...    2-nodes
    ...    hicn-light
    ...    500
    ...    1
    ...    0
    ...    0
    Run Latency Test
    ...    2-nodes
    ...    vpp-bridge
    ...    3000
    ...    3000
    ...    3000
