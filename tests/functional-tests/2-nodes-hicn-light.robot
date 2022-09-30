*** Settings ***
Resource            ../resources/libraries/robot/runtest.robot
Resource            ../resources/libraries/robot/common.robot

Suite Setup         Run Keywords
...                     Build Topology
...                     2-nodes
...                     hicn-light
...                     AND
...                     Check Environment
Suite Teardown      Run Keywords
...                     Destroy Topology


*** Test Cases ***
Throughput Testing Raaqm Mobile
    Run Throughput Test Raaqm
    ...    2-nodes
    ...    hicn-light
    ...    200
    ...    500
    ...    400

Throughput Testing Raaqm Mobile New Packet Format
<<<<<<< HEAD
    Run Throughput Test Raaqm New Packet Format
    ...    2-nodes
    ...    hicn-light
    ...    200
    ...    500
    ...    400
=======
    Run Throughput Test Raaqm New Packet Format    hicn-light    200    500    400
>>>>>>> 030a054 (refactor(hicn-light): cleanup towards optimizations to UDP socket face)

Throughput Testing CBR Mobile
    Run Throughput Test CBR
    ...    2-nodes
    ...    hicn-light
    ...    20
    ...    500
    ...    400

Throughput Testing CBR Mobile New Packet Format
<<<<<<< HEAD
    Run Throughput Test CBR New Packet Format
    ...    2-nodes
    ...    hicn-light
    ...    200
    ...    500
    ...    400
=======
    Run Throughput Test CBR New Packet Format    hicn-light    200    500    400
>>>>>>> 030a054 (refactor(hicn-light): cleanup towards optimizations to UDP socket face)

RTC Testing Mobile
    Run RTC Test
    ...    2-nodes
    ...    hicn-light
    ...    4
    ...    4
    ...    4

Latency Testing Mobile
    Set Link
    ...    2-nodes
    ...    hicn-light
    ...    500
    ...    1
    ...    0
    ...    0
    Run Latency Test
    ...    2-nodes
    ...    hicn-light
    ...    3000
    ...    3000
    ...    3000

Latency Testing Mobile New Packet Format
<<<<<<< HEAD
    Set Link
    ...    2-nodes
    ...    hicn-light
    ...    500
    ...    1
    ...    0
    ...    0
    Run Latency Test New Packet Format
    ...    2-nodes
    ...    hicn-light
    ...    3000
    ...    3000
    ...    3000
=======
    Set Link                    hicn-light    500     1       0       0
    Run Latency Test New Packet Format        hicn-light    3000    3000    3000
>>>>>>> 030a054 (refactor(hicn-light): cleanup towards optimizations to UDP socket face)
