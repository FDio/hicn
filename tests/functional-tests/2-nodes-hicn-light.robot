*** Settings ***
Resource          resources/libraries/robot/runtest.robot
Resource          resources/libraries/robot/common.robot
Suite Setup       Run Keywords
...               Build Topology                             2-nodes    hicn-light    AND
...               Check Environment
Suite Teardown    Run Keywords
...               Destroy Topology
Resource          resources/libraries/robot/runtest.robot

*** Test Cases ***

Throughput Testing Raaqm Mobile
    Run Throughput Test Raaqm    hicn-light    200    500    400

Throughput Testing CBR Mobile
    Run Throughput Test CBR    hicn-light    200    500    400

RTC Testing Mobile
    Run RTC Test    hicn-light    4    4    4

Latency Testing Mobile
    Set Link            hicn-light    500     1       0       0
    Run Latency Test    hicn-light    3000    3000    3000
