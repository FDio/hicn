*** Settings ***
Resource            ../resources/libraries/robot/runtest.robot
Resource            ../resources/libraries/robot/common.robot

Suite Setup         Run Keywords
...                     Build Topology
...                     2-nodes
...                     vpp-memif-local-remote
...                     AND
...                     Check Environment
Suite Teardown      Run Keywords
...                     Destroy Topology


*** Test Cases ***
Test traffic received from local face is forwarded to remote face
    Log to console    Test traffic received from local face is forwarded to remote face
    ${result} =    Run Process    bash    -x    ${EXECDIR}/config.sh    localremote
    Log Many    ${result}
