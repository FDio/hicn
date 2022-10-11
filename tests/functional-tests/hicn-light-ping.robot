*** Settings ***
Resource            ../resources/libraries/robot/common.robot

Test Setup          Run Keywords
...                     Build Topology
...                     1-node
...                     AND
...                     Check Environment
Test Teardown       Run Keywords
...                     Destroy Topology


*** Test Cases ***
Ping with manifest
    Log to console    Test ping with manifest
    ${result} =    Run Process    bash    -x    ${EXECDIR}/config.sh    ping    manifest
    Log Many    stdout:    ${result.stdout}
    Should Be Equal As Integers    ${result.rc}    0

Ping wrong signature
    Log to console    Test ping with wrong signature
    ${result} =    Run Process    bash    -x    ${EXECDIR}/config.sh    ping    signature
    Log Many    stdout:    ${result.stdout}
    Should Be Equal As Integers    ${result.rc}    0

Ping timeout
    Log to console    Test ping timeout
    ${result} =    Run Process    bash    -x    ${EXECDIR}/config.sh    ping    timeout
    Log Many    stdout:    ${result.stdout}
    Should Be Equal As Integers    ${result.rc}    0
