*** Settings ***
Resource          resources/libraries/robot/common.robot
Test Setup        Run Keywords
...               Build Topology                             1-node    AND
...               Check Environment
Test Teardown     Run Keywords
...               Destroy Topology

*** Test Cases ***
Listeners
  Log to console      Test listeners
  ${result} =         Run Process       ${EXECDIR}/config.sh    ctrl  listeners
  Log Many            stdout:           ${result.stdout}
  Should Be Equal As Integers   ${result.rc}        0
  Should Not Contain            ${result.stdout}    FAILED

Connections
  Log to console      Test connections
  ${result} =         Run Process       ${EXECDIR}/config.sh    ctrl  connections
  Log Many            stdout:           ${result.stdout}
  Should Be Equal As Integers   ${result.rc}        0
  Should Not Contain            ${result.stdout}    FAILED

Routes
  Log to console      Test routes
  ${result} =         Run Process       ${EXECDIR}/config.sh    ctrl  routes
  Log Many            stdout:           ${result.stdout}
  Should Be Equal As Integers   ${result.rc}        0
  Should Not Contain            ${result.stdout}    FAILED
