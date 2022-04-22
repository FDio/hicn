*** Settings ***
Library    OperatingSystem
Library    Process
Library    String

*** Variables ***

*** Keywords ***

Build Topology
    [Arguments]          ${TEST_TOPOLOGY}=${NONE}                                    ${TEST_CONFIGURATION}=${NONE}
    Log to console       Building topology ${TEST_TOPOLOGY} ${TEST_CONFIGURATION}
    ${result_setup} =    Run Process                                                 ${EXECDIR}/config.sh              build    setup    ${TEST_TOPOLOGY}    ${TEST_CONFIGURATION}
    Log to console       Done
    Log Many             stdout: ${result_setup.stdout}                              stderr: ${result_setup.stderr}
    Should Be Equal As Integers  ${result_setup.rc}  0

Check Environment
    ${result} =    Run Process                 docker                      ps
    Log Many       stdout: ${result.stdout}    stderr: ${result.stderr}

Destroy Topology
    ${result_teardown} =    Run Process                          ${EXECDIR}/config.sh                 stopall
    Log Many                stdout: ${result_teardown.stdout}    stderr: ${result_teardown.stderr}
    Should Be Equal As Integers     ${result_teardown.rc}  0
