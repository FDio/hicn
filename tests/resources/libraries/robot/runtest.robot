*** Settings ***
Library     OperatingSystem
Library     Process
Library     String


*** Keywords ***
Infra ${VALUE}
    Run Process    ${EXECDIR}/config.sh    ${VALUE}

Run Test
    [Arguments]
    ...    ${TEST_TOPOLOGY}=${NONE}
    ...    ${TEST_SETUP}=${NONE}
    ...    ${TESTID}=${NONE}
    ...    ${EXPECTED_MIN}=${NONE}
    ...    ${EXPECTED_MAX}=${NONE}
    ...    ${EXPECTED_AVG}=${NONE}
    ${result_test} =    Run Process
    ...    ${EXECDIR}/config.sh
    ...    start
    ...    ${TEST_TOPOLOGY}
    ...    ${TEST_SETUP}
    ...    ${TESTID}
    ...    stdout=${TEMPDIR}/stdout.txt
    ...    stderr=${TEMPDIR}/stderr.txt
    Log Many    stdout: ${result_test.stdout}    stderr: ${result_test.stderr}
    ${min_max_avg_line} =    Get Line    ${result_test.stdout}    0
    @{min_max_avg} =    Split String    ${min_max_avg_line.strip()}
    Log To Console    Min Max Average Array: @{min_max_avg}
    IF    '${TESTID}' == 'rtc'
        Should Be True
        ...    ${min_max_avg}[0] == ${EXPECTED_MIN}
        ...    msg="Min does not match (${min_max_avg}[0] != ${EXPECTED_MIN})"
        Should Be True
        ...    ${min_max_avg}[1] == ${EXPECTED_MAX}
        ...    msg="Max does not match (${min_max_avg}[1] != ${EXPECTED_MAX})"
        Should Be True
        ...    ${min_max_avg}[2] == ${EXPECTED_AVG}
        ...    msg="Avg does not match (${min_max_avg}[2] != ${EXPECTED_AVG})"
    ELSE IF    '${TESTID}' == 'requin'
        Should Be True
        ...    ${min_max_avg}[0] >= ${EXPECTED_MIN}
        ...    msg="Min does not match (${min_max_avg}[0] < ${EXPECTED_MIN})"
        Should Be True
        ...    ${min_max_avg}[1] >= ${EXPECTED_MAX}
        ...    msg="Max does not match (${min_max_avg}[1] < ${EXPECTED_MAX})"
        Should Be True
        ...    ${min_max_avg}[2] >= ${EXPECTED_AVG}
        ...    msg="Avg does not match (${min_max_avg}[2] < ${EXPECTED_AVG})"
    ELSE IF    '${TESTID}' == 'requin-new-paket-format'
        Should Be True
        ...    ${min_max_avg}[0] >= ${EXPECTED_MIN}
        ...    msg="Min does not match (${min_max_avg}[0] < ${EXPECTED_MIN})"
        Should Be True
        ...    ${min_max_avg}[1] >= ${EXPECTED_MAX}
        ...    msg="Max does not match (${min_max_avg}[1] < ${EXPECTED_MAX})"
        Should Be True
        ...    ${min_max_avg}[2] >= ${EXPECTED_AVG}
        ...    msg="Avg does not match (${min_max_avg}[2] < ${EXPECTED_AVG})"
    ELSE IF    '${TESTID}' == 'latency'
        Should Be True
        ...    ${min_max_avg}[0] <= ${EXPECTED_MIN}
        ...    msg="Min does not match (${min_max_avg}[0] > ${EXPECTED_MIN})"
        Should Be True
        ...    ${min_max_avg}[1] <= ${EXPECTED_MAX}
        ...    msg="Max does not match (${min_max_avg}[1] > ${EXPECTED_MAX})"
        Should Be True
        ...    ${min_max_avg}[2] <= ${EXPECTED_AVG}
        ...    msg="Avg does not match (${min_max_avg}[2] > ${EXPECTED_AVG})"
    ELSE IF    '${TESTID}' == 'latency-new-paket-format'
        Should Be True
        ...    ${min_max_avg}[0] <= ${EXPECTED_MIN}
        ...    msg="Min does not match (${min_max_avg}[0] > ${EXPECTED_MIN})"
        Should Be True
        ...    ${min_max_avg}[1] <= ${EXPECTED_MAX}
        ...    msg="Max does not match (${min_max_avg}[1] > ${EXPECTED_MAX})"
        Should Be True
        ...    ${min_max_avg}[2] <= ${EXPECTED_AVG}
        ...    msg="Avg does not match (${min_max_avg}[2] > ${EXPECTED_AVG})"
    ELSE IF    '${TESTID}' == 'cbr'
        Should Be True
        ...    ${min_max_avg}[0] >= ${EXPECTED_MIN}
        ...    msg="Min does not match (${min_max_avg}[0] < ${EXPECTED_MIN})"
        Should Be True
        ...    ${min_max_avg}[1] >= ${EXPECTED_MAX}
        ...    msg="Max does not match (${min_max_avg}[1] < ${EXPECTED_MAX})"
        Should Be True
        ...    ${min_max_avg}[2] >= ${EXPECTED_AVG}
        ...    msg="Avg does not match (${min_max_avg}[2] < ${EXPECTED_AVG})"
    ELSE IF    '${TESTID}' == 'cbr-new-paket-format'
        Should Be True
        ...    ${min_max_avg}[0] >= ${EXPECTED_MIN}
        ...    msg="Min does not match (${min_max_avg}[0] < ${EXPECTED_MIN})"
        Should Be True
        ...    ${min_max_avg}[1] >= ${EXPECTED_MAX}
        ...    msg="Max does not match (${min_max_avg}[1] < ${EXPECTED_MAX})"
        Should Be True
        ...    ${min_max_avg}[2] >= ${EXPECTED_AVG}
        ...    msg="Avg does not match (${min_max_avg}[2] < ${EXPECTED_AVG})"
    ELSE
        Fail    "Provided Test ID does not exist"
    END

Set Link
    [Documentation]
    ...    Configure link rate/delay/jitter/loss
    ...    Arguments:
    ...    ${TEST_TOPOLOGY} The topology of the test.
    ...    ${RATE} Rate of the link
    ...    ${DELAY} Delay of the link
    ...    ${JITTER} Jitter of the link
    ...    ${LOSS} Loss of the link
    [Arguments]
    ...    ${TEST_TOPOLOGY}=${NONE}
    ...    ${TEST_SETUP}=${NONE}
    ...    ${RATE}=${NONE}
    ...    ${DELAY}=${NONE}
    ...    ${JITTER}=${NONE}
    ...    ${LOSS}=${NONE}
    ${result_link} =    Run Process
    ...    ${EXECDIR}/config.sh
    ...    setchannel
    ...    ${TEST_TOPOLOGY}
    ...    ${TEST_SETUP}
    ...    server
    ...    eth0
    ...    ${RATE}-${DELAY}-${JITTER}-${LOSS}
    Log Many    stdout: ${result_link.stdout}    stderr: ${result_link.stderr}

Run Latency Test
    [Documentation]
    ...    Run hicn-ping on the \${TEST_SETUP} topology and measure latency.
    ...    Arguments:
    ...    ${TEST_TOPOLOGY} The topology of the test.
    ...    ${TEST_SETUP} The setup of the test.
    ...    ${EXPECTED_MIN} The expected min latency
    ...    ${EXPECTED_MAX} The expected max latency
    ...    ${EXPECTED_AVG} The expected avg latency
    [Arguments]
    ...    ${TEST_TOPOLOGY}=${NONE}
    ...    ${TEST_SETUP}=${NONE}
    ...    ${EXPECTED_MIN}=${NONE}
    ...    ${EXPECTED_MAX}=${NONE}
    ...    ${EXPECTED_AVG}=${NONE}
    Run Test
    ...    ${TEST_TOPOLOGY}
    ...    ${TEST_SETUP}
    ...    latency
    ...    ${EXPECTED_MIN}
    ...    ${EXPECTED_MAX}
    ...    ${EXPECTED_AVG}

Run Throughput Test Raaqm
    [Documentation]
    ...    Run hiperf on the \${TEST_TOPOLOGY}-\${TEST_SETUP} topology
    ...    and measure throughput.
    ...    Arguments:
    ...    ${TEST_TOPOLOGY} The topology of the test.
    ...    ${TEST_SETUP} The setup of the test.
    ...    ${EXPECTED_MIN} The expected min throughput
    ...    ${EXPECTED_MAX} The expected max throughput
    ...    ${EXPECTED_AVG} The expected avg throughput
    [Arguments]
    ...    ${TEST_TOPOLOGY}=${NONE}
    ...    ${TEST_SETUP}=${NONE}
    ...    ${EXPECTED_MIN}=${NONE}
    ...    ${EXPECTED_MAX}=${NONE}
    ...    ${EXPECTED_AVG}=${NONE}
    Run Test
    ...    ${TEST_TOPOLOGY}
    ...    ${TEST_SETUP}
    ...    requin
    ...    ${EXPECTED_MIN}
    ...    ${EXPECTED_MAX}
    ...    ${EXPECTED_AVG}

Run Throughput Test Raaqm New Packet Format
    [Documentation]
    ...    Run hiperf on the \${TEST_SETUP} topology and measure throughput.
    ...    Arguments:
    ...    ${TEST_TOPOLOGY} The topology of the test.
    ...    ${TEST_SETUP} The setup of the test.
    ...    ${EXPECTED_MIN} The expected min throughput
    ...    ${EXPECTED_MAX} The expected max throughput
    ...    ${EXPECTED_AVG} The expected avg throughput
    [Arguments]
    ...    ${TEST_TOPOLOGY}=${NONE}
    ...    ${TEST_SETUP}=${NONE}
    ...    ${EXPECTED_MIN}=${NONE}
    ...    ${EXPECTED_MAX}=${NONE}
    ...    ${EXPECTED_AVG}=${NONE}
    Run Test
    ...    ${TEST_TOPOLOGY}
    ...    ${TEST_SETUP}
    ...    requin-new-paket-format
    ...    ${EXPECTED_MIN}
    ...    ${EXPECTED_MAX}
    ...    ${EXPECTED_AVG}

Run Throughput Test CBR
    [Documentation]
    ...    Run hiperf on the \${TEST_SETUP} topology and measure throughput.
    ...    Arguments:
    ...    ${TEST_TOPOLOGY} The topology of the test.
    ...    ${TEST_SETUP} The setup of the test.
    ...    ${EXPECTED_MIN} The expected min throughput
    ...    ${EXPECTED_MAX} The expected max throughput
    ...    ${EXPECTED_AVG} The expected avg throughput
    [Arguments]
    ...    ${TEST_TOPOLOGY}=${NONE}
    ...    ${TEST_SETUP}=${NONE}
    ...    ${EXPECTED_MIN}=${NONE}
    ...    ${EXPECTED_MAX}=${NONE}
    ...    ${EXPECTED_AVG}=${NONE}
    Run Test
    ...    ${TEST_TOPOLOGY}
    ...    ${TEST_SETUP}
    ...    cbr
    ...    ${EXPECTED_MIN}
    ...    ${EXPECTED_MAX}
    ...    ${EXPECTED_AVG}

Run Throughput Test CBR New Packet Format
    [Documentation]
    ...    Run hiperf on the \${TEST_SETUP} topology and measure throughput.
    ...    Arguments:
    ...    ${TEST_TOPOLOGY} The topology of the test.
    ...    ${TEST_SETUP} The setup of the test.
    ...    ${EXPECTED_MIN} The expected min throughput
    ...    ${EXPECTED_MAX} The expected max throughput
    ...    ${EXPECTED_AVG} The expected avg throughput
    [Arguments]
    ...    ${TEST_TOPOLOGY}=${NONE}
    ...    ${TEST_SETUP}=${NONE}
    ...    ${EXPECTED_MIN}=${NONE}
    ...    ${EXPECTED_MAX}=${NONE}
    ...    ${EXPECTED_AVG}=${NONE}
    Run Test
    ...    ${TEST_TOPOLOGY}
    ...    ${TEST_SETUP}
    ...    cbr-new-paket-format
    ...    ${EXPECTED_MIN}
    ...    ${EXPECTED_MAX}
    ...    ${EXPECTED_AVG}

Run RTC Test
    [Documentation]
    ...    Run hiperf RTC on the \${TEST_SETUP} topology and check consumer syncs to
    ...    producer bitrate.
    ...    Arguments:
    ...    ${TEST_TOPOLOGY} The topology of the test.
    ...    ${TEST_SETUP} The setup of the test.
    ...    ${EXPECTED_MIN} The expected min bitrate
    ...    ${EXPECTED_MAX} The expected max bitrate
    ...    ${EXPECTED_AVG} The expected avg bitrate
    [Arguments]
    ...    ${TEST_TOPOLOGY}=${NONE}
    ...    ${TEST_SETUP}=${NONE}
    ...    ${EXPECTED_MIN}=${NONE}
    ...    ${EXPECTED_MAX}=${NONE}
    ...    ${EXPECTED_AVG}=${NONE}
    Run Test
    ...    ${TEST_TOPOLOGY}
    ...    ${TEST_SETUP}
    ...    rtc
    ...    ${EXPECTED_MIN}
    ...    ${EXPECTED_MAX}
    ...    ${EXPECTED_AVG}

Run Latency Test New Packet Format
    [Documentation]
    ...    Run hicn-ping on the \${TEST_SETUP} topology with the new
    ...    packet format and measure latency.
    ...    Arguments:
    ...    ${TEST_TOPOLOGY} The topology of the test.
    ...    ${TEST_SETUP} The setup of the test.
    ...    ${EXPECTED_MIN} The expected min latency
    ...    ${EXPECTED_MAX} The expected max latency
    ...    ${EXPECTED_AVG} The expected avg latency
    [Arguments]
    ...    ${TEST_TOPOLOGY}=${NONE}
    ...    ${TEST_SETUP}=${NONE}
    ...    ${EXPECTED_MIN}=${NONE}
    ...    ${EXPECTED_MAX}=${NONE}
    ...    ${EXPECTED_AVG}=${NONE}
    Run Test
    ...    ${TEST_TOPOLOGY}
    ...    ${TEST_SETUP}
    ...    latency-new-paket-format
    ...    ${EXPECTED_MIN}
    ...    ${EXPECTED_MAX}
    ...    ${EXPECTED_AVG}
