*** Settings ***
Library                 Process
Test Template           Run Test
Test Setup              Setup
Test Teardown           Teardown
Test Timeout            5 seconds

*** Variables ***
${cmd}                  bash test_forwarder.sh

*** Test Cases ***
# Commands
Add listener                        test_add_listener
Remove listener                     test_remove_listener
Remove non-existing listener        test_remove_non_existing_listener
Add duplicated listener             test_add_duplicated_listener
List listeners                      test_list_listeners
Commands from config file           test_commands_from_config

# Ping
Ping one packet                     test_ping_one_packet
Ping two packets                    test_ping_two_packets
Ping using CS                       test_ping_using_cs
Ping using CS different order       test_ping_using_cs_different_order
Ping timeout                        test_ping_timeout
Ping aggregation                    test_ping_aggregation
Ping with CS store disabled         test_ping_with_cs_store_disabled
Ping with CS serve disabled         test_ping_with_cs_serve_disabled
Ping with eviction                  test_ping_with_eviction
Ping with zero data lifetime        test_ping_with_zero_data_lifetime

*** Keywords ***
Setup
  ${result}=  Run Process  ${cmd} set_up  shell=True
  Log Many  stdout: ${result.stdout}  stderr: ${result.stderr}

Teardown
  ${result}=  Run Process  ${cmd} tear_down  shell=True
  Log Many  stdout: ${result.stdout}  stderr: ${result.stderr}

Run Test
  [Arguments]  ${test_name}
  ${result}=  Run Process  ${cmd} ${test_name}  shell=True
  Log Many  stdout: ${result.stdout}  stderr: ${result.stderr}
  Should Be Equal As Integers  ${result.rc}  0