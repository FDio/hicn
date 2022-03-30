#!/bin/bash

############################################################################
#                               CONSTANTS
############################################################################
INTERFACE_CMD="ip route get 1 | grep -Po '(?<=(dev )).*(?= src| proto)'"
ADDRESS_CMD="ip route get 1 | sed -n '/src/{s/.*src *\([^ ]*\).*/\1/p;q}'"
CTRL_CMD="docker exec test-hicn     \
                /hicn-build/build/build-root/bin/hicn-light-control"
PING_SERVER_CMD="docker exec -d test-hicn   \
                    /hicn-build/build/build-root/bin/hicn-ping-server \
                    -z hicnlightng_module"
PING_CLIENT_CMD="docker exec test-hicn     \
                    /hicn-build/build/build-root/bin/hicn-ping-client \
                    -z hicnlightng_module"
PING_CLIENT_DETACHED_CMD="docker exec -d test-hicn     \
                    /hicn-build/build/build-root/bin/hicn-ping-client \
                    -z hicnlightng_module"
LISTENER_NAME="udp0"
CONN_NAME="conn0"
PREFIX="c001::/64"
COST=1
FIVE_SECONDS=5000

############################################################################
#                                   UTILS
############################################################################
set_up() {
  docker build -t hicn-dev .
  run_forwarder
}

tear_down() {
  docker stop --time 0 test-hicn
}

get_address() {
  echo $(docker exec test-hicn sh -c "${ADDRESS_CMD}")
}

get_interface() {
  echo $(docker exec test-hicn sh -c "${INTERFACE_CMD}")
}

#---------------------------------------------------------------------------
# Exec
#---------------------------------------------------------------------------
run_forwarder() {
  capacity=${1:-"100000"}
  loglevel=${2:-"trace"}
  config=${3:-""}

  config_file_arg=""
  if [[ $config != "" ]]; then
    config_file_arg="--config ${config}"
  fi

  docker run --rm -d --name test-hicn \
    -v $(pwd)/..:/hicn-build \
    -e LD_LIBRARY_PATH=/hicn-build/build/build-root/lib \
    hicn-dev \
    /hicn-build/build/build-root/bin/hicn-light-daemon \
    --log ${loglevel} --capacity ${capacity} $config_file_arg
}

exec_controller() {
  command=$1

  # Redirect stderr to stdout
  output=$(${CTRL_CMD} ${command} 2>&1)
  assert_exit_code
  echo ${output}
}

exec_ping_server() {
  data_lifetime=${1:-""}

  lifetime_arg=""
  if [[ $data_lifetime != "" ]]; then
    lifetime_arg="-l ${data_lifetime}"
  fi

  ${PING_SERVER_CMD} ${lifetime_arg}
}

exec_ping_client() {
  num_packets=$1

  output=$(${PING_CLIENT_CMD} -m ${num_packets})
  assert_exit_code
  echo ${output}
}

exec_ping_client_detached() {
  num_packets=$1
  interest_lifetime=$2

  ${PING_CLIENT_DETACHED_CMD} -m ${num_packets} -l ${interest_lifetime}
}

#---------------------------------------------------------------------------
# Asserts
#---------------------------------------------------------------------------
assert_exit_code() {
  if [[ $? -ne 0 ]]; then
    exit_with_failure
  fi
}

assert_forwarder() {
  # Print forwarder logs for debug info
  echo "******** Forwarder Logs ********"
  docker logs test-hicn
  echo "********************************"

  output=$(docker logs test-hicn)
  if [[ $output == "" ]]; then
    exit_with_failure
  fi

  if [[ "${output}" == *"ERROR"* ]]; then
    exit_with_failure
  fi

  if [[ "${output}" == *"Aborted (core dumped)"* ]]; then
    exit_with_failure
  fi
}

assert_ack() {
  # Print controller logs for debug info
  echo "******** Controller Logs ********"
  echo $1
  echo "********************************"

  output=$1

  if [[ "$output" == *"Error"* ]]; then
    exit_with_failure
  fi
}

assert_nack() {
  # Print controller logs for debug info
  echo "******** Controller Logs ********"
  echo $1
  echo "********************************"

  output=$1

  if [[ "$output" != *"Error"* ]]; then
    exit_with_failure
  fi
}

assert_ping_client() {
  # Print ping client logs for debug info
  echo "******** Ping Client Logs ********"
  echo $1
  echo "********************************"

  ping_client_output=$1
  pkts_sent=$2
  pkts_recv=$3
  pkts_timeout=$4

  match_str="Sent: ${pkts_sent} Received: ${pkts_recv} Timeouts: ${pkts_timeout}"
  if [[ ! ${ping_client_output} == *"${match_str}"* ]]; then
    exit_with_failure
  fi
}

assert_forwarder_stats() {
  satisfied_from_cs=${1:-""}
  no_route_in_fib=${2:-""}
  aggregated=${3:-""}

  fwder_stats=$(docker logs test-hicn | grep "Forwarder: received" | tail -n 1)

  if [[ $satisfied_from_cs != "" &&
    "${fwder_stats}" != *"satisfied_from_cs = ${satisfied_from_cs}"* ]]; then
    exit_with_failure
  fi

  if [[ $no_route_in_fib != "" &&
    "${fwder_stats}" != *"no_route_in_fib = ${no_route_in_fib}"* ]]; then
    exit_with_failure
  fi

  if [[ $aggregated != "" &&
    "${fwder_stats}" != *"aggregated = ${aggregated}"* ]]; then
    exit_with_failure
  fi
}

assert_pkt_cache_stats() {
  total_size=${1:-""}
  pit_size=${2:-""}
  cs_size=${3:-""}

  pkt_cache_stats=$(docker logs test-hicn | grep "Packet cache:" | tail -n 1)

  if [[ $total_size != "" &&
    "${pkt_cache_stats}" != *"total size = ${total_size}"* ]]; then
    exit_with_failure
  fi

  if [[ $pit_size != "" &&
    "${pkt_cache_stats}" != *"PIT size = ${pit_size}"* ]]; then
    exit_with_failure
  fi

  if [[ $cs_size != "" &&
    "${pkt_cache_stats}" != *"CS size = ${cs_size}"* ]]; then
    exit_with_failure
  fi
}

assert_cs_stats() {
  evictions=${1:-""}

  cs_stats=$(docker logs test-hicn | grep "Content store:" | tail -n 1)

  if [[ $evictions != "" &&
    "${cs_stats}" != *"evictions = ${evictions}"* ]]; then
    exit_with_failure
  fi
}

############################################################################
#                                TEST SUITE
############################################################################

#---------------------------------------------------------------------------
# Commands
#---------------------------------------------------------------------------
test_add_listener() {
  # Exec hicn-light-control command and capture its output
  INTERFACE=$(get_interface)
  ADDRESS=$(get_address)
  command="add listener udp ${LISTENER_NAME} ${ADDRESS} 9695 ${INTERFACE}"
  ctrl_output=$(exec_controller "${command}")

  # Check hicn-light-control and hicn-light-daemon outputs
  assert_ack "$ctrl_output"
  assert_forwarder
}

test_remove_listener() {
  INTERFACE=$(get_interface)
  ADDRESS=$(get_address)
  command="add listener udp ${LISTENER_NAME} ${ADDRESS} 9695 ${INTERFACE}"
  ctrl_output=$(exec_controller "${command}")
  assert_ack "$ctrl_output"

  command="remove listener udp0"
  ctrl_output=$(exec_controller "${command}")

  assert_ack "$ctrl_output"
  assert_forwarder
}

test_remove_non_existing_listener() {
  command="remove listener udp0"
  ctrl_output=$(exec_controller "${command}")

  assert_nack "$ctrl_output"
  assert_forwarder
}

test_add_duplicated_listener() {
  # Exec hicn-light-control command and capture its output
  INTERFACE=$(get_interface)
  ADDRESS=$(get_address)
  command="add listener udp ${LISTENER_NAME} ${ADDRESS} 9695 ${INTERFACE}"
  exec_controller "${command}"
  ctrl_output=$(exec_controller "${command}")

  # Check hicn-light-control and hicn-light-daemon outputs
  assert_nack "$ctrl_output"
  assert_forwarder
}

test_list_listeners() {
  # Exec hicn-light-control command and capture its output
  command="list listener"
  ctrl_output=$(exec_controller "${command}")

  # Check hicn-light-control and hicn-light-daemon outputs
  assert_forwarder
  # Only the local listener should be present
  [[ "${ctrl_output}" =~ "inet4://127.0.0.1:9695" ]] && return 0 || exit_with_failure
}

test_commands_from_config() {
  # Create config file
  INTERFACE=$(get_interface)
  ADDRESS=$(get_address)
  echo "# Teset config file
    add listener udp $LISTENER_NAME $ADDRESS 9695 ${INTERFACE}
    add connection udp $CONN_NAME $ADDRESS 12345 $ADDRESS 9695 ${INTERFACE}
    add route $CONN_NAME $PREFIX $COST
    set strategy c001::/64 random
  " >forwarder.conf

  # Restart the forwarder specifying the config file
  tear_down
  run_forwarder "" "" "/hicn-build/tests/forwarder.conf"
  rm forwarder.conf

  # Check for errors in the output
  assert_forwarder
}

#---------------------------------------------------------------------------
# Ping
#---------------------------------------------------------------------------
test_ping_one_packet() {
  # Exec hicn-ping-server
  exec_ping_server
  # Exec hicn-ping-client (w/ 1 packet) and capture its output
  output=$(exec_ping_client 1)

  # Check hicn-ping-client (1 pkt sent, 1 pkt received, 0 timeouts)
  # and hicn-light-daemon outputs
  assert_ping_client "${output}" 1 1 0
  assert_forwarder
}

test_ping_two_packets() {
  exec_ping_server
  output=$(exec_ping_client 2)

  assert_ping_client "${output}" 2 2 0
  assert_forwarder
}

test_ping_using_cs() {
  exec_ping_server
  exec_ping_client 2
  output=$(exec_ping_client 1)

  assert_ping_client "${output}" 1 1 0
  assert_forwarder
  assert_forwarder_stats 1
}

test_ping_using_cs_different_order() {
  exec_ping_server
  exec_ping_client 1
  output=$(exec_ping_client 2)

  assert_ping_client "${output}" 2 2 0
  assert_forwarder
  assert_forwarder_stats 1
}

test_ping_timeout() {
  # Send ping without the ping server being run
  output=$(exec_ping_client 1)

  assert_ping_client "${output}" 1 0 1
  assert_forwarder
  assert_forwarder_stats 0 1
}

test_ping_aggregation() {
  # Send ping without server, waiting for a reply
  exec_ping_client_detached 1 ${FIVE_SECONDS}
  exec_ping_server
  # This new ping interest will be aggregated with the previous one
  # and the forwarder will reply to both ping clients
  output=$(exec_ping_client 1)

  assert_ping_client "${output}" 1 1 0
  assert_forwarder
  assert_forwarder_stats "" "" 1
}

test_ping_with_cs_store_disabled() {
  command="store cache off"
  exec_controller "${command}"

  exec_ping_server
  exec_ping_client 1
  output=$(exec_ping_client 1)

  assert_ping_client "${output}" 1 1 0
  assert_forwarder
  assert_forwarder_stats 0 "" ""
  # The packet is not stored in the CS
  assert_pkt_cache_stats "" "" 0
}

test_ping_with_cs_serve_disabled() {
  command="serve cache off"
  exec_controller "${command}"

  exec_ping_server
  exec_ping_client 1
  output=$(exec_ping_client 1)

  assert_ping_client "${output}" 1 1 0
  assert_forwarder
  assert_forwarder_stats 0 "" ""
  # The packet is stored in the CS, but CS is not used
  assert_pkt_cache_stats "" "" 1
}

test_ping_with_eviction() {
  # Restart the forwarder with CS capacity = 1
  tear_down
  run_forwarder 1

  exec_ping_server
  exec_ping_client 1
  output=$(exec_ping_client 2)

  assert_ping_client "${output}" 2 2 0
  assert_forwarder
  # Check if eviction happened
  assert_cs_stats 1
  assert_pkt_cache_stats "" "" 1
}

test_ping_with_zero_data_lifetime() {
  exec_ping_server 0
  exec_ping_client 1
  output=$(exec_ping_client 1)

  assert_ping_client "${output}" 1 1 0
  assert_forwarder
  # The data is not taken from the CS because expired
  assert_forwarder_stats 0 "" ""
}

"$@"
