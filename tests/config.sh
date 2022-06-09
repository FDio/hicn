#!/usr/bin/env bash

set -euo pipefail

SCRIPT_PATH=$(
  cd "$(dirname "${BASH_SOURCE}")"
  pwd -P
)

# Import test configurations and names
source ${SCRIPT_PATH}/.env

set -a
DOCKERFILE=${DOCKERFILE:-Dockerfile.dev}
BASE_IMAGE=${BASE_IMAGE:-hicn}
BUILD_SOFTWARE=${BUILD_SOFTWARE:-1}
set +a

HIPERF_CMD_RTC="hiperf -q -n 50 -C -H -R ${RTC_PRODUCER} -P 2"
HIPERF_CMD_MEMIF_RTC="${HIPERF_CMD_RTC} -z memif_module"
POSTPROCESS_COMMAND_RAAQM_RTC='tail -n +3 | \
  tr -s " " |                               \
  cut -f 4 -d " " |                         \
  sort -n |                                 \
  tail -n 40 |                              \
  head -n 35 |                              \
  awk "BEGIN {                              \
    c=0;                                    \
    s=0;                                    \
  }{                                        \
    a[n++]=\$1;                             \
    s+=\$1;                                 \
  } END {                                   \
    print int(a[0]), int(a[n-1]), int(s/n)  \
  }"'

HIPERF_CMD_RAAQM="hiperf -q -n 50 -i 200 -C -H ${RAAQM_PRODUCER}"
HIPERF_CMD_CBR="${HIPERF_CMD_RAAQM} -W 350 -M 0"
HIPERF_CMD_MEMIF_RAAQM="${HIPERF_CMD_RAAQM} -z memif_module"
HIPERF_CMD_MEMIF_CBR="${HIPERF_CMD_CBR} -z memif_module"

PING_CMD="hicn-ping-client -m 50 -i 200000 -n ${PING_PRODUCER}"
PING_CMD_MEMIF="${PING_CMD} -z memif_module"
POSTPROCESS_COMMAND_PING='grep trip |       \
  cut -f 4 -d " " |                         \
  sort -n |                                 \
  tail -n 40 |                              \
  head -n 35 |                              \
  awk "BEGIN {                              \
    c=0;                                    \
    s=0;                                    \
  }{                                        \
    a[n++]=\$1;                             \
    s+=\$1;                                 \
  } END {                                   \
    print int(a[0]), int(a[n-1]), int(s/n)  \
  }"'

declare -a topologies
declare -a configurations

# Fill topology array using the same values in the .env file
for topology in $(compgen -A variable | grep TOPOLOGY_); do
  topologies+=("${!topology}")
done

# Fill configurations array using the same values in the .env file
for test in $(compgen -A variable | grep TEST_); do
  configurations+=("${!test}")
done

declare -A tests=(
  ["hicn-light-rtc"]="${HIPERF_CMD_RTC} | tee >(>&2 cat) |  ${POSTPROCESS_COMMAND_RAAQM_RTC}"
  ["vpp-bridge-rtc"]="${HIPERF_CMD_MEMIF_RTC} | tee >(>&2 cat) | ${POSTPROCESS_COMMAND_RAAQM_RTC}"
  ["vpp-memif-rtc"]="${HIPERF_CMD_MEMIF_RTC} | tee >(>&2 cat) | ${POSTPROCESS_COMMAND_RAAQM_RTC}"
  ["vpp-memif-replication-rtc"]="${HIPERF_CMD_MEMIF_RTC} | tee >(>&2 cat) | ${POSTPROCESS_COMMAND_RAAQM_RTC}"

  ["hicn-light-requin"]="${HIPERF_CMD_RAAQM} | tee >(>&2 cat) | ${POSTPROCESS_COMMAND_RAAQM_RTC}"
  ["vpp-bridge-requin"]="${HIPERF_CMD_MEMIF_RAAQM} | tee >(>&2 cat) | ${POSTPROCESS_COMMAND_RAAQM_RTC}"
  ["vpp-memif-requin"]="${HIPERF_CMD_MEMIF_RAAQM} | tee >(>&2 cat) | ${POSTPROCESS_COMMAND_RAAQM_RTC}"
  ["vpp-memif-replication-requin"]="${HIPERF_CMD_MEMIF_RAAQM} | tee >(>&2 cat) | ${POSTPROCESS_COMMAND_RAAQM_RTC}"

  ["hicn-light-cbr"]="${HIPERF_CMD_CBR} | tee >(>&2 cat) |  ${POSTPROCESS_COMMAND_RAAQM_RTC}"
  ["vpp-bridge-cbr"]="${HIPERF_CMD_MEMIF_CBR} | tee >(>&2 cat) | ${POSTPROCESS_COMMAND_RAAQM_RTC}"
  ["vpp-memif-cbr"]="${HIPERF_CMD_MEMIF_CBR} | tee >(>&2 cat) | ${POSTPROCESS_COMMAND_RAAQM_RTC}"
  ["vpp-memif-replication-cbr"]="${HIPERF_CMD_MEMIF_CBR} | tee >(>&2 cat) | ${POSTPROCESS_COMMAND_RAAQM_RTC}"

  ["hicn-light-latency"]="${PING_CMD} | tee >(>&2 cat) |  ${POSTPROCESS_COMMAND_PING}"
  ["vpp-bridge-latency"]="${PING_CMD_MEMIF} | tee >(>&2 cat) | ${POSTPROCESS_COMMAND_PING}"
  ["vpp-memif-latency"]="${PING_CMD_MEMIF} | tee >(>&2 cat) | ${POSTPROCESS_COMMAND_PING}"
  ["vpp-memif-replication-latency"]="${PING_CMD_MEMIF} | tee >(>&2 cat) | ${POSTPROCESS_COMMAND_PING}"
)

declare -A link_model=(
  ["500-0-0-0"]="500 0 0 0"
  ["500-1-0-0"]="500 1 0 0"
  ["500-5-0-0"]="500 5 0 0"
  ["500-200-0-0"]="500 200 0 0"
  ["100-1-0-0"]="100 1 0 0"
  ["100-10-0-0"]="100 10 0 0"
  ["100-15-0-0"]="100 15 0 0"
  ["200-5-0-0"]="200 5 0 0"
  ["300-5-0-0"]="300 5 0 0"
  ["400-5-0-0"]="400 5 0 0"
  ["1000-1-0-0"]="1000 1 0 0"
  ["10-50-1-10"]="10 50 1 10"
)

function topology_exists() {
  [[ "${topologies[*]}" =~ ${1} ]] && return 0 || return 1
}

function test_exists() {
  [[ "${!tests[*]}" =~ ${1} ]] && return 0 || return 1
}

function conf_exists() {
  [[ "${configurations[*]}" =~ ${1} ]] && return 0 || return 1
}

# test-name client/server link-model
function setchannel() {
  if ! conf_exists "${1}"; then
    error "Error: topology does not exist."
  fi

  if ! test_exists "${1}"; then
    error "Error: test does not exist."
  fi
  docker exec "${1}-${2}" bash -c "/workspace/tests/config.sh link set br0\
                                                          ${link_model[${3}]}"
}
# test-name client/server link-model
function changechannel() {
  if ! conf_exists "${1}"; then
    error "Error: topology does not exist."
  fi

  if ! test_exists "${1}"; then
    error "Error: test does not exist."
  fi
  docker exec "${1}-${2}" bash -c "/workspace/tests/config.sh link change br0\
                                                          ${link_model[${3}]}"
}

# channel set/change dev rate delay jitter lossrate
function channel() {
  DEV=${2}
  RATE=${3}mbit
  DELAY=${4}ms
  JITTER=${5}ms
  LOSS=${6}
  if [[ $1 == set ]]; then
    sudo tc qdisc add dev "${DEV}" root handle 1:0 htb default 1
    sudo tc class add dev "${DEV}" parent 1:0 classid 1:1 htb rate "$RATE"
    sudo tc qdisc add dev "${DEV}" parent 1:1 handle 2:0 netem delay "${DELAY}" \
      "${JITTER}" loss random "${LOSS}"
    echo "Dev: ${DEV}, rate: ${RATE}, delay: ${DELAY}, jitter: ${JITTER}, loss: ${LOSS}%"
  elif [[ ${1} == change ]]; then
    sudo tc qdisc change dev "$DEV" parent 1:1 handle 2:0 netem delay "$DELAY" \
      "${JITTER}" loss random "${LOSS}"
    echo "Dev: ${DEV}, rate: ${RATE}, delay: ${DELAY}, jitter: ${JITTER}, loss: ${LOSS}%"
  else
    sudo tc qdisc del dev "${DEV}" root
    echo "set or change"
  fi
}
function error() {
  echo >&2 "${@}"
  return 1
}

function build() {
  docker-compose -f build.yml build
  docker-compose -f build.yml up --force-recreate --remove-orphans >/dev/null
}

function setup() {
  topology=${1}
  conf=${2}

  if ! topology_exists "${topology}"; then
    error "Error: topology does not exist."
  fi

  if [[ "${topology}" == "1-node" && "${conf}" == "None" ]]; then
    docker-compose -f "${topology}".yml build
    docker-compose -f "${topology}".yml up --remove-orphans --force-recreate -d

    sleep 1
    return
  fi

  if ! conf_exists "${conf}"; then
    error "Error: topology conf does not exist."
  fi

  docker-compose -f "${topology}".yml -f "${topology}-${conf}".yml build
  docker-compose -f "${topology}".yml -f "${topology}-${conf}".yml up --remove-orphans --force-recreate -d

  sleep 10
}

function start() {
  conf=${1}
  test=${2}

  if ! conf_exists "${conf}"; then
    error "Error: configuration does not exist."
  fi

  TESTNAME="${conf}-${test}"

  if ! test_exists "${TESTNAME}"; then
    error "Error: test does not exist."
  fi

  docker exec "${1}"-client bash -c "/workspace/tests/config.sh runtest ${tests[${TESTNAME}]}"
}

function stop() {
  topology="${1}"
  conf="${2}"

  if ! topology_exists "${topology}"; then
    error "Error: topology does not exist."
  fi

  if [[ "${topology}" == "1-node" && "${conf}" == "None" ]]; then
    docker-compose -f "${topology}".yml down || true
    return
  fi

  if ! conf_exists "${conf}"; then
    error "Error: tect configuration does not exist."
  fi

  LOG_FILE="${SCRIPT_PATH}/${topology}-${conf}.log"
  rm -f "${LOG_FILE}"
  docker-compose -f "${topology}".yml -f "${topology}-${conf}".yml down || true
}

function stopall() {
  for topology in "${topologies[@]}"; do
    for conf in "${configurations[@]}"; do
      stop "${topology}" "${conf}"
    done
  done
}

function runtest() {
  echo "${@}" | sudo -i
}

################################################################
# Test commands (hicn-light-control)
################################################################
INTERFACE="eth0"
ADDRESS="192.168.1.1"
LISTENER_NAME="udp0"
LISTENER_NAME_2="udp1"
CONN_NAME="conn0"
CONN_NAME_2="conn1"
PREFIX="b001::/16"
COST=1

#---------------------------------------------------------------
# Helpers
#---------------------------------------------------------------
function exec_command() {
  command=$1

  output=$(docker exec forwarder hicn-light-control $command 2>&1)
  echo "$output"
}

function assert_cmd_success() {
  command=$1
  output=$(exec_command "${command}")

  if [[ -z "$output" ]]; then
    echo "OK"
  else
    echo "FAILED"
    exit 0
  fi
}

function assert_cmd_failure() {
  command=$1
  output=$(exec_command "${command}")

  if [[ ! -z "$output" ]]; then
    echo "OK"
  else
    echo "FAILED"
    exit 0
  fi
}

#---------------------------------------------------------------
# Tests for listeners, connections, routes
#---------------------------------------------------------------
function test_listeners() {
  echo -n "Add listeners: "
  command="add listener udp $LISTENER_NAME $ADDRESS 9695 $INTERFACE"
  _=$(exec_command "${command}")
  command="add listener udp $LISTENER_NAME_2 127.0.0.1 12345 $INTERFACE"
  assert_cmd_success "${command}"

  echo -n "List listeners: "
  command="list listener"
  output=$(exec_command "${command}")

  if [[ "${output}" =~ "udp0 inet4://192.168.1.1:9695" &&
    "${output}" =~ "udp1 inet4://127.0.0.1:12345" &&
    "${output}" =~ "interface=lo" &&
    "${output}" =~ "interface=$INTERFACE" &&
    ! "${output}" =~ "ERROR" ]]; then
    echo "OK"
  else
    echo "FAILED"
    echo $output
    exit 0
  fi

  echo -n "Remove listener using symbolic: "
  command="remove listener $LISTENER_NAME"
  assert_cmd_success "${command}"

  echo -n "Remove listener using ID: "
  command="remove listener 2"
  assert_cmd_success "${command}"

  echo -n "Remove non-existing listener using symbolic: "
  command="remove listener $LISTENER_NAME_2"
  assert_cmd_failure "${command}"

  echo -n "Remove non-existing listener using ID: "
  command="remove listener 5"
  assert_cmd_failure "${command}"

  echo -n "Add duplicated listener (same symbolic): "
  command="add listener udp $LISTENER_NAME $ADDRESS 9695 $INTERFACE"
  _=$(exec_command "${command}")
  command="add listener udp $LISTENER_NAME 127.0.0.1 12345 $INTERFACE"
  assert_cmd_failure "${command}"

  echo -n "Add duplicated listener (same endpoints): "
  command="add listener udp $LISTENER_NAME $ADDRESS 9695 $INTERFACE"
  _=$(exec_command "${command}")
  command="add listener udp $LISTENER_NAME_2 $ADDRESS 9695 $INTERFACE"
  assert_cmd_failure "${command}"
}

function test_connections() {
  echo -n "Add connections: "
  command="add listener udp $LISTENER_NAME $ADDRESS 9695 $INTERFACE"
  _=$(exec_command "${command}")
  command="add connection udp $CONN_NAME $ADDRESS 9695 $ADDRESS 9695 $INTERFACE"
  _=$(exec_command "${command}")
  command="add connection udp $CONN_NAME_2 $ADDRESS 12345 $ADDRESS 9695 $INTERFACE"
  assert_cmd_success "${command}"

  echo -n "List connections: "
  command="list connection"
  output=$(exec_command "${command}")

  if [[ "${output}" =~ "inet4://192.168.1.1:12345" &&
    "${output}" =~ "inet4://192.168.1.1:9695" &&
    "${output}" =~ "conn0" && "${output}" =~ "conn1" &&
    ! "${output}" =~ "ERROR" ]]; then
    echo "OK"
  else
    echo "FAILED"
    echo $output
    exit 0
  fi

  echo -n "Remove connection using symbolic: "
  command="remove connection $CONN_NAME"
  assert_cmd_success "${command}"

  echo -n "Remove connection using ID: "
  command="remove connection 2"
  assert_cmd_success "${command}"

  echo -n "Remove non-existing connection using symbolic: "
  command="remove connection $CONN_NAME"
  assert_cmd_failure "${command}"

  echo -n "Remove non-existing connection using ID: "
  command="remove connection 5"
  assert_cmd_failure "${command}"

  echo -n "Add duplicated connection (same symbolic): "
  command="add connection udp $CONN_NAME $ADDRESS 9695 $ADDRESS 9695 $INTERFACE"
  _=$(exec_command "${command}")
  command="add connection udp $CONN_NAME $ADDRESS 9695 $ADDRESS 12345 $INTERFACE"
  assert_cmd_failure "${command}"

  # This case is allowed, success code is returned and symbolic is not updated
  echo -n "Add duplicated connection (different symbolic, same endpoints): "
  command="add connection udp $CONN_NAME_2 $ADDRESS 9695 $ADDRESS 9695 $INTERFACE"
  assert_cmd_success "${command}"
}

function test_routes() {
  echo -n "Add route: "
  command="add listener udp $LISTENER_NAME $ADDRESS 9695 $INTERFACE"
  _=$(exec_command "${command}")
  command="add connection udp $CONN_NAME $ADDRESS 9695 $ADDRESS 9695 $INTERFACE"
  _=$(exec_command "${command}")
  command="add route $CONN_NAME $PREFIX $COST"
  assert_cmd_success "${command}"

  echo -n "List routes: "
  command="list route"
  output=$(exec_command "${command}")

  if [[ "${output}" =~ "b001::" && "${output}" =~ "16" &&
    ! "${output}" =~ "ERROR" ]]; then
    echo "OK"
  else
    echo "FAILED"
    echo "$output"
    exit 0
  fi

  echo -n "Remove route using symbolic: "
  command="remove route $CONN_NAME $PREFIX"
  assert_cmd_success "${command}"

  echo -n "Remove route using ID: "
  command="add route $CONN_NAME $PREFIX $COST"
  _=$(exec_command "${command}")
  command="remove route 1 $PREFIX"
  assert_cmd_success "${command}"

  echo -n "Remove non-existing route using symbolic: "
  command="remove connection $CONN_NAME $PREFIX"
  assert_cmd_failure "${command}"

  echo -n "Remove non-existing route using ID: "
  command="remove route 5 $PREFIX"
  assert_cmd_failure "${command}"
}

declare -A ctrl_tests=(
  ["listeners"]="test_listeners"
  ["connections"]="test_connections"
  ["routes"]="test_routes"
)

function ctrl() {
  type=$1
  if [[ ! -v "ctrl_tests[${type}]" ]]; then
    error "Error: hicn-light-contrl test does not exist."
    exit 1
  fi

  ${ctrl_tests[${type}]}
}

while (("${#}")); do
  case "$1" in
  'build')
    build
    shift
    ;;
  'link')
    shift
    channel "$@"
    shift 6
    ;;
  'setchannel')
    shift
    setchannel "$@"
    shift 4
    ;;
  'changechannel')
    shift
    changechannel "$@"
    shift 4
    ;;
  'setup')
    setup "${2}" "${3}"
    shift 3
    ;;
  'start')
    start "${2}" "${3}"
    shift 3
    ;;
  'stop')
    stop "${2}" "${3}"
    shift 3
    ;;
  'stopall')
    stopall
    shift
    ;;
  'runtest')
    runtest "${@:2}"
    break
    ;;
  'ctrl')
    ctrl "${2}"
    break
    ;;
  *)
    exit 1
    ;;
  esac
done

exit 0
