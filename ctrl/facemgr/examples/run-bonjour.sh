#!/bin/bash

# Notes for MacOS:
#
#  - Browse all discoverable services
#    dns-sd -B _services._dns-sd._udp local.
#
#  - Browse all hICN services
#    dns-sd -B _hicn._udp local.
#
#  - Lookup for specific options
#    dns-sd -L "hicn node" _hicn._udp local.
#
#  - Lookup addresses
#    dns-sd -G v4v6 adreena.local.
#
# NOTE: trailing dot '.' is optional

set -e

PORT=9695

#-------------------------------------------------------------------------------

FN_AVAHI_CFG_SRC=$SCRIPT_PATH/etc_avahi_services_hicn.service
FN_AVAHI_CFG=/etc/avahi/services/hicn.service

# https://unix.stackexchange.com/questions/265149/why-is-set-o-errexit-breaking-this-read-heredoc-expression
! read -r -d '' TPL_AVAHI_CFG <<-EOF
<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name>hicn node</name>
  <service>
    <type>_hicn._udp</type>
    <port>$PORT</port>
  </service>
</service-group>
EOF

#-------------------------------------------------------------------------------

# Reliably determine script's full path
SCRIPT_PATH="$( cd "$(dirname "$0")" ; pwd -P )"

# https://unix.stackexchange.com/questions/325594/script-a-test-for-installed-debian-package-error-handling
function pkg_is_installed()
{
    PKG="$1"
    LISTF=$(mktemp)
    dpkg-query -W -f '${Package} ${State}\n' >$LISTF
    grep "^${PKG} " $LISTF >/dev/null
    GREP_RC=$?
    rm $LISTF

    # for even moar strict error handling
    test $GREP_RC == 0 -o $GREP_RC == 1

    return $GREP_RC
}

# https://stackoverflow.com/questions/3466166/how-to-check-if-running-in-cygwin-mac-or-linux
function detect_os()
{
    unameOut="$(uname -s)"
    case "${unameOut}" in
        Linux*)     machine=linux;;
        Darwin*)    machine=mac;;
        CYGWIN*)    machine=cygwin;;
        MINGW*)     machine=mingw;;
        *)          machine=unknown;;
    esac
    echo ${machine}
}

function ensure_pkg_is_installed()
{
    PKG="$1"
    pkg_is_installed $PKG && return
    sudo apt install $PKG
}

function ensure_file_installed()
{
    SRC=$1
    DST=$2

    # Test whether destination exists and is up to date
    [ -s $DST ] && cmp -s $SRC $DST && return

    sudo cp $SRC $DST
}

function ensure_file_template()
{
    DST=$1
    TPL=$2

    echo "$TPL" | sudo tee $DST >/dev/null
}

function is_function()
{
    [ "$(type -t $1)" == "function" ]
}

function os_function()
{
    FUN=$1
    shift
    ARGS=$@

    OS=$(detect_os)
    if ! is_function ${FUN}_${OS}; then
        echo "Platform $OS not supported for $FUN [${FUN}_${OS}]"
        exit -1
    fi
    ${FUN}_${OS} $ARGS
}

#-------------------------------------------------------------------------------

# NOTE: debian only
function run_bonjour_server_linux()
{
    ensure_pkg_is_installed avahi-daemon
    #ensure_file_installed $FN_AVAHI_CFG_SRC $FN_AVAHI_CFG
    ensure_file_template  $FN_AVAHI_CFG "$TPL_AVAHI_CFG"
    sudo service avahi-daemon restart
    echo >&2, "Bonjour is now served through avahi"
}

function run_bonjour_server_mac()
{
    dns-sd -R hicn _hicn._tcp local $PORT
    # Proxy mode -P
}

function run_bonjour_client_linux()
{
    avahi-browse -ptr _hicn._udp
}

function run_bonjour_client_mac()
{
    dns-sd -B _hicn._udp local

}

# XXX function run_bonjour_proxy_linux() { }

function run_bonjour_proxy_mac()
{
    if [[ $# != 2 ]]; then
        echo "Usage: $0 proxy IP_ADDRESS"
        exit -1
    fi
    IP=$1
    dns-sd -P hicn _hicn._udp local $PORT hicn.local $IP path=/
}

#-------------------------------------------------------------------------------

case $1 in
    client)
        os_function run_bonjour_client
        ;;
    server)
        os_function run_bonjour_server
        ;;
    proxy)
        os_function run_bonjour_proxy $@
        ;;
    *)
        echo "$0 [client|server]"
        exit -1
        ;;
esac
