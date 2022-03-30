#!/bin/bash

set -e

DEV=$2
RATE=$3mbit
DELAY=$4ms
JITTER=$5ms
LOSS=$6

if [[ $1 -eq "set" ]]; then
    tc qdisc add dev "$DEV" root handle 1:0 htb default 1
    tc class add dev "$DEV" parent 1:0 classid 1:1 htb rate "$RATE"
    tc qdisc add dev "$DEV" parent 1:1 handle 2:0 netem delay "$DELAY"
    "$JITTER" loss random "$LOSS"
    echo "Dev: $DEV, rate: $RATE, delay: $DELAY, jitter: $JITTER, loss: $LOSS%"
elif [[ $1 -eq "change" ]]; then
    tc qdisc change dev "$DEV" parent 1:1 handle 2:0 netem delay "$DELAY" "$JITTER" loss random "$LOSS"
    echo "Dev: $DEV, rate: $RATE, delay: $DELAY, jitter: $JITTER, loss: $LOSS%"
else
    echo "set or change"
fi
