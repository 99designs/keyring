#!/bin/bash

set -euo pipefail

trap "echo gnome-keyring unlock failed" ERR

eval "$(dbus-launch --sh-syntax)"
eval "$(printf '\n' | gnome-keyring-daemon --unlock)"

# test gnome-keyring roundtrip
printf "gnome-keyring unlocked" | secret-tool store --label="gnome-keyring-test" gnome-keyring-test success-msg
secret-tool lookup gnome-keyring-test success-msg
secret-tool clear gnome-keyring-test success-msg

exec "$@"
