#!/bin/bash

set -euo pipefail

trap "echo gnome-keyring FAILED" ERR

eval "$(dbus-launch --sh-syntax)"
eval "$(printf '\n' | gnome-keyring-daemon --unlock)"
eval "$(printf '\n' | /usr/bin/gnome-keyring-daemon --start)"

# test gnome-keyring roundtrip
printf "gnome-keyring OK" | secret-tool store --label="gnome-keyring-test" gnome-keyring-test success-msg
secret-tool lookup gnome-keyring-test success-msg

exec "$@"
