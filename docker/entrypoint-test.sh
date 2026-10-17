#!/bin/sh
# Start sshd so there is a real listener to find, then run the whole suite.
set -eu
/usr/sbin/sshd
exec python3 -m pytest -q -p no:cacheprovider "$@"
