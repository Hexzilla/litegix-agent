#!/bin/bash
#
# Owned by RunCloud
# Usage without permission is prohibited


export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive
apt-get update > /dev/null 2>&1
unattended-upgrades
dpkg --force-confdef --force-confold --configure -a
apt-get install -f -y
unattended-upgrades
