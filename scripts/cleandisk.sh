#!/bin/bash
#
# Owned by RunCloud
# Usage without permission is prohibited

# Clean the log rotated log
rm /var/log/*.log.* > /dev/null 2>&1
rm /var/log/*.gz > /dev/null 2>&1
rm /var/log/apt/*.log.* > /dev/null 2>&1
rm /var/log/redis/*.log.* > /dev/null 2>&1
rm /var/log/unattended-upgrades/*.log.* > /dev/null 2>&1
rm /home/*/logs/apache2/*.gz > /dev/null 2>&1
rm /home/*/logs/nginx/*.gz > /dev/null 2>&1

# Truncate web app log
for log in `ls /home/*/logs/nginx/*`; do
    echo '' > $log
done

for log in `ls /home/*/logs/apache2/*`; do
    echo '' > $log
done

# clean apt
apt-get clean -y > /dev/null 2>&1
apt-get autoclean -y > /dev/null 2>&1
apt-get autoremove --purge -y > /dev/null 2>&1

# check mysql is running
pgrep mysqld
if [ $? -eq 0 ]; then
    # Delete mysql bin log
    /usr/bin/mysql -e "PURGE BINARY LOGS BEFORE DATE(NOW() - INTERVAL 3 DAY) + INTERVAL 0 SECOND"
