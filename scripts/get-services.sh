#Get status
systemctl show -p SubState --value cron
systemctl show -p MainPID --value cron


# Nginx
systemctl show -p MainPID -p SubState --value nginx
dpkg -s nginx

dpkg -s mariadb-server

processId=21314
usages=$(ps -p $processId -o %cpu,%mem | sed -n '2 p')
IFS=' ' read -a strarr <<< $usages
echo "This is cpu: ${strarr[0]}"
echo "This is mem: ${strarr[1]}"