#! /bin/bash

saveCurrent() {
    grep 'cpu ' /proc/stat > /home/litegix/.litegix/.cpu
}

[ ! -e /home/litegix/.litegix/.cpu ] && saveCurrent

previous=$(cat /home/litegix/.litegix/.cpu)
current=$(grep 'cpu ' /proc/stat)

awkscript='NR == 1 {
             owork=($2+$4);
             oidle=$5;
           }
           NR > 1 {
             work=($2+$4)-owork;
             idle=$5-oidle;
             printf "%.1f", 100 * work / (work+idle)
           }'

usage=$(echo -e "$previous\n$current" | awk "$awkscript")

CPU=$usage
MEMORY=$(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2 }')
DISK=$(df -h | awk '$NF=="/"{printf "%s", $5}')
LOADAVG=$(top -bn1 | grep load | awk '{printf "%.2f%%", $(NF-2)}')

SLEEPTIME=$[ ( $RANDOM % 40 )  + 1 ]s
sleep $SLEEPTIME

curl --max-time 15 --connect-timeout 60 --silent "http://95.217.190.94/api/agent/60d6cd3deaea5f2a73871010/monitor/state" \
-H "Accept: application/json" \
-H "Content-Type:application/json" \
--data @<(cat <<EOF
    {
      "memory": "$MEMORY",
      "cpu": "$CPU",
      "disk":"$DISK",
      "loadavg": "$LOADAVG"
    }
EOF
)

saveCurrent
