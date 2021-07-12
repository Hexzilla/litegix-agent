#!/bin/bash


# Constants
EASY_CLOUD_URL="http://localhost:3600"
INSTALL_STATE_URL="$EASY_CLOUD_URL/api/installation/status"
INSTALL_PACKAGE="curl git wget expect nano build-essential openssl zip unzip make net-tools bc mariadb-server redis-server python-setuptools perl fail2ban augeas-tools libaugeas0 augeas-lenses firewalld acl memcached beanstalkd passwd unattended-upgrades postfix nodejs jq"

# Initialize
osname=$(lsb_release -si)
osversion=$(lsb_release -sr)
oscodename=$(lsb_release -sc)

############################################################
# Helpers
############################################################
function get_rand_string {
  tr -dc A-Za-z0-9 </dev/urandom | head -c 16
}

function send_state {
  state=$1
  curl --ipv4 --header "Content-Type: application/json" -X POST $INSTALL_STATE_URL -d '{"state": "'"$state"'"}'
  sleep 2
}

function throw_error {
  message=$1
  echo $message 1>&2
  curl --ipv4 --header "Content-Type: application/json" -X POST $INSTALL_STATE_URL -d '{"state": "err", "message": "'"$message"'"}' 
  exit 1
}


############################################################
# Checking
############################################################

# Check root user
if [[ $EUID -ne 0 ]]; then
  throw_error "This script must be run as root" 
fi

# Check OS Version
if [[ "$osname" != "Ubuntu" ]]; then
  throw_error "This script only support Ubuntu"
fi

# Check system architecture
if [[ $(uname -m) != "x86_64" ]]; then
  throw_error "This script only support x86_64 architecture"
fi

# Check OS Version
grep -q $osversion <<< "16.04 18.04 20.04"
if [[ $? -ne 0 ]]; then
  throw_error "This script does not support $osname $osversion"
fi



############################################################
# Installing
############################################################

# Install packages
send_state "packages"
function install_packages {
  apt-get update
  apt-get remove mysql-common --purge -y
  apt-get install $INSTALLPACKAGE -y
}
install_packages

# Fail2Ban
send_state "fail2ban"
function install_fail2Ban {

}
install_fail2Ban


################################################################################
# MariaDB
################################################################################
send_state "mariadb"
function install_mariadb {
  mkdir -p /tmp/lens
  curl --ipv4 $EASY_CLOUD_URL/files/lenses/augeas-mysql.aug --create-dirs -o /tmp/lens/mysql.aug 

  ROOTPASS=$(get_rand_string)

  # Start mariadb untuk initialize
  systemctl start mysql

  SECURE_MYSQL=$(expect -c "
set timeout 5
spawn mysql_secure_installation

expect \"Enter current password for root (enter for none):\"
send \"\r\"

expect \"Switch to unix_socket authentication\"
send \"y\r\"

expect \"Change the root password?\"
send \"y\r\"

expect \"New password:\"
send \"$ROOTPASS\r\"

expect \"Re-enter new password:\"
send \"$ROOTPASS\r\"

expect \"Remove anonymous users?\"
send \"y\r\"

expect \"Disallow root login remotely?\"
send \"y\r\"

expect \"Remove test database and access to it?\"
send \"y\r\"

expect \"Reload privilege tables now?\"
send \"y\r\"

expect eof
")
    echo "$SECURE_MYSQL"


#     /usr/bin/augtool -I /tmp/lens/ <<EOF
# set /files/etc/mysql/my.cnf/target[ . = "client" ]/user root
# set /files/etc/mysql/my.cnf/target[ . = "client" ]/password $ROOTPASS
# save
# EOF

/usr/bin/augtool -I /tmp/lens/ <<EOF
set /files/etc/mysql/my.cnf/target[ . = "client" ]/user root
set /files/etc/mysql/my.cnf/target[ . = "client" ]/password $ROOTPASS
set /files/etc/mysql/my.cnf/target[ . = "mysqld" ]/bind-address 0.0.0.0
set /files/etc/mysql/conf.d/mariadb.cnf/target[ . = "mysqld" ]/innodb_file_per_table 1
set /files/etc/mysql/conf.d/mariadb.cnf/target[ . = "mysqld" ]/max_connections 15554
set /files/etc/mysql/conf.d/mariadb.cnf/target[ . = "mysqld" ]/query_cache_size 80M
set /files/etc/mysql/conf.d/mariadb.cnf/target[ . = "mysqld" ]/query_cache_type 1
set /files/etc/mysql/conf.d/mariadb.cnf/target[ . = "mysqld" ]/query_cache_limit 2M
set /files/etc/mysql/conf.d/mariadb.cnf/target[ . = "mysqld" ]/query_cache_min_res_unit 2k
set /files/etc/mysql/conf.d/mariadb.cnf/target[ . = "mysqld" ]/thread_cache_size 60
save
EOF

echo "[client]
user=root
password=$ROOTPASS
" > /etc/mysql/conf.d/root.cnf

    chmod 600 /etc/mysql/conf.d/root.cnf
}
install_mariadb
