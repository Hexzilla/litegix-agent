#!/bin/bash

webserver=$1
php=$2
database=$3
echo "[Agent] Webserver: $webserver"
echo "[Agent] PHP: $php"
echo "[Agent] Database: $database"

echo "[Agent] updating all system packages"
#sudo apt update -qq



#############################################################################
# Install Nginx
#############################################################################
echo "[Agent] checking nginx installed or not"
result=$(sudo apt -qq list nginx 2>/dev/null)
#echo $result
installed="false"
if [[ $result == *installed* ]] # * is used for pattern matching
then
  installed="true"
fi

if [[ $installed == "true" ]]
then
  echo "[Agent] nginx is already installed"
else
  echo "[Agent] installing nginx webserver"
  sudo apt install -qq --yes nginx
fi

echo "[Agent] Adjusting the Firewall"
sudo ufw allow 'Nginx Full'


#############################################################################
# Install MySQL 5.7
#############################################################################
export DEBIAN_FRONTEND=noninteractive
MYSQL_ROOT_PASSWORD='root'

# Install MySQL
echo debconf mysql-server/root_password password $MYSQL_ROOT_PASSWORD | sudo debconf-set-selections
echo debconf mysql-server/root_password_again password $MYSQL_ROOT_PASSWORD | sudo debconf-set-selections

sudo apt-get -qq install mysql-server > /dev/null # Install MySQL quietly




#debconf-set-selections <<< 'mysql-server mysql-server/root_password password MySuperPassword'
#debconf-set-selections <<< 'mysql-server mysql-server/root_password_again password MySuperPassword'
#apt-get update
#apt-get install -y mysql-server










#Method 1: Managing services in Linux with systemd
#systemctl start <service-name>
#systemctl stop <service-name>
#systemctl restart <service-name>
#systemctl status <service-name>

#Method 2: Managing services in Linux with init
#service --status-all
#service <service-name> start
#service <service-name> stop
#service <service-name> restart
#service <service-name> status

#netstat -napl | grep 80

#List Ubuntu Services with Service command
#service  --status-all

#List Services with systemctl command
#systemctl list-units

# Installing nginx
# sudo apt install nginx

# Installing PHP
#result=$(sudo apt list --installed | grep nginx | cut -d ":" -f2)
#result=$(sudo apt -qq list nginx)
#echo $result

# Installing PHP 7.4 with Apache
#sudo apt-get install --yes php
#sudo apt install libapache2-mod-php

# Installing Apache
#sudo apt install apache2


#Enabling PHP Repository
#sudo apt install software-properties-common
#require reboot
#sudo add-apt-repository ppa:ondrej/php
#sudo apt update


#Installing PHP 8.0 with Nginx
#sudo apt update
#sudo apt install php8.0-fpm

#sudo apt -qq list php
#sudo apt -qq list php8.0-fpm