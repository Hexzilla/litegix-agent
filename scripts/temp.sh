#!/bin/bash
MYSQL_PASS="www.amazon.com#2021"

# Add MySQL software repo (possibly unnecessary for you, but I want to set up group replication later)
cd /tmp
curl -OL https://dev.mysql.com/get/mysql-apt-config_0.8.17-1_all.deb
DEBIAN_FRONTEND=noninteractive dpkg -i mysql-apt-config*

# Install mysql
apt-get update

# You may have to change these two lines
echo "mysql-community-server mysql-community-server/root-pass password $MYSQL_PASS" | debconf-set-selections
echo "mysql-community-server mysql-community-server/re-root-pass password $MYSQL_PASS" | debconf-set-selections

apt-get install -y mysql-server

# Clean up install files
rm mysql-apt-config*

# Install "expect"
apt-get -qq install expect > /dev/null

# Generate an expect script
tee ~/secure_mysql.sh > /dev/null << EOF

  spawn $(which mysql_secure_installation)

  # Enter the password for user root
  expect "Enter the password for user root:"
  send $MYSQL_PASS
  send "\r"

  # Would you like to setup the validate Password Plugin?
  expect "Press y|Y for Yes, any other key for No:"
  send "n\r"

  # Change the password for root?
  expect "Change the password for root ? ((Press y|Y for Yes, any other key for No) :"
  send "n\r"

  # Remove anonymous users
  expect "Remove anonymous users? (Press y|Y for Yes, any other key for No) :"
  send "y\r"

  # Disallow remote root login
  expect "Disallow root login remotely? (Press y|Y for Yes, any other key for No) :"
  send "y\r"

  # Remove test DB?
  expect "Remove test database and access to it? (Press y|Y for Yes, any other key for No) :"
  send "y\r"

  # Reload privilege tables
  expect "Reload privilege tables now? (Press y|Y for Yes, any other key for No) :"
  send "y\r"

  expect eof
EOF

# Run Expect script.
# This runs the "mysql_secure_installation" script which removes insecure defaults.
sudo expect ~/secure_mysql.sh

# Cleanup
rm -v ~/secure_mysql.sh # Remove the generated Expect script

echo "MySQL setup completed. Insecure defaults are gone. Please remove this script manually when you are done with it (or at least remove the MySQL root password that you put inside it."