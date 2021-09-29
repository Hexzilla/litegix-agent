#!/bin/bash


# Constants
LITEGIX_URL="http://localhost:3600"
INSTALL_STATE_URL="$LITEGIX_URL/api/installation/status"
INSTALL_PACKAGE="curl git wget expect nano build-essential openssl zip unzip make net-tools bc python-setuptools perl fail2ban augeas-tools libaugeas0 augeas-lenses firewalld acl memcached beanstalkd passwd unattended-upgrades postfix jq"

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


# Install packages
send_state "packages"
function install_packages {
  apt-get update
  apt-get remove mysql-common --purge -y
  apt-get install $INSTALLPACKAGE -y

  apt install software-properties-common -y

  curl https://haproxy.debian.net/bernat.debian.org.gpg | apt-key add -
  echo "deb http://haproxy.debian.net $(lsb_release -cs)-backports-2.0 main" | tee /etc/apt/sources.list.d/haproxy.list
  add-apt-repository ppa:vbernat/haproxy-2.1 -y

  apt update
  apt install haproxy -y
}
install_packages


# Config
echo "# Litegix

global
    maxconn 5000
    log /dev/log        local0
    log /dev/log        local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    # Default SSL material locations
    ca-base /etc/ssl/certs
    crt-base /etc/ssl/private

    # Default ciphers to use on SSL-enabled listening sockets.
    # For more information, see ciphers(1SSL). This list is from:
    #  https://hynek.me/articles/hardening-your-web-servers-ssl-ciphers/
    # An alternative list with additional directives can be obtained from
    #  https://mozilla.github.io/server-side-tls/ssl-config-generator/?server=haproxy
    ssl-default-bind-ciphers ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS
    ssl-default-bind-options no-sslv3

defaults
    log global
    mode        http
    option      httplog
    option      dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

# Default Let's Encrypt backend server used for renewals and requesting certificates
backend letsencrypt-backend
    server letsencrypt 127.0.0.1:8888

# Load balancer settings
frontend load-balancer
    bind *:80



    # See if its an Lets Encrypt request
    acl letsencrypt-acl path_beg /.well-known/acme-challenge/
    use_backend letsencrypt-backend if letsencrypt-acl

    mode http
    default_backend webservers

# Backend webservers (the attached servers to the load balancer)
backend webservers
    fullconn 5000
    maxconn 5000
    balance roundrobin
    option forwardfor
    cookie SRVNAME insert
    http-request set-header X-Forwarded-Port %[dst_port]
    http-request add-header X-Forwarded-Proto https if { ssl_fc }
" > /etc/haproxy/haproxy.cfg