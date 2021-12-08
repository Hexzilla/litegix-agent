#!/bin/bash

DOMAIN="$1"
EMAIL="$2"

apt-get install certbot python3-certbot-nginx -y
certbot run -n --nginx --agree-tos -d $DOMAIN,www.$DOMAIN  -m $EMAIL --redirect
