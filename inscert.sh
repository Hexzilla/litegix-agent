#!/bin/bash

DOMAIN="$1"
EMAIL="$2"

apt install certbot python3-certbot-nginx
certbot run -n --nginx --agree-tos -d $DOMAIN,www.$DOMAIN  -m $EMAIL --redirect
