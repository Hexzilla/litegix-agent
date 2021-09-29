#!/bin/bash
##
# Owned by RunCloud
# Usage without permission is prohibited

WEBAPPNAME=$1
EMAIL=$2
DOMAINS=$3
WEBROOT="/opt/RunCloud/letsencrypt"

mkdir -p $WEBROOT

# For old legacy cert
IFS=, read -ra values <<< "$DOMAINS"
for domain in "${values[@]}"
do
    rm -rf /etc/letsencrypt/archive/$domain
    rm -rf /etc/letsencrypt/live/$domain
    rm -rf /etc/letsencrypt/live/$domain-*
    rm -rf /etc/letsencrypt/renewal/$domain.conf
done

# Delete web app based cert
rm -rf /etc/letsencrypt/archive/$WEBAPPNAME
rm -rf /etc/letsencrypt/live/$WEBAPPNAME
rm -rf /etc/letsencrypt/live/$WEBAPPNAME-*
rm -rf /etc/letsencrypt/renewal/$WEBAPPNAME.conf


/usr/sbin/certbot-rc certonly --email $EMAIL \
    --agree-tos \
    --webroot \
    -w $WEBROOT \
    --non-interactive \
    --expand \
    --allow-subset-of-names \
    --cert-name $WEBAPPNAME \
    -d $DOMAINS \
    -q

