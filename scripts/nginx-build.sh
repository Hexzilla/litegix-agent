#!/bin/bash
# Installing a Prebuilt Debian Package from the Official NGINX Repository

function DownloadNginxModules {
  # Download 3rd Party Modules
  modname="array-var-nginx-module-0.05.tar.gz"
  wget -q -O $modname https://github.com/openresty/array-var-nginx-module/archive/refs/tags/v0.05.tar.gz
  tar -xzf $modname
  rm $modname

  modname="echo-nginx-module-0.62.tar.gz"
  wget -q -O $modname https://github.com/openresty/echo-nginx-module/archive/refs/tags/v0.62.tar.gz
  tar -xzf $modname
  rm $modname

  modname="ngx_coolkit-0.2.tar.gz"
  wget -q -O $modname https://github.com/FRiCKLE/ngx_coolkit/archive/refs/tags/0.2.tar.gz
  tar -xzf $modname
  rm $modname

  modname="form-input-nginx-module-0.12.tar.gz"
  wget -q -O $modname https://github.com/calio/form-input-nginx-module/archive/refs/tags/v0.12.tar.gz
  tar -xzf $modname
  rm $modname

  modname="encrypted-session-nginx-module-0.08.tar.gz"
  wget -q -O $modname https://github.com/openresty/encrypted-session-nginx-module/archive/refs/tags/v0.08.tar.gz
  tar -xzf $modname
  rm $modname

  modname="ngx_lua-0.10.19.tar.gz"
  wget -q -O $modname https://github.com/openresty/lua-nginx-module/archive/refs/tags/v0.10.19.tar.gz
  tar -xzf $modname
  rm $modname

  modname="ngx_lua_upstream-0.07.tar.gz"
  wget -q -O $modname https://github.com/openresty/lua-upstream-nginx-module/archive/refs/tags/v0.07.tar.gz
  tar -xzf $modname
  rm $modname

  modname="headers-more-nginx-module-0.33.tar.gz"
  wget -q -O $modname https://github.com/openresty/headers-more-nginx-module/archive/refs/tags/v0.33.tar.gz
  tar -xzf $modname
  rm $modname

  modname="memc-nginx-module-0.19.tar.gz"
  wget -q -O $modname https://github.com/openresty/memc-nginx-module/archive/refs/tags/v0.19.tar.gz
  tar -xzf $modname
  rm $modname

  modname="ngx_brotli-1.0.0rc.tar.gz"
  wget -q -O $modname https://github.com/google/ngx_brotli/archive/refs/tags/v1.0.0rc.tar.gz
  tar -xzf $modname
  rm $modname

  modname="ngx_cache_purge-2.3.tar.gz"
  wget -q -O $modname https://github.com/FRiCKLE/ngx_cache_purge/archive/refs/tags/2.3.tar.gz
  tar -xzf $modname
  rm $modname

  modname="ModSecurity-nginx-1.0.2.tar.gz"
  wget -q -O $modname https://github.com/SpiderLabs/ModSecurity-nginx/archive/refs/tags/v1.0.2.tar.gz
  tar -xzf $modname
  rm $modname

  modname="redis2-nginx-module-0.15.tar.gz"
  wget -q -O $modname https://github.com/openresty/redis2-nginx-module/archive/refs/tags/v0.15.tar.gz
  tar -xzf $modname
  rm $modname

  modname="rds-json-nginx-module-0.15.tar.gz"
  wget -q -O $modname https://github.com/openresty/rds-json-nginx-module/archive/refs/tags/v0.15.tar.gz
  tar -xzf $modname
  rm $modname

  modname="rds-csv-nginx-module-0.09.tar.gz"
  wget -q -O $modname https://github.com/openresty/rds-csv-nginx-module/archive/refs/tags/v0.09.tar.gz
  tar -xzf $modname
  rm $modname

  modname="set-misc-nginx-module-0.32.tar.gz"
  wget -q -O $modname https://github.com/openresty/set-misc-nginx-module/archive/refs/tags/v0.32.tar.gz
  tar -xzf $modname
  rm $modname

  modname="srcache-nginx-module-0.32.tar.gz"
  wget -q -O $modname https://github.com/openresty/srcache-nginx-module/archive/refs/tags/v0.32.tar.gz
  tar -xzf $modname
  rm $modname

  modname="ngx_stream_lua-0.0.9.tar.gz"
  wget -q -O $modname https://github.com/openresty/stream-lua-nginx-module/archive/refs/tags/v0.0.9.tar.gz
  tar -xzf $modname
  rm $modname

  modname="ngx_devel_kit-0.3.1.tar.gz"
  wget -q -O $modname https://codeload.github.com/vision5/ngx_devel_kit/tar.gz/refs/tags/v0.3.1
  tar -xzf $modname
  rm $modname

  modname="xss-nginx-module-0.06.tar.gz"
  wget -q -O $modname https://github.com/openresty/xss-nginx-module/archive/refs/tags/v0.06.tar.gz
  tar -xzf $modname
  rm $modname
}

# Download 3rd Part Modules
rm -rf ~/easycloud
mkdir -p ~/easycloud/modules
cd ~/easycloud/modules
DownloadNginxModules

# Download the key used to sign NGINX packages and the repository
mkdir -p ~/easycloud/nginx
sudo chown -Rv _apt:root ~/easycloud/nginx
sudo chmod -Rv 700 ~/easycloud/nginx
cd ~/easycloud/nginx

wget https://nginx.org/keys/nginx_signing.key
apt-key add nginx_signing.key

# Update sources.list
cat <<-EOF > /etc/apt/sources.list.d/nginx.list
deb [arch=amd64] http://nginx.org/packages/ubuntu/ focal nginx
deb-src http://nginx.org/packages/ubuntu/ focal nginx
EOF

# Install the NGINX package
apt-get remove nginx-common
apt-get update

# Get the build dependencies and the source code for nginx.
apt-get build-dep nginx -y
apt-get source nginx -y


COMMON_CONFIGURE_ARGS := \
--prefix=/etc/easycloud/nginx 
--with-cc-opt='-O2 -g -O3 -fPIE -fstack-protector-strong -flto -Wno-error=strict-aliasing -Wformat -Werror=format-security -fPIC -Wdate-time -D_FORTIFY_SOURCE=2' 
--add-module=~/easycloud/modules/ngx_devel_kit-0.3.1 
--add-module=~/easycloud/modules/echo-nginx-module-0.62 
--add-module=~/easycloud/modules/xss-nginx-module-0.06 
--add-module=~/easycloud/modules/ngx_coolkit-0.2 
--add-module=~/easycloud/modules/set-misc-nginx-module-0.32 
--add-module=~/easycloud/modules/form-input-nginx-module-0.12 
--add-module=~/easycloud/modules/encrypted-session-nginx-module-0.08 
--add-module=~/easycloud/modules/srcache-nginx-module-0.32 
--add-module=~/easycloud/modules/ngx_lua-0.10.19 
--add-module=~/easycloud/modules/ngx_lua_upstream-0.07 
--add-module=~/easycloud/modules/headers-more-nginx-module-0.33 
--add-module=~/easycloud/modules/array-var-nginx-module-0.05 
--add-module=~/easycloud/modules/memc-nginx-module-0.19 
--add-module=~/easycloud/modules/redis2-nginx-module-0.15 
--add-module=~/easycloud/modules/redis-nginx-module-0.3.7 
--add-module=~/easycloud/modules/rds-json-nginx-module-0.15 
--add-module=~/easycloud/modules/rds-csv-nginx-module-0.09 
--add-module=~/easycloud/modules/ngx_stream_lua-0.0.9 
--add-module=~/easycloud/modules/ngx_brotli-1.0.0rc 
--add-module=~/easycloud/modules/ngx_cache_purge-2.3 
--add-module=~/easycloud/modules/ModSecurity-nginx-1.0.2
--with-ld-opt='-Wl,-rpath,/RunCloud/Packages/nginx-rc/luajit/lib -Wl,-Bsymbolic-functions -fPIE -pie -Wl,-z,relro -Wl,-z,now -fPIC' 
--sbin-path=/usr/local/sbin/nginx-rc 
--conf-path=/etc/nginx-rc/nginx.conf 
--error-log-path=/var/log/nginx-rc/error.log 
--http-log-path=/var/log/nginx-rc/access.log 
--lock-path=/var/lock/nginx-rc.lock 
--pid-path=/var/run/nginx-rc.pid 
--group=runcloud-www 
--user=runcloud-www 
--with-openssl=/home/runcloud/Downloads/openssl-OpenSSL_1_1_1b 
--with-openssl-opt='-g no-weak-ssl-ciphers no-ssl3 no-shared enable-ec_nistp_64_gcc_128 -DOPENSSL_NO_HEARTBEATS -fstack-protector-strong' --modules-path=/usr/lib/nginx-rc/modules --with-threads 
--with-http_stub_status_module 
--with-http_ssl_module 
--with-http_v2_module 
--with-stream 
--with-stream_ssl_module 
--with-pcre 
--with-pcre-jit 
--with-file-aio 
--with-http_realip_module 
--with-http_addition_module 
--with-http_flv_module 
--with-http_mp4_module 
--with-http_gunzip_module 
--with-http_gzip_static_module 
--with-http_geoip_module 
--with-http_image_filter_module 
--with-http_sub_module 
--with-stream 
--with-stream_ssl_preread_module 

cd ~/easycloud/nginx/nginx-1.20.1
dpkg-buildpackage -uc -b
cd ..

dpkg --install nginx_1.20.1-1~focal_amd64.deb
apt-mark hold nginx
