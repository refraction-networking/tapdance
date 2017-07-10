#!/bin/bash

HOST="$(hostname)"

echo "Installing files for $HOST..."

mkdir -p /var/lib/tapdance/
cp default/client_conf_gen1 /var/lib/tapdance/client_conf

mkdir -p /etc/tapdance/

cp $HOST/config /etc/tapdance/

cp $HOST/zbalance /etc/init.d/
cp $HOST/tapdance /etc/init.d/
cp $HOST/gobbler /etc/init.d/

chmod +x /etc/init.d/zbalance
chmod +x /etc/init.d/tapdance
chmod +x /etc/init.d/gobbler

update-rc.d zbalance defaults
update-rc.d tapdance defaults
update-rc.d gobbler defaults

