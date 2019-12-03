#!/bin/bash
set -ev

ulimit -c unlimited -S
sudo bash -c "echo '/tmp/core.%p.%E' > /proc/sys/kernel/core_pattern"

pushd agent/$OPENRASP_LANG
php run-tests.php -p `which php` -d extension=`pwd`/modules/openrasp.so --offline --show-diff --set-timeout 120
popd