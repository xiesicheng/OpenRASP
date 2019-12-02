#!/bin/bash
set -ev

ulimit -c unlimited -S
echo '/tmp/core.%p.%E' > /proc/sys/kernel/core_pattern

pushd agent/$OPENRASP_LANG
php run-tests.php -p `which php` -d extension=`pwd`/modules/openrasp.so --offline --show-diff --set-timeout 120
popd

for i in $(find /tmp -maxdepth 1 -name 'core*' -print); do gdb php-cgi core* -ex "thread apply all bt" -ex "set pagination 0" -batch; done;