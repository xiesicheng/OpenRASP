#!/bin/bash
set -ev

ulimit -c
ulimit -a -S
ulimit -a -H
cat /proc/sys/kernel/core_pattern


#cmake
wget -N https://cmake.org/files/v3.14/cmake-3.14.5-Linux-x86_64.tar.gz -P $HOME/cache
tar zxf $HOME/cache/cmake-3.14.5-Linux-x86_64.tar.gz -C /tmp
export PATH=/tmp/cmake-3.14.5-Linux-x86_64/bin:$PATH

#openrasp-v8
mkdir -p $TRAVIS_BUILD_DIR/openrasp-v8/build
pushd $TRAVIS_BUILD_DIR/openrasp-v8/build
cmake -DENABLE_LANGUAGES=php ..
make -j2 --quiet
popd

#openrasp
pushd agent/$OPENRASP_LANG
phpenv config-rm xdebug.ini || true
phpenv config-rm ext-opcache.ini || true
phpize && ./configure --with-openrasp-v8=$TRAVIS_BUILD_DIR/openrasp-v8 --with-gettext --enable-openrasp-remote-manager --enable-cli-support && make -j4
popd