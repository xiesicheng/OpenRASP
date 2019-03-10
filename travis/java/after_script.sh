#!/bin/bash
set -ev

pushd agent/java/
mkdir integration-test/jacoco/temp
mkdir -p integration-test/jacoco/sources/com/baidu/openrasp/
mkdir -p integration-test/jacoco/classes/com/baidu/openrasp/
cp engine/target/original-rasp-engine.jar integration-test/jacoco/temp
cp engine/target/rasp-engine.jar integration-test/jacoco/temp
cp boot/target/rasp.jar integration-test/jacoco/temp
pushd integration-test/jacoco/temp/
if [[ -f "rasp-engine.jar" ]] && [[ -f "rasp.jar" ]]; then
	jar -xvf original-rasp-engine.jar  com/baidu/
    pushd com/baidu/openrasp/
    fileList=
    for file in $(ls); do
       fileList="com/baidu/openrasp/$file $fileList"
    done
    popd
    rm -rf com/
    jar -xvf rasp-engine.jar $fileList
    jar -xvf rasp.jar com/baidu
    cp -r com/baidu/openrasp/* ../classes/com/baidu/openrasp/
    popd
    cp -r engine/src/main/java/com/baidu/openrasp/* integration-test/jacoco/sources/com/baidu/openrasp/
    cp -r boot/src/main/java/com/baidu/openrasp/* integration-test/jacoco/sources/com/baidu/openrasp/
fi
ls -a integration-test/jacoco/sources/com/baidu/openrasp/
ls -a integration-test/jacoco/classes/com/baidu/openrasp/
pushd integration-test/jacoco
dataFile=/home/travis/build/baidu/openrasp/agent/java
java -jar jacococli.jar report $dataFile/jacoco.exec --classfiles classes/ --sourcefiles sources/ --xml jacoco.xml
popd
rm -rf integration-test/temp/
rm -rf integration-test/sources/
rm -rf integration-test/classes/
