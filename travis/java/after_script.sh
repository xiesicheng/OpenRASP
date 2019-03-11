#!/bin/bash
set -ev

pushd agent/java/
dataFile=/home/travis/build/baidu/openrasp/agent/java/integration-test/jacoco/
java -jar integration-test/jacoco/jacococli.jar report $dataFile/jacoco.exec --classfiles boot/target/classes/ --sourcefiles boot/src/main/java/ --xml jacoco.xml