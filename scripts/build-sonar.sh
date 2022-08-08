#!/bin/bash

export SONAR_SCANNER_VERSION=4.7.0.2747
export SONAR_SCANNER_HOME=$HOME/.sonar/sonar-scanner-$SONAR_SCANNER_VERSION-linux
curl --create-dirs -sSLo $HOME/.sonar/sonar-scanner.zip https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-$SONAR_SCANNER_VERSION-linux.zip
unzip -o $HOME/.sonar/sonar-scanner.zip -d $HOME/.sonar/
export PATH=$SONAR_SCANNER_HOME/bin:$PATH
export SONAR_SCANNER_OPTS="-server"
curl --create-dirs -sSLo $HOME/.sonar/build-wrapper-linux-x86.zip https://sonarcloud.io/static/cpp/build-wrapper-linux-x86.zip
unzip -o $HOME/.sonar/build-wrapper-linux-x86.zip -d $HOME/.sonar/
export PATH=$HOME/.sonar/build-wrapper-linux-x86:$PATH

cd /workspace

$HOME/.sonar/build-wrapper-linux-x86/build-wrapper-linux-x86-64 --out-dir bw-output make build

$SONAR_SCANNER_HOME/bin/sonar-scanner \
-Dsonar.organization=fdio \
-Dsonar.projectKey=fdio-hicn \
-Dsonar.sources=/workspace \
-Dsonar.cfamily.build-wrapper-output=bw-output \
-Dsonar.host.url=https://sonarcloud.io