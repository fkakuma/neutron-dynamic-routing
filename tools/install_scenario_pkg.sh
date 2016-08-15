#!/bin/sh

if [ -n "$1" ]; then
    DIR_BASE=$1
else
    DIR_BASE=.
fi
sudo apt-get update
sudo apt-get install -y docker.io
git clone https://github.com/jpetazzo/pipework.git $DIR_BASE/pipework
sudo install -m 0755 $DIR_BASE/pipework/pipework /usr/local/bin/pipework
sudo pip install docker-py pycrypto fabric nsenter
