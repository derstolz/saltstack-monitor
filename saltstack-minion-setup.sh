#!/bin/bash

#Run the following command to import the SaltStack repository key:
wget -O - https://repo.saltstack.com/apt/debian/9/amd64/latest/SALTSTACK-GPG-KEY.pub | sudo apt-key add - &&

#Save the following file to /etc/apt/sources.list.d/saltstack.list:
echo 'deb http://repo.saltstack.com/apt/debian/9/amd64/latest stretch main' > /etc/apt/sources.list.d/saltstack.list &&

apt update &&

#Install the salt-minion, salt-master, or other Salt components:
apt install salt-minion &&
apt install salt-api &&

echo 'Add a master address to /etc/salt'

echo "Enter a log path to be parsed by the Web Minion" &&
read log_path &&
export WEB_MINION_LOG_PATH=$log_path &&
echo 'export WEB_MINION_LOG_PATH='$log_path >> ~/.bashrc &&

link web_monitor_minion.py web-monitor-minion &&
mv web-monitor-minion /usr/bin

echo 'Done'.
