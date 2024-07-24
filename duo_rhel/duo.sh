#!/bin/bash

echo "****Welcome to Duo Automation By PHT Security****"

echo "****The script is only been tested for RHEL 8.7****"

echo "****Create yum reposd duosecurity.repo****"

cp /home/your_username/script/duo/duosecurity.repo /etc/yum.repos.d

echo "****Import the public key to the system****"

rpm --import https://duo.com/DUO-GPG-PUBLIC-KEY.asc

echo "****Install the Duo Package****"

yum install duo_unix

cp /home/your_username/script/duo/pam_duo.conf /etc/duo/

cp /home/your_username/script/duo/sshd_config /etc/ssh/

cp /home/your_username/script/duo/system-auth /etc/pam.d/

cp /home/your_username/script/duo/sshd /etc/pam.d/

cp /home/your_username/script/duo/gdm-password /etc/pam.d/

echo "****Complete****"











