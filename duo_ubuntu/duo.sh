#!/bin/bash

echo "****Welcome to Duo Automation By PHT Security****"

echo "****The script has only been tested on Ubuntu 22.04****"

echo "****Download the latest Duo tar file****"

wget --content-disposition https://dl.duosecurity.com/duo_unix-latest.tar.gz

echo "****Install pam_duo Prerequisites****"

apt update 

apt install -y gcc make 

apt install -y vim libssl-dev 

apt install -y libpam-dev

echo "****Extract the downloaded tarball for duo_unix****"

tar zxf /home/your_username/duo_unix-2.0.2.tar.gz

cd /home/your_username/duo_unix-2.0.2

echo "****Build and install duo unix with PAM support Pam Duo****"

./configure --with-pam --prefix=/usr && make && make install

echo "****Build and install duo unix with PAM support Pam Duo****"

cp /home/your_username/uscript/duo/pam_duo.conf /etc/duo/

cp /home/your_username/uscript/duo/sshd_config /etc/ssh/

systemctl restart sshd

systemctl status sshd

cp /home/your_username/uscript/duo/common-auth /etc/pam.d/ 

cp /home/your_username/uscript/duo/sshd /etc/pam.d/

echo "****Complete****"











