#!/bin/bash
# NOTE: uncomment/comment the following lines if you want sleeps
#SLEEP20s="sleep 20s"
#SLEEP45s="sleep 45s"
#SLEEP90s="sleep 90s"
#SLEEP240s="sleep 240s"
SLEEP20s=""
SLEEP45s=""
SLEEP90s=""
SLEEP240s=""

# NOTE: Remopve the '-y' if you want to run 'dnf' interactively

DNF_INSTALL="dnf install -y"
DNF_REMOVE="dnf remove -y"
DNF_UPDATE="dnf update -y"

echo "****Removes the default ssh keys from Redhat server****"

rm -f /etc/ssh/*key*

echo "****Creates a fresh set of ssh keys for good measure****"

ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key

ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key

ssh-keygen -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key

echo "****Setup Fail2Ban****"

cd /home/your_username/script || exit

$DNF_INSTALL https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm -y

$DNF_INSTALL -y fail2ban

cp /home/your_username/script/jail.local /etc/fail2ban/

cp /home/your_username/script/sshd.local /etc/fail2ban/jail.d/

systemctl start fail2ban

systemctl enable fail2ban

echo "****Ensure mounting of cramfs filesystems is disabled****"

echo "****Step 1 audit for cramfs****"

modprobe -n -v cramfs | grep "^install" 

lsmod | grep cramfs

echo "****Is the module blacklisted ****"

grep -E "^blacklist\s+cramfs" /etc/modprobe.d/*

$SLEEP20s

echo "****Creates a file in the /etc/modprobe.d/ directory ending in .conf with a line that reads install cramfs /bin/false and a line the reads blacklist cramfs****"

printf "install cramfs /bin/false blacklist cramfs" >> /etc/modprobe.d/cramfs.conf

echo "****The following command unloads the cramfs module****"

modprobe -r cramfs

#Ask if client is using squashfs, As Snap packages utilizes squashfs as a compressed filesystem, disabling squashfs will cause Snap packages to fail.

#echo "****Ensure mounting of squashfs filesystems is disabled****"

#echo "****Step 1 audit for squashfs****"

#modprobe -n -v squashfs | grep "^install"

#lsmod | grep squashfs

#"****Is the module blacklisted ****"

#grep -E "^blacklist\s+squashfs" /etc/modprobe.d/*

#@SLEEP20s

#echo "****Create a file in the /etc/modprobe.d/ directory ending in .conf with the lines that reads install squashfs /bin/false and blacklist squashfs****"

#printf "install squashfs /bin/false blacklist squashfs" >> /etc/modprobe.d/squashfs.conf

#echo "****The following command unloads the squashfs module****"

#modprobe -r squashfs

#Ask if client is using udf filesystem, As Microsoft Azure requires the usage of udf, and offloading the use of this filesystem should not be done on systems run on Microsoft Azure.

echo "****Ensure mounting of the udf filesystems is disabled****"

echo "****Step 1 audit for the udf filesystem****"

modprobe -n -v udf | grep "^install"lsmod | grep udf

lsmod | grep udf

echo "****Is the module blacklisted ****"

grep -E "^blacklist[[:blank:]]*udf" /etc/modprobe.d/*

$SLEEP20s

echo "****Create a file in the /etc/modprobe.d/ directory ending in .conf with the lines that reads install udf /bin/false and blacklist udf****"

printf "install udf /bin/false blacklist udf" >> /etc/modprobe.d/udf.conf

echo "****The following command unloads the udf module****"

modprobe -r udf

#echo "****Disable Automounting****"

#Check if client if Automounting of portable drives is needed for servers or workstations

#echo "****Run the following command to verify autofs is not installed****"

#systemctl is-enabled autofs 

$SLEEP20s

#echo "****Removes the package****"

#$DNF_REMOVE autofs

#echo "****The following command to disable autofs****"

#systemctl --now disable autofs 

#echo "****Disable USB Storage****"

#Check with client if USB protable devices are used on workstations and servers

#echo "The following command verifies usb storage is enabled"

#modprobe -n -v usb-storage 

#lsmod | grep usb-storage

$SLEEP20s

#echo "****Create a file in the /etc/modprobe.d/ directory ending in .conf with the lines that reads install udf /bin/false and blacklist usb storage divices****"

#printf "install usb-storage /bin/true" >> /etc/modprobe.d/usb_storage.conf

#echo "****Unloads the usb-storage module****"

rmmod usb-storage 

echo "****Verifiy the Red Hat Subscription****"

subscription-manager identity 

subscription-manager register

echo "****Ensure GPG keys are configured****"

grep -r gpgkey /etc/yum.repos.d/* /etc/dnf/dnf.conf 

echo "****To find where these keys comes from****"

for PACKAGE in $(find /etc/pki/rpm-gpg/ -type f -exec rpm -qf {} \; | sort -u); do rpm -q --queryformat "%{NAME}-%{VERSION} %{PACKAGER} %{SUMMARY}\\n" "${PACKAGE}"; done 

echo "****Ensure gpgcheck is globally activated****"

echo "****Audit by verifying that gpgcheck is set to 1****"

grep ^gpgcheck /etc/dnf/dnf.conf

grep -P "^gpgcheck\h*=\h*[^1].*\h*$" /etc/yum.repos.d/*

$SLEEP20s

echo "****Remediation Edits /etc/dnf/dnf.conf and set a gpgcheck=1 in the [main] section****"

find /etc/yum.repos.d/ -name "*.repo" -exec echo "Checking:" {} \; -execsed -i 's/^gpgcheck\s*=\s*.*/gpgcheck=1/' {} \;

echo "****Run the following command to verify repositories are configured correctly****"

dnf repolist

echo "****Install AIDE Package****"

yum install aide -y

echo "****Verify the installation****"

rpm -qa | grep aide

echo "****To check the current installed version****"

aide -v

echo "****Copy the AIDE config to the required directory****"

cp /home/your_username/script/aide.conf /etc/

echo "****Comment out the default /etc paths in the config file during testing so that any change in /etc directories are avoided by aide check****"

sed -i 's|^/etc|#/etc|g' /etc/aide.conf

echo "****Create AIDE database****"

aide --init

echo "****A tar file will get created inside /var/lib/aide****"

cd /var/lib/aide

echo "****Rename the tar file****"

mv aide.db.new.gz aide.db.gz

echo "****Check Integrity****"

aide --check

echo "**** Re-initialize Database****"

aide --update

echo "****Ensure gpgcheck is globally activated****"

echo '****Audit by verifying that gpgcheck is set to 1****'

grep '^gpgcheck' /etc/dnf/dnf.conf

grep -P '^gpgcheck\h*=\h*[^1].*\h*$' /etc/yum.repos.d/epel-modular.repo /etc/yum.repos.d/epel.repo /etc/yum.repos.d/epel-testing-modular.repo /etc/yum.repos.d/epel-testing.repo

#Please check with client, modifing the bootloader passwrd could impact access to system as to who could config changes, which user would be used to make this change?

#echo "****Ensure bootloader password is set****"

#grub2-setpassword

#$SLEEP240s

#grub2-mkconfig -o "$(dirname "$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec grep -Pl '^\h*(kernelopts=|linux|kernel)' {} \;)")/grub.cfg"

echo "****Ensure permissions on bootloader config are configured****"

ls -l /boot/grub2/grub.cfg /boot/grub2/grubenv /boot/efi/EFI/redhat/grub.cfg

echo "****Run the following commands to set ownership and permissions on your grub configuration files****"

[ -f /boot/grub2/grub.cfg ] && chown root:root /boot/grub2/grub.cfg 

[ -f /boot/grub2/grub.cfg ] && chmod og-rwx /boot/grub2/grub.cfg 
 
[ -f /boot/grub2/grubenv ] && chown root:root /boot/grub2/grubenv

[ -f /boot/grub2/grubenv ] && chmod og-rwx /boot/grub2/grubenv 
 
[ -f /boot/grub2/user.cfg ] && chown root:root /boot/grub2/user.cfg 

[ -f /boot/grub2/user.cfg ] && chmod og-rwx /boot/grub2/user.cfg 

echo "****Ensure authentication is required when booting into rescue mode****"

grep -r /systemd-sulogin-shell /usr/lib/systemd/system/rescue.service /etc/systemd/system/rescue.service.d 

$SLEEP20s

echo "********Write the following file emergency.service to /usr/lib/systemd/system/"

cp /home/your_username/script/emergency.service /usr/lib/systemd/system/

echo "********Write the following file systemd-sulogin-shell to /usr/lib/systemd/system/"

cp /home/your_username/script/systemd-sulogin-shell /usr/lib/systemd/system/

echo "****A core dump generally useful only for developers trying to debug problems.  Ask client if the devlopers are using core dumps for debugging in the RHEL System****"

echo "****Ensure core dump storage is disabled****"

echo "****Run the following command to verify Storage is set to none and ProcessSizeMax is set to 0 in /etc/systemd/coredump.conf****"

grep -i Storage=none /etc/systemd/coredump.conf

echo "***Write the following value to /etc/systemd/coredump.conf****"

sed -i 's/#Storage=external/Storage=none/g' /etc/systemd/coredump.conf

echo "****Ensure core dump backtraces are disabled****"

echo "****Run the following command to verify ProcessSizeMax is set to 0 in /etc/systemd/coredump.conf****"

# NOTE: '-z' checks for an empty string. Surround the command with '"' to prevent multiple arguments error
if [ -z "`grep -i ProcessSizeMax /etc/systemd/coredump.conf `" ]
then
	echo "****ProcessSizeMax is NOT set to 0 in /etc/systemd/coredump.conf****"
fi

$SLEEP20s

echo "***Write the following value to /etc/systemd/coredump.conf****"

sed -i '/ProcessSizeMax/c\ProcessSizeMax=0' /etc/systemd/coredump.conf

echo "****Ensure address space layout randomization (ASLR) is enabled****"

grep -i "kernel.randomize_va_space = 2" /etc/sysctl.d/60-kernel_sysctl.conf

$SLEEP20s

echo "****Set the following parameter in /etc/sysctl.conf or a /etc/sysctl.d/* file****"

printf "kernel.randomize_va_space = 2" >> /etc/sysctl.d/60-kernel_sysctl.conf

echo "****Ensure SELinux is installed****"

rpm -q libselinux 
if [ $? -ne 0 ]
then
	echo "****libselinux is NOT installed****"
else
# NOTE: 
	echo "You probably want to install it here"
fi

echo "****Ensure SELinux is not disabled in bootloader configuration****" 

echo "****Run the following commands to verify that neither the selinux=0 or enforcing=0 parameters have been set****"

# NOTE: '-f' checks if a file exists
if [ -f /boot/grub2/grubenv ]
then
# NOTE: use 'egrep' and separate the arguments with a '|' to search for multiple arguments
	if [ -n "`egrep -i \"selinux=0|enforcing=0\" /boot/grub2/grubenv`" ]
	then
		echo "****selinux=0 or enforcing=0 found in /boot/grub2/grubenv****"
	fi
fi

if [ -f /boot/grub2/grub.conf ]
then
	if [ -n "`egrep -i \"selinux=0|enforcing=0\" /boot/grub2/grub.conf`" ]
	then
		echo "****selinux=0 or enforcing=0 found in /boot/grub2/grub.conf****"
	fi
fi

if [ -f /boot/grub2/grub.cfg ]
then
	if [ -n "`egrep -i \"selinux=0|enforcing=0\" /boot/grub2/grub.cfg`" ]
	then
		echo "****selinux=0 or enforcing=0 found in /boot/grub2/grub.cfg****"
	fi
fi

$SLEEP20s

echo "****Run the following command to remove all instances of selinux=0 and enforcing=0 from all CMDLINE_LINUX parameters****"

grubby --update-kernel ALL --remove-args 'selinux=0 enforcing=0'

echo "****Ensure SELinux policy is configured****"

echo "****Run the following commands and ensure output matches either " targeted " or " mls ": ****"

grep -E '^\s*SELINUXTYPE=(targeted|mls)\b' /etc/selinux/config 

$SLEEP20s

echo "****Set the following value within the /etc/selinux/config file to state SELINUXTYPE=targeted****"

sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config

echo "****Ensure the SELinux mode is not disabled****"

echo "****Run the following command to verify SELinux's current mode****"

getenforce

echo "****Run the following command to verify SELinux's configured mode****"

grep -Ei '^\s*SELINUX=(enforcing|permissive)' /etc/selinux/config

$SLEEP20s

echo "****To set SELinux mode to Enforcing****"

setenforce 1

echo "****Ensure unconfined services are disclosed to the client****"

echo "****Run the following command and verify what is produced for unconfined services for SELinux****"

ps -eZ | grep unconfined_service_t

echo "****Occasionally certain daemons such as backup or centralized management software may require running unconfined. Any such software should be carefully analyzed and documented before such an exception is made.****" 

echo "****Ensure SETroubleshoot is not installed****"

echo "****Verify setroubleshoot is not installed****"

rpm -q setroubleshoot
if [ $? -ne 0 ]
then
	echo "****Run the following command to uninstall setroubleshoot****"
	$DNF_REMOVE setroubleshoot 
fi

echo "****Ensure the MCS Translation Service (mcstrans) is not installed****"

echo "****Verify mcstrans is not installed****"

rpm -q mcstrans
if [ $? -ne 0 ]
then
	echo "****Run the following command to uninstall mcstrans****"
	$DNF_REMOVE mcstrans
fi

#Does the client even require a message of the day is configured

#echo "****Ensure local login warning banner is configured properly****"

#echo "****99-class-banner need to be copied to the folowing directories for GUI banner message to display on bottom of screen****" 

#echo "****Install the gnome-shell-extension-classification-banner package****"

#yum install gnome-shell-extension-classification-banner

#cp /home/your_username/script/gdm.d/99-class-banner /etc/dconf/db/gdm.d/99-class-banner

#cp /home/your_username/script/local.d/99-class-banner /etc/dconf/db/local.d/99-class-banner

#echo "****Update the dconf database****"

#dconf update

echo "****Configure SSH Warning Banner****"

cp /home/your_username/script/sshd_config /etc/ssh/sshd_config

cp /home/your_username/script/ssh_banner /etc/ssh/ssh_banner

 systemctl restart sshd

$SLEEP20s

echo "****Ensure permissions on /etc/motd are configured****"
if [ -f /etc/motd ]
then
	echo "****Run the following commands to set permissions on /etc/motd****"
	$SLEEP20s
	chown root:root /etc/motd
	chmod u-x,go-wx /etc/motd
fi

echo "****Ensure permissions on /etc/issue are configured****"
if [ -f /etc/issue ]
then
	$SLEEP20s
	chown root:root /etc/issue
	chmod u-x,go-wx /etc/issue
fi

echo "****Ensure permissions on /etc/issue.net are configured****"

if [ -f /etc/issue.net ]
then
	$SLEEP20s
	chown root:root /etc/issue.net
	chmod u-x,go-wx /etc/issue.net
fi

#Consult client regarding Gnome Desktop

#"****Ensure GNOME Display Manager is removed ****"

#rpm -q gdm

#$DNF_REMOVE gdm

echo "****Ensure last logged in user display is disabled****"

echo "****Verify that /etc/dconf/profile/gdm exists and includes the following:****"

cat /etc/dconf/profile/gdm

echo "****Verify that 00-login-screen exists in /etc/dconf/db/gdm.d/****"

grep -i "disable-user-list=true" /etc/dconf/db/gdm.d/00-login-screen

grep -i "file-db:/usr/share/gdm/greeter-dconf-defaults" /etc/dconf/profile/gdm

$SLEEP20s

echo "****The following value with be written to /etc/dconf/profile/gdm user-db:user system-db:gdm file-db:/usr/share/gdm/greeter-dconf-defaults****"

cp /home/your_username/script/gdm /etc/dconf/profile/

echo "****The following value with be written to /etc/dconf/db/gdm.d/00-login-screen [org/gnome/login-screen] disable-user-list=true ****"

cp /home/your_username/script/00-login-screen /etc/dconf/db/gdm.d/

dconf update

echo "****Ensure XDMCP is not enabled****"

echo "***Run the following command and verify XDMCP is not enabled*****"

grep -Eis '^\s*Enable\s*=\s*true' /etc/gdm/custom.conf 

$SLEEP20s

echo "****The following value xdmcp #Enable=true with be written to /etc/gdm/custom.conf****"

sed -i '/\[xdmcp\]/,/^\[/ s/^Enable=true/#Enable=true/' /etc/gdm/custom.conf

#Ask client if mounting of removable media needed

#echo "Ensure automatic mounting of removable media is disabled"

#"****Run the following command to verify automatic mounting is disabled****"

#"****Verify result is false****"

#gsettings get org.gnome.desktop.media-handling automount

#echo "****To disable automatic mounting of removable media for all users****"

# cp /home/your_username/script/00-media-automount /etc/dconf/db/local.d/

#dconf update 

#Check with client first if they require compatibility with older insecure protocols.  The use of the less secure LEGACY policy level may be needed

echo "****Ensure system-wide crypto policy is not legacy****"

grep -E -i '^\s*LEGACY\s*(\s+#.*)?$' /etc/crypto-policies/config

$SLEEP20s

echo "****Checks for the DEFAULT Policy ****"

grep -E -i '^\s*DEFAULT\s*(\s+#.*)?$' /etc/crypto-policies/config

$SLEEP20s

echo "****Checks for the FUTURE Policy ****"

grep -E -i '^\s*FUTURE\s*(\s+#.*)?$' /etc/crypto-policies/config

$SLEEP20s

echo "****Checks for the FUTURE Policy****"

grep -E -i '^\s*FIPS\s*(\s+#.*)?$' /etc/crypto-policies/config

echo "****Run the following command to change the system-wide crypto policy****"

update-crypto-policies --set DEFAULT 

echo "****Run the following command to make the updated system-wide crypto policy active****"

update-crypto-policies 

#"****To switch the system to the FIPS system-wide crypto policy run the following command****"

#fips-mode-setup --enable

echo "****Ensure chrony is configured****"

echo "****Run the following commands and verify remote server is configured properly****"

grep -E "^(server|pool)" /etc/chrony.conf 

grep ^OPTIONS /etc/sysconfig/chronyd

echo "****Run the following command to deploy chrony.conf with the default configuration to the system****"

sed -i 's/pool.*rhel.pool.ntp.org iburst/pool 2.rhel.pool.ntp.org iburst/' /etc/chrony.conf

sed -i 's/OPTIONS=.*/OPTIONS="-u chrony"/g' /etc/sysconfig/chronyd

echo "****Ensure xinetd is not installed****"

rpm -q xinetd

echo "****Run the following command to remove xinetd****"

$DNF_REMOVE xinetd

#Ask client if they will require xorg-x11-server-common, because some Some Linux Java packages have a dependency on specific X Windows xorg-x11-fonts.

#echo "****Ensure xorg-x11-server-common is not installed****"

#rpm -q xorg-x11-server-common

#echo "****Run the following command to remove the X Windows Server packages****"

#$DNF_REMOVE xorg-x11-server-common

echo "****Ensure Avahi Server is not installed****"

echo "****Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD service discovery****"

echo "****Run one of the following command to verify avahi-autoipd and avahi are not installed****"

rpm -q avahi-autoipd avahi 

$SLEEP20s

echo "****Run the following commands to stop, mask and remove avahi-autoipd and avahi****"

systemctl stop avahi-daemon.socket avahi-daemon.service

$DNF_REMOVE avahi-autoipd avahi

#Check with client if CUPS is needed

#echo "****Ensure CUPS is not installed****"

#"****Run the following command to verify cups is not installed****"

#rpm -q cups 

#echo "****Run the following command to remove cups****"

#$DNF_REMOVE cups 

#Eunsre the system is not a DHCP server

$SLEEP45s

echo "****Ensure DHCP Server is not installed****"

echo "****Run the following command to verify dhcp is not installed****"

rpm -q dhcp-server

$SLEEP20s

echo "****Run the following command to remove dhcp****"

$DNF_REMOVE dhcp-server

echo "****Ensure DNS Server is not installed****"

echo "****Run the following command to verify a DNS server is not installed****"

rpm -q bind

$SLEEP20s

echo "****Run the following command to remove the DNS server****"

$DNF_REMOVE bind

echo "****Ensure FTP Server is not installed****"

echo "****Run the following command to verify a FTP server is not installed****"

rpm -q ftp

$SLEEP20s

echo "****Run the following command to remove the ftp server****"

$DNF_REMOVE ftp

echo "****Ensure VSFTP Server is not installed****"

echo "****Run the following command to verify a VSFTP server is not installed****"

rpm -q vsftpd

$SLEEP20s

echo "****Run the following command to remove the vsftp server****"

$DNF_REMOVE vsftpd

echo "****Ensure TFTP Server is not installed****"

echo "****Run the following command to verify a TFTP server is not installed****"

rpm -q tftp-server

$SLEEP20s

echo "****Run the following command to remove the tftp server****"

$DNF_REMOVE tftp-server

#Check with client is system is a web server

echo "****Ensure a web Server is not installed****"

echo "****Run the following command to verify a web server is not installed****"

rpm -q httpd nginx

$SLEEP20s

echo "****Run the following command to remove the web server****"

$DNF_REMOVE httpd nginx

echo "****Ensure IMAP and POP3 server is not installed ****"

echo "****Run the following command to verify dovecot and cyrus-imapd are not installed****"

rpm -q dovecot cyrus-imapd 

$SLEEP20s

echo "****Run the following command to remove dovecot and cyrus-imapd****"

$DNF_REMOVE dovecot cyrus-imapd

echo "****Ensure the Samba server is not installed****"

echo "****Run the following command to ensure the Samba server not installed****"

rpm -q samba

$SLEEP20s

echo "****Run the following command to remove the Samba server****"

$DNF_REMOVE samba 

echo "****Ensure HTTP Proxy Server is not installed****"

echo "****Run the following command to verify squid is not installed****"

rpm -q squid

$SLEEP20s

echo "****Run the following command to remove the squid package****"

$DNF_REMOVE squid

echo "****Ensure net-snmp is not installed****"

echo "****Run the following command to verify net-snmp is not installed****"

rpm -q net-snmp

$SLEEP20s

echo "****Run the following command to remove net-snmpd****"

$DNF_REMOVE net-snmp


echo "****Run the following command to verify ypserv is not installed****"

rpm -q ypserv

$SLEEP20s

echo "****Run the following command to remove ypserv****"

$DNF_REMOVE ypserv

echo "****Ensure telnet-server is not installed****"

echo "****Run the following command to verify the telnet-server package is not installed****"

rpm -q telnet-server

$SLEEP20s

echo "****Run the following command to remove the telnet-server package****"

$DNF_REMOVE telnet-server

echo "****Ensure mail transfer agent is configured for local-only mode****"

echo "****Run the following command to verify that the MTA is not listening on any non-loopback address****"

systemctl status postfix 

ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|\[?::1\]?):25\s'

$SLEEP20s

echo "****Adds the following value inet interfaces to RECEIVING MAIL section of /etc/postfix/main configuration file****"

sudo sed -i '/^# RECEIVING MAIL/ a\inet_interfaces = loopback-only' /etc/postfix/main.cf

systemctl restart postfix

#Consult with client to confirm that an nfs-server service is used

echo "****Ensure nfs-utils is not installed or the nfs-server service is masked****"

echo "****Run the following command to verify nfs-utils is not installed****"

rpm -q nfs-utils

echo "****If the nfs-package is required as a dependency, run the following command to verify that the nfs-server service is masked****"

systemctl is-enabled nfs-server

echo "****If the nfs-package is required as a dependency, run the following command to stop and mask the nfs-server service****"

systemctl --now mask nfs-server

echo "****Run the following command to verify that the nfs-server service is masked after change****"

systemctl is-enabled nfs-server

echo "****Ensure rpcbind is not installed or the rpcbind services are masked****"

echo "****Run the following command to verify rpcbind is not installed****"

rpm -q rpcbind

echo "****If the rpcbind package is required as a dependency, run the following commands to verify that the rpcbind and rpcbind.socket services are masked****"


systemctl is-enabled rpcbind 

systemctl is-enabled rpcbind.socket

echo "****If the rpcbind package is required as a dependency, run the following commands to stop and mask the rpcbind and rpcbind.socket services****"

systemctl --now mask rpcbind

systemctl --now mask rpcbind.socket 

echo "****If the rpcbind package is required as a dependency, run the following commands to verify that the rpcbind and rpcbind.socket services are masked****"

systemctl is-enabled rpcbind 

systemctl is-enabled rpcbind.socket

echo "****Ensure rsync is not installed or the rsyncd service is masked****"

rpm -q rsync 

echo "****Run the following command to verify the rsyncd service is masked****"

systemctl is-enabled rpcbind

echo "****Run the following command to mask the rsyncd service****"

systemctl --now mask rsyncd

echo "****Run the following command to verify the rsyncd service is masked****"

systemctl is-enabled rpcbind

echo "****Ensure NIS Client is not installed****"

echo "****Run the following command to verify that the ypbind package is not installed****"

rpm -q ypbind

$SLEEP20s

echo "****Run the following command to remove the ypbind package****"

$DNF_REMOVE ypbind

echo "****Ensure rsh client is not installed****"

echo "****Run the following command to verify that the rsh package is not installed****"

rpm -q rsh

$SLEEP20s

echo "****Run the following command to remove the rsh package****"

$DNF_REMOVE rsh

echo "****Ensure talk client is not installed****"

rpm -q rsh 

$SLEEP20s

echo "****Run the following command to remove the rsh package****"

$DNF_REMOVE rsh 

echo "****Ensure talk client is not installed****"

echo "****Run the following command to verify that the talk package is not installed****"

rpm -q talk 

$SLEEP20s

echo "****Run the following command to remove the talk package****"

$DNF_REMOVE talk 

echo "****Ensure telnet client is not installed****"

echo "****Run the following command to verify that the telnet package is not installed****"

rpm -q telnet

$SLEEP20s

echo "****Run the following command to remove the telnet package****"

$DNF_REMOVE telnet

echo "****Ensure LDAP client is not installed****"

echo "****Run the following command to verify that the openldap-clients package is not installed****"

rpm -q openldap-clients

$SLEEP20s

echo "****Run the following command to remove the openldap-clients package****"

$DNF_REMOVE openldap-clients 

echo "****Ensure LDAP client is not installed****"

echo "****Run the following command to verify that the openldap-clients package is not installed****"

rpm -q openldap-clients

$SLEEP20s

echo "****Run the following command to remove the openldap-clients package****"

$DNF_REMOVE openldap-clients

echo "****Ensure TFTP client is not installed****"

echo "****Run the following command to verify tftp is not installed****"

rpm -q tftp 

$SLEEP20s

echo "****Run the following command to remove tftp****"

$DNF_REMOVE tftp 

echo "****Ensure SCTP is disabled****"

echo "****Run the following commands and verify the output is as indicated****"

modprobe -n -v sctp

lsmod | grep sct

$SLEEP20s

echo "****Create a file in the /etc/modprobe.d/ directory ending in .conf ****"

printf "install sctp /bin/true" >> /etc/modprobe.d/sctp.conf 

echo "****Ensure DCCP is disabled****"

modprobe -n -v dccp

lsmod | grep dccp

$SLEEP20s

echo "****Write the folowing value in the /etc/modprobe.d/ directory ending in .conf****"

printf "install dccp /bin/true" >> /etc/modprobe.d/dccp.conf 

echo "****Ensure IP forwarding is disabled****"

echo "****Run the following command to verify net.ipv4.ip_forward is to 0****"

sysctl net.ipv4.ip_forward

echo "****Run the following script to verify net.ipv6.conf.all.forwarding is set to 0****"

sysctl net.ipv6.conf.all.forwarding

$SLEEP20s

echo "****Set the following parameter /etc/sysctl.d/* file:****"

printf "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf

echo "****Run the following command to set the active kernel parameters****"

sysctl -w net.ipv4.ip_forward=0 

sysctl -w net.ipv4.route.flush=1 

echo "****If IPv6 is enabled on the system****"

echo "****Set the following parameter in the /etc/sysctl.d/* file****"

printf "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf

echo "****Run the following command to set the active kernel parameters****"

sysctl -w net.ipv6.conf.all.forwarding=0 

sysctl -w net.ipv6.route.flush=1 

echo "****Ensure packet redirect sending is disabled****"

echo "****Run the following command to verify net.ipv4.conf.all.send_redirects is to 0****"

sysctl net.ipv4.conf.all.send_redirects

echo "****Run the following command to verify net.ipv4.conf.default.send_redirects is to 0****"

sysctl net.ipv4.conf.default.send_redirects

$SLEEP20s

echo "****Set the following parameters in the /etc/sysctl.d/* file****"

printf "net.ipv4.conf.all.send_redirects = 0 net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf 

echo "Run the following command to set the active kernel parameters"

sysctl -w net.ipv4.conf.all.send_redirects=0

sysctl -w net.ipv4.conf.default.send_redirects=0

sysctl -w net.ipv4.route.flush=1

echo "****Ensure source routed packets are not accepted****"

echo "****Run the following command to verify net.ipv4.conf.all.accept_source_route is set to 0****"

sysctl net.ipv4.conf.all.accept_source_route

echo "****Run the following script to verify net.ipv4.conf.default.accept_source_route is set to 0****"

sysctl net.ipv4.conf.default.accept_source_route

echo "****Run the following command to verify net.ipv6.conf.all.accept_source_route is set to 0****"

sysctl net.ipv6.conf.all.accept_source_route

$SLEEP20s

echo "****Set the following parameters in the /etc/sysctl.d/* file****"

printf "net.ipv4.conf.all.accept_source_route = 0 net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf 

echo "****Run the following command to set the active kernel parameters****"

sysctl -w net.ipv4.conf.all.accept_source_route=0 

sysctl -w net.ipv4.conf.default.accept_source_route=0

sysctl -w net.ipv4.route.flush=1

echo "****If IPv6 is enabled on the system****"

echo "****Set the following parameters in the /etc/sysctl.d/* file****"

printf "net.ipv6.conf.all.accept_source_route = 0 net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf 

echo "Run the following command to set the active kernel parameters"

sysctl -w net.ipv6.conf.all.accept_source_route=0

sysctl -w net.ipv6.conf.default.accept_source_route=0

sysctl -w net.ipv6.route.flush=1

echo "****Ensure ICMP redirects are not accepted****"

echo "****Run the following command to verify net.ipv4.conf.all.accept_redirects is set to 0****"

sysctl net.ipv4.conf.all.accept_redirects

echo "****Run the following command to verify net.ipv4.conf.default.accept_redirects is set to 0****"

sysctl net.ipv4.conf.default.accept_redirects

echo "****Run the following command to verify net.ipv6.conf.all.accept_redirects is set to 0****"

sysctl net.ipv6.conf.all.accept_redirects

echo "****Run the following command to verify net.ipv6.conf.default.accept_redirects is set to 0****"

sysctl net.ipv6.conf.default.accept_redirects

$SLEEP20s

echo "****Set the following parameters in /etc/sysctl.d/* file****"

printf "net.ipv4.conf.all.accept_redirects = 0 net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf

echo "Run the following command to set the active kernel parameters"

sysctl -w net.ipv4.conf.all.accept_redirects=0

sysctl -w net.ipv4.conf.default.accept_redirects=0

sysctl -w net.ipv4.route.flush=1

echo "****Set the following parameters in the /etc/sysctl.d/* file****"

printf "net.ipv6.conf.all.accept_redirects = 0 net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf 

echo "****Run the following command to set the active kernel parameters****"

sysctl -w net.ipv6.conf.all.accept_redirects=0 

sysctl -w net.ipv6.conf.default.accept_redirects=0 

sysctl -w net.ipv6.route.flush=1

echo "****Ensure secure ICMP redirects are not accepted****"

echo "****Run the following command to verify net.ipv4.conf.all.log_martians is to 0****"

sysctl net.ipv4.conf.default.secure_redirect

sysctl net.ipv4.conf.all.secure_redirects

$SLEEP20s

echo "****Set the following parameters in the /etc/sysctl.d/* file"

printf "net.ipv4.conf.all.secure_redirects = 0 net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf 

echo "****Run the following commands to set the active kernel parameters****"

sysctl -w net.ipv4.conf.default.secure_redirects=0

sysctl -w net.ipv4.conf.all.secure_redirects=0

sysctl -w net.ipv4.route.flush=1

echo "****Ensure suspicious packets are logged****"

echo "****Run the following command to verify net.ipv4.conf.all.log_martians is to 1****"

sysctl -a 2>/dev/null | grep net.ipv4.conf.all.log_martians

echo "****Run the following command to verify net.ipv4.conf.default.log_martians is to 1****"

sysctl -a 2>/dev/null | grep net.ipv4.conf.default.log_martians

$SLEEP20s

echo "****Set the following parameters in /etc/sysctl.d/* file****"

printf "net.ipv4.conf.all.log_martians = 1 net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf 

echo "****Run the following command to set the active kernel parameters****"

sysctl -w net.ipv4.conf.all.log_martians=1

sysctl -w net.ipv4.conf.default.log_martians=1

sysctl -w net.ipv4.route.flush=1

echo "****Ensure broadcast ICMP requests are ignored to reduce the risk or a Smurf Attack****"

echo "****Run the following command to verify net.ipv4.icmp_echo_ignore_broadcasts is to 1****"

sysctl -a 2>/dev/null | grep net.ipv4.icmp_echo_ignore_broadcasts

$SLEEP20s

echo "****Set the following parameters in /etc/sysctl.d/* file****"

printf "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf 

echo "****Run the following command to set the active kernel parameters****"

sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

sysctl -w net.ipv4.route.flush=1

echo "****Ensure bogus ICMP responses are ignored****"

echo "****Run the following command to verify net.ipv4.icmp_ignore_bogus_error_responses is to 1****"

sysctl -a 2>/dev/null | grep net.ipv4.icmp_ignore_bogus_error_responses

$SLEEP20s

echo "****Set the following parameter in /etc/sysctl.d/* file****"

printf "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf

echo "****Run the following command to set the active kernel parameters****"

sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1

sysctl -w net.ipv4.route.flush=1

echo "****Ensure Reverse Path Filtering is enabled ****"

echo "****Run the following command to verify net.ipv4.conf.all.rp_filter is to 1****"

sysctl -a 2>/dev/null | grep net.ipv4.conf.all.rp_filter

echo "****Run the followingRun the following command to verify net.ipv4.conf.default.rp_filter is to 1****"

sysctl -a 2>/dev/null | grep net.ipv4.conf.default.rp_filter

$SLEEP20s

echo "****Set the following parameters in the /etc/sysctl.d/* file****"

printf "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf 

echo "****Run the following commands to set the active kernel parameters****"

sysctl -w net.ipv4.conf.all.rp_filter=1

sysctl -w net.ipv4.conf.default.rp_filter=1

sysctl -w net.ipv4.route.flush=1

echo "****Ensure TCP SYN Cookies is enabled****"

echo "****Run the following command to verify net.ipv4.tcp_syncookies is to 1****"

sysctl -a 2>/dev/null | grep net.ipv4.tcp_syncookies

$SLEEP90s

echo "****Set the following parameters in /etc/sysctl.d/* file****"

printf "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf

echo "****Run the following command to set the active kernel parameters****"

sysctl -w net.ipv4.tcp_syncookies=1

sysctl -w net.ipv4.route.flush=1 

echo ****"Ensure IPv6 router advertisements are not accepted"****

echo ****"Run the following script to verify net.ipv6.conf.all.accept_ra is set to 0"****

sysctl -a 2>/dev/null | grep net.ipv6.conf.all.accept_ra

$SLEEP20s

echo "****Set the following parameters in /etc/sysctl.d/* file****"

printf "net.ipv6.conf.all.accept_ra = 0 net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf 

echo "****Run the following command to set the active kernel parameters****"

sysctl -w net.ipv6.conf.all.accept_ra=0 

sysctl -w net.ipv6.conf.default.accept_ra=0 

sysctl -w net.ipv6.route.flush=1

echo "****Ensure firewalld or iptables are installed"

echo "****Run the following command to verify that FirewallD and iptables are installed****"

rpm -q firewalld iptables

echo "****Run the following command to install FirewallD and iptables****"

$DNF_INSTALL firewalld iptables

#Check if client is using iptables

#echo "****Ensure iptables-services not installed with firewalld****"

#echo "****Running both firewalld and iptables/ip6tables service may lead to unexpected results****"

#rpm -q iptables-services

#systemctl stop iptables

#$DNF_REMOVE iptables-services

echo "****Ensure nftables either not installed or masked with firewalld****"

echo "****Run the following commend to verify that nftables is not installed****"

rpm -q nftables

echo "****Run the following commands to verify that nftables is inactive****"

systemctl is-active nftables

echo "****Run the following command to verify nftables.service is masked****"

systemctl is-enabled nftables

echo "****Run the following command to stop and mask nftables****"

systemctl --now mask nftables

echo "****Ensure firewalld service enabled and running****"

echo "****Run the following command to verify that firewalld is enabled****"

systemctl is-enabled firewalld

echo "****Run the following command to verify that firewalld is running****"

firewall-cmd --state

echo "****Run the following command to unmask firewalld****"

systemctl unmask firewalld 

echo "****Run the following command to enable and start firewalld****"

systemctl --now enable firewalld

echo "****Ensure firewalld default zone is set****"

echo "****Run the following command and verify that the default zone adheres to company policy****"

firewall-cmd --get-default-zone

$SLEEP20s

echo "****Run the following command to set the default zone****"

firewall-cmd --set-default-zone=public

#Check with client as to what interface is being used for what zone before making changes

#echo "****Ensure network interfaces are assigned to appropriate zone****"

#echo "****Run the following and verify that the interface follow site policy for zone assignment****"

#firewall-cmd --get-active-zones

#echo "****Run the following command to assign an interface to the approprate zone****"

#firewall-cmd --zone=pubic --change-interface=eth0 

#Check with client as to what services are allowed on each interface and each zone before making changes

#echo "****Ensure firewalld drops unnecessary services and ports****"

#echo "****Run the following command and review output to ensure that listed services and ports follow site policy.****"

# firewall-cmd --get-active-zones | awk '!/:/ {print $1}' | while read ZN; do firewall-cmd --list-all --zone=$ZN; done

#echo "****Run the following command to remove an unnecessary service****"

#firewall-cmd --remove-service=cockpit

#echo "****Run the following command to remove an unnecessary port****"

#firewall-cmd --remove-port=25/tcp

#echo "****Run the following command to make new settings persistent****"

#firewall-cmd --runtime-to-permanent

#Consult client as to whether they are using nftables or firewalld.  Running both nftables.service and firewalld.service may lead to conflict and unexpected results. 

#echo "****Ensure firewalld is either not installed or masked with nftables ****"

#echo "****Run the following command to verify that firewalld is not installed****"

#rpm -q firewalld

#echo "****Run the following command to verify that FirewallD is not running****"

#firewall-cmd >/dev/null && firewall-cmd --state | grep "running"

#echo "****Run the following command to verify that FirewallD is masked****"

#systemctl is-enabled firewalld 

#echo "****Run the following command to remove firewalld****"

#$DNF_REMOVE firewalld

#"****Run the following command to stop and mask firewalld****"

#systemctl --now mask firewalld

echo "****Ensure auditing is enabled****"

echo "****Ensure auditd is installed****"

echo "****Run the following command and verify auditd is installed****"

rpm -q audit

echo "****Run the following command to Install auditd****"

$DNF_INSTALL audit

echo "****Ensure auditd service is enabled****"

echo "****Run the following command to verify auditd is enabled****"

systemctl is-enabled auditd

echo "****Run the following command to enable auditd****"

systemctl --now enable auditd

echo "****Ensure auditing for processes that start prior to auditd is enabled****"

echo "****Verify that processes are capable of being audited can be audited even if they start up prior to auditd startup****"

find /boot -type f -name 'grubenv' -exec grep -P 'kernelopts=([^#\n\r]+\h+)?(audit=1)' {} \;

echo "****Run the following command to add audit=1 to GRUB_CMDLINE_LINUX****"

grubby --update-kernel ALL --args "audit=1"

echo "****Ensure audit_backlog_limit is sufficient****"

echo "****The backlog limit has a default setting of 64****"

echo "****Run the following command and verify the audit_backlog_limit= parameter is set to an appropriate size for your organization****"

find /boot -type f -name "grubenv" -exec grep -P "kernelopts=([^#\n\r]+\h+)?(audit_backlog_limit=\S+\b)" {} \;

echo "****Run the following command to add audit_backlog_limit=<BACKLOG SIZE> to GRUB_CMDLINE_LINUX****"

echo "****Recommended that this value be 8192 or larger****"

grubby --update-kernel ALL --args "audit_backlog_limit=8192"

echo "****Ensure audit log storage size is configured****"

echo "****Run the following command and ensure output is in compliance with site policy****"

grep -i "max_log_file" /etc/audit/auditd.conf

$SLEEP20s

echo "****Set the following parameter in /etc/audit/auditd.conf****"

sed -i "s/max_log_file = .*/max_log_file = 32/" /etc/audit/auditd.conf

echo "****Ensure audit logs are not automatically deleted****"

echo "****Run the following command and verify output matches****"

grep "max_log_file_action = keep_logs" /etc/audit/auditd.conf

$SLEEP20s

echo "****Set the following parameter in /etc/audit/auditd.conf****"

sed -i "s/max_log_file_action = .*/max_log_file_action = keep_logs/" /etc/audit/auditd.conf

echo "****Ensure system is disabled when audit logs are full ****"

echo "****Run the following commands****"

grep space_left_action /etc/audit/auditd.conf

grep action_mail_acct /etc/audit/auditd.conf

grep -E 'admin_space_left_action\s*=\s*(halt|single)' /etc/audit/auditd.conf 

$SLEEP20s

sed -i "s/space_left_action.*/space_left_action = email/" /etc/audit/auditd.conf

sed -i "s/action_mail_acct.*/action_mail_acct = root" /etc/audit/auditd.conf

sed -i 's/^admin_space_left_action.*/admin_space_left_action = halt/' /etc/audit/auditd.conf

echo "****Ensure changes to system administration sudoers is collected****"

echo "****Run the following command to check the on disk rules****"

grep -e "-w /etc/sudoers -p wa -k scope" /etc/audit/rules.d/audit.rules

grep -e "-w /etc/sudoers.d -p wa -k scope" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure actions as another user are always logged****"

echo "****On disk configuration Run the following commands to check the on disk rules****"

grep -e "-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation" /etc/audit/rules.d/audit.rules

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure events that modify the  log file are collected****"

echo "****Run the following command to check the on disk rules****"

grep -e "-w /var/log/.log -p wa -k _log_file" /etc/audit/rules.d/audit.rules

echo "****To ensure events that modify the  log file are collected in Red Hat Linux, you can use the following command to set up auditing for the log file****"

auditctl -w /var/log/.log -p wa -k -log-change

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure events that modify date and time information are collected****"

echo "****Run the following command to check the on disk rules****"

grep -e "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F arch=b64 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F arch=b32 -S clock_settime -k time-change" /etc/audit/rules.d/audit.rules

grep -e "-w /etc/localtime -p wa -k time-change" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure events that modify the systems network environment are collected****"

echo "****Run the following command to check loaded rules****"

grep -e "-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale" /etc/audit/rules.d/audit.rules

grep -e "-w /etc/issue -p wa -k system-locale" /etc/audit/rules.d/audit.rules

grep -e "-w /etc/issue.net -p wa -k system-locale" /etc/audit/rules.d/audit.rules

grep -e "-w /etc/hosts -p wa -k system-locale" /etc/audit/rules.d/audit.rules 

grep -e "-w /etc/sysconfig/network -p wa -k system-locale" /etc/audit/rules.d/audit.rules

grep -e "-w /etc/sysconfig/network-scripts/ -p wa -k system-locale" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure use of privileged commands are collected****"

echo "****Will traverse all mounted file systems that is not mounted with either noexec or nosuid mount options.****"

findmnt -n -l -k -it $(awk '/nodev/ { print "$2" }' /proc/filesystems | paste -sd,) | grep -Pv "noexec|nosuid"

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure unsuccessful file access attempts are collected****"

echo "****Monitor for unsuccessful attempts to access files. The following parameters are associated with system calls that control files****"

grep -e "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F arch=b32 -S open,truncate,ftruncate,creat,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F arch=b32 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure events that modify user/group information are collected****"

echo "****Record events affecting the modification of user or group information, including that of passwords and old passwords if in use****"

echo "****/etc/group - system groups****"

echo "****/etc/passwd - system users****"

echo "****/etc/gshadow - encrypted password for each group****"

echo "****/etc/shadow - system user passwords****"

echo "****/etc/security/opasswd - storage of old passwords if the relevant PAM module is in use****"

echo "****Run the following command to check the on disk rules****"

grep -e "-w /etc/group -p wa -k identity" /etc/audit/rules.d/audit.rules

grep -e "-w /etc/passwd -p wa -k identity" /etc/audit/rules.d/audit.rules

grep -e "-w /etc/gshadow -p wa -k identity" /etc/audit/rules.d/audit.rules

grep -e "-w /etc/shadow -p wa -k identity" /etc/audit/rules.d/audit.rules

grep -e "-w /etc/security/opasswd -p wa -k identity" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "Ensure discretionary access control permission modification events are collected"

echo "****Monitor changes to file permissions, attributes, ownership and group. The parameters in this section track changes for system calls that affect file permissions and attributes. The following commands and system calls effect the permissions, ownership and various attributes of files****" 

echo "****chmod***"

echo "****fchmod****"

echo "****fchmodat****"

echo "****chown****"

echo "****fchown****"

echo "****fchownat****"  

echo "****lchown****"  

echo "****setxattr****"  

echo "****lsetxattr****"

echo "****fsetxattr****" 

echo "****removexattr****" 

echo "****lremovexattr****"  

echo "****fremovexattr****" 

echo "****Run the following command to check the on disk rules****"

grep -e "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure successful file system mounts are collected****"

echo "****Run the following command to check the on disk rules****"

grep -e "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure session initiation information is collected****"

echo "****Run the following commands to check the on disk rules****"

grep -e "-w /var/run/utmp -p wa -k session" /etc/audit/rules.d/audit.rules

grep -e "-w /var/log/wtmp -p wa -k session" /etc/audit/rules.d/audit.rules

grep -e "-w /var/log/btmp -p wa -k session" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure login and logout events are collected****"

echo "****Run the following commands to check the on disk rules****"

grep -e "-w /var/log/lastlog -p wa -k logins" /etc/audit/rules.d/audit.rules

grep -e "-w /var/log/faillog -p wa -k logins" /etc/audit/rules.d/audit.rules

grep -e "-w /var/log/tallylog -p wa -k logins" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure file deletion events by users are collected****"

echo "****Run the following command to check the on disk rules****"

grep -e "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure events that modify the systems Mandatory Access Controls are collected****"

echo "****Run the following command to check the on disk rules****"

grep -e "-w /etc/selinux -p wa -k MAC-policy" /etc/audit/rules.d/audit.rules

grep -e "-w /usr/share/selinux -p wa -k MAC-policy" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure successful and unsuccessful attempts to use the chcon command are recorded****"

echo "****Run the following command to check the on disk rules****"

grep -e "-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure successful and unsuccessful attempts to use the setfacl command are recorded****"

echo "****Run the following command to check the on disk rules****"

grep -e "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure successful and unsuccessful attempts to use the chacl command are recorded****"

echo "****Run the following command to check the on disk rules****"

grep -e "-a always,exit -S all -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"


echo "****Ensure successful and unsuccessful attempts to use the usermod command are recorded****"

echo "****Run the following command to check the on disk rules****"

grep -e "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure kernel module loading unloading and modification is collected****"

echo "***Run the following commands to check the on disk rules****"

grep -e "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure the audit configuration is immutable****"

echo "****Run the following command and verify output matches****"

grep -e "-e 2" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****Write the audit rules file to /etc/audit/rules.d/audit.rules****"

cp /home/your_username/script/audit.rules /etc/audit/rules.d/

grep "^\s*[^#]" /etc/audit/rules.d/*.rules | tail -1

echo "****Ensure audit system is running and on disk configuration is the same****"

echo "****Ensure that all rules in /etc/audit/rules.d have been merged into /etc/audit/audit.rules****"

augenrules --check

echo "****Merge and load the rules into active configuration****"

augenrules --load

service auditd restart

chkconfig auditd on

echo "****List loaded rules****"

auditctl -l

service auditd status

echo "****Ensure cron daemon is enabled****"

echo "****Run the the following command to verify cron is enabled****"

systemctl is-enabled crond

echo "****Run the following command to enable cron****"

$SLEEP20s

systemctl --now enable crond

echo "****Ensure permissions on /etc/crontab are configured****"

echo "****Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other****" 

stat /etc/crontab

$SLEEP20s

echo "****Run the following commands to set ownership and permissions on /etc/crontab****"

chown root:root /etc/crontab

chmod og-rwx /etc/crontab

echo "****Ensure permissions on /etc/cron.hourly are configured****"

echo "****Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other****"

stat /etc/cron.hourly

$SLEEP20s

echo "****Run the following commands to set ownership and permissions on /etc/cron.hourly****"

chown root:root /etc/cron.hourly

chmod og-rwx /etc/cron.hourly

echo "****Ensure permissions on /etc/cron.daily are configured****"

echo "****Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other****"

stat /etc/cron.daily

$SLEEP20s

echo "****Run the following commands to set ownership and permissions on /etc/cron.daily****"

chown root:root /etc/cron.daily

chmod og-rwx /etc/cron.daily

echo "****Ensure permissions on /etc/cron.weekly are configured****"

echo "****Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other****"

stat /etc/cron.weekly

$SLEEP20s

echo "****Run the following commands to set ownership and permissions on /etc/cron.weekly****"

chown root:root /etc/cron.weekly

chmod og-rwx /etc/cron.weekly

echo "****Ensure permissions on /etc/cron.monthly are configured****"

echo "****Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other****"

stat /etc/cron.monthly

$SLEEP20s

echo "****Run the following commands to set ownership and permissions on /etc/cron.monthly****"

chown root:root /etc/cron.monthly

chmod og-rwx /etc/cron.monthly

echo "****Ensure permissions on /etc/cron.d are configured****"

echo "****Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other****"

stat /etc/cron.d

echo "****Run the following commands to set ownership and permissions on /etc/cron.d****"

chown root:root /etc/cron.d

chmod og-rwx /etc/cron.d

echo "Ensure cron is restricted to authorized users"

if [ ! -f /etc/cron.allow ]
then
	$SLEEP20s
	rm -f /etc/cron.deny
	touch /etc/cron.allow
	chown root:root /etc/cron.allow
	chmod u-x,go-rwx /etc/cron.allow
fi
$SLEEP20s

echo "****Ensure at is restricted to authorized users****"
if [ ! -f /etc/at.allow ]
then
	rm -f /etc/at.deny
	touch /etc/at.allow
	chown root:root /etc/at.allow
	chmod u-x,go-rwx /etc/at.allow
fi
$SLEEP20s

echo "****Ensure permissions on /etc/ssh/sshd_config are configured****"

echo "****Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other****"

stat /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following commands to set ownership and permissions on /etc/ssh/sshd_config****"

chown root:root /etc/ssh/sshd_config

chmod og-rwx /etc/ssh/sshd_config

echo "****Ensure permissions on SSH private host key files are configured****"

echo "****Run the following command and verify either****"

echo "****Uid is 0/root and Gid is /ssh_keys and permissions 0640 or more restrictive****"

echo "****OR Uid is 0/root and Gid is 0/root and permissions are 0600 or more restrictive****"

find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \;

$SLEEP20s

echo "****Run the following commands to set permissions, ownership, and group on the private SSH host key files****"

find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,g-wx,o-rwx {} \;

find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:ssh_keys {} \;

echo "****Ensure permissions on SSH public host key files are configured****"

echo "****Run the following command and verify Access does not grant write or execute permissions to group or other for all returned files****"

find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;

$SLEEP20s

echo "****Run the following commands to set permissions and ownership on the SSH host public key files****"

find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,go-wx {} \;

find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \; 

#Check with client to see if the site will allow limits as to who can access system via ssh

#echo "****Ensure SSH access is limited****"

#echo "****Run the following commands and verify the output****"

#sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$

#grep -Pi '^\h*(allow|deny)(users|groups)\h+\H+(\h+.*)?$' /etc/ssh/sshd_config

#$SLEEP20s

#echo "****Write to the following location****"

#cp /home/your_username/script/sshd_config /etc/ssh/ 

echo "****Ensure SSH PAM is enabled****"

echo "****Run the following command and verify that output matches****"

grep -i "UsePAM" /etc/ssh/sshd_config

$SLEEP20s

echo "Write the following file to /etc/ssh/sshd_config"

sed -i 's/UsePAM no/UsePAM yes/g' /etc/ssh/sshd_config

echo "****Ensure SSH LogLevel is appropriate****"

echo "****Run the following command and verify that output matches loglevel VERBOSE or loglevel INFO****"

grep -i "LogLevel" /etc/ssh/sshd_config

$SLEEP20s

echo "Write the following config to /etc/ssh/sshd_config"

sed -i 's/LogLevel INFO/LogLevel VERBOSE/g' /etc/ssh/sshd_config

echo "****Ensure SSH HostbasedAuthentication is disabled****"

echo "****Run the following command and verify that output matches****"

grep -i "HostbasedAuthentication" /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/HostbasedAuthentication yes/HostbasedAuthentication no/g' /etc/ssh/sshd_config

echo "****Ensure SSH PermitEmptyPasswords is disabled****"

echo "Run the following command and verify that output matches"

grep -i "PermitEmptyPasswords" /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/PermitEmptyPasswords yes/PermitEmptyPasswords no/g' /etc/ssh/sshd_config

echo "****Ensure SSH PermitUserEnvironment is disabled****"

echo "Run the following command and verify that output matches"

grep -i "PermitUserEnvironment" /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/PermitUserEnvironment yes/PermitUserEnvironment no/g' /etc/ssh/sshd_config

echo "****Ensure SSH IgnoreRhosts is enabled****"

echo "****Run the following command and verify that output matches****"

grep -i "IgnoreRhosts" /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/IgnoreRhosts no/IgnoreRhosts yes/g' /etc/ssh/sshd_config

#Ask client if X11Forwarding is utilized by admins per site policy

echo "****Ensure SSH X11 forwarding is disabled****"

echo "****Run the following command and verify that the output matches****"

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config

echo "****Ensure SSH AllowTcpForwarding is disabled****"

echo "****Run the following command and verify the output****"

grep -i "AllowTcpForwarding" /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/AllowTcpForwarding yes/AllowTcpForwarding no/g' /etc/ssh/sshd_config

echo "****Ensure system-wide crypto policy is not over-ridden****"

echo "****System-wide Crypto policy can be over-ridden or opted out of for openSSH****"

echo "****Over-riding or opting out of the system-wide crypto policy could allow for the use of less secure Ciphers, MACs, KexAlgorithms and GSSAPIKexAlgorithm****"

echo "****Run the following command****"

grep -i '^\s*CRYPTO_POLICY=' /etc/sysconfig/sshd

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/^CRYPTO_POLICY=/#&/' /etc/sysconfig/sshd

echo "****Ensure SSH MaxAuthTries is set to 4 or less****"

echo "****Run the following command and verify that output MaxAuthTries is 4 or less****"

grep -i "maxauthtries" /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/^#*\s*MaxAuthTries\s\+.*/MaxAuthTries 4/' /etc/ssh/sshd_config

echo "****Ensure SSH MaxStartups is configured****"

echo "****Run the following command and verify that output MaxStartups is 10:30:60 or more restrictive****"

grep -i "MaxStartups" /etc/ssh/sshd_config

$SLEEP20s

echo "****In the setting MaxStartups 10:30:60, the values are as follows****"

echo "****<start> is 10, meaning that the first 10 unauthenticated connection attempts will be allowed without any rate-limiting****"

echo "****<<rate> is 30, meaning that after the initial 10 connections, the server will allow up to 30 new unauthenticated connections per second****"

echo "****<<max> is 60, meaning that the maximum number of concurrent unauthenticated connections allowed at any given time is 60****"

echo "****Run the following command to remediate the security finding****"

sed -i 's/^#*\s*MaxStartups\s\+.*/MaxStartups 5:5:5/' /etc/ssh/sshd_config

echo "****Ensure SSH MaxSessions is set to 10 or less****"

echo "****Run the following command and verify that output MaxSessions is 10 or less****"

grep -i "MaxSessions" /etc/ssh/sshd_config

$SLEEP90s

echo "****Run the following command to remediate the security finding****"

sed -i 's/^#*\s*MaxSessions\s\+.*/MaxSessions 4/' /etc/ssh/sshd_config

echo "****Ensure SSH LoginGraceTime is set to one minute or less ****"

echo "****Run the following command and verify that output LoginGraceTime is between 1 and 60 seconds or 1m****"

grep -i "logingracetime" /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/^#*\s*LoginGraceTime\s\+.*/LoginGraceTime 1m/' /etc/ssh/sshd_config

#In some cases this setting may cause termination of long-running scripts over SSH or remote automation tools which rely on SSH. 

#echo "****Ensure SSH Idle Timeout Interval is configured****"

#grep -i "ClientAliveInterval" /etc/ssh/sshd_config

#grep -i "ClientAliveCountMax" /etc/ssh/sshd_config

#$SLEEP20s

#echo "****Run the following command to remediate the security finding****"

#sed -i 's/^#*\s*ClientAliveInterval\s\+.*/ClientAliveInterval 900/' /etc/ssh/sshd_config

#sed -i 's/^#*\s*ClientAliveCountMax\s\+.*/ClientAliveCountMax 10/' /etc/ssh/sshd_config

echo "****Ensure  is installed****"

$DNF_UPDATE dnf list  

$SLEEP20s

echo "****Run the following command to install ****"

$DNF_INSTALL 

echo "****Ensure commands use pty****"

echo "****Check the configuration of the /etc/sudoers file with the following command****"

grep -i "Defaults use_pty" /etc/sudoers

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

echo "Defaults use_pty" >> /etc/sudoers

echo "****Ensure sudoers log file exists****"

echo "****Check the configuration of the /etc/sudoers file with the following command****"

grep -rPi '^\h*Defaults\h+([^#\n\r]+,)?use_pty(,\h*\h+\h*)*\h*(#.*)?$' /etc/sudoers*

$SLEEP20s

"****The following security finding will be remediated shortly****"

echo "****Ensure users must provide password for escalation****"

echo "****Check the configuration of the /etc/sudoers file with the following command****"

grep -i "NOPASSWD" /etc/sudoers

$SLEEP20s

"****The following security finding will be remediated shortly****"

echo "****Ensure re-authentication for privilege escalation is not disabled globally****"

echo "****Check the configuration of the /etc/sudoers file with the following command****"

grep -i "authenticate" /etc/sudoers

$SLEEP20s

"****The following security finding will be remediated shortly****"

echo "****Ensure  authentication timeout is configured correctly****"

echo "****Ensure that the caching timeout is no more than 15 minutes****"

grep -roP "timestamp_timeout=\K[0-9]*" /etc/sudoers*

 -V | grep "Authentication timestamp timeout:"

$SLEEP20s

echo "****Run the following commands to remediate the security findings****"

sh -c 'echo "Defaults env_reset, timestamp_timeout=15" >> /etc/sudoers'

cp /home/your_username/script/sudoers /etc

#Ash the client if they would like a an empty group that will be specified for use of the su command. The group should be named according to site policy. 

#echo "****Ensure access to the su command is restricted****"

#echo "****Run the following command and verify the output matches the line*****"

#grep -i auth required pam_wheel.so use_uid /etc/pam.d/su

#echo "****Create an empty group that will be specified for use of the su command. The group should be named according to site policy****"

#groupadd sugroup

#echo "auth required pam_wheel.so use_uid group=sugroup" |  tee -a /etc/pam.d/su

echo "****Ensure password creation requirements are configured****" 

echo "****Verify password creation requirements conform to organization policy****"

grep  pam_pwquality.so /etc/pam.d/system-auth /etc/pam.d/password-auth

echo "****Run the following commands and verify password length requirements conform to organization policy****"

grep -i "minlen" /etc/security/pwquality.conf

echo "****Run one of the following commands and verify that password complexity conforms to organization policy****"

grep -i "minclass" /etc/security/pwquality.conf

$SLEEP20s

echo "****Write to the following command for password length to conform to site policy****"

sed -i 's/^#*\s*minlen\s*=.*/minlen = 14/' /etc/security/pwquality.conf

echo "****Write to the following command for password length to conform to site policy****"

sed -i 's/^#*\s*minclass\s*=.*/minclass = 4/' /etc/security/pwquality.conf

echo "****Ensure lockout for failed password attempts is configured****"

echo "****Run the following command to verify that Number of failed logon attempts before the account is locked is no greater than 5****"

grep -i "deny =" /etc/security/faillock.conf

echo "****Run the following command to verify that the time in seconds before the account is unlocked is either 0 never or 900 or more****"

grep -i "unlock_time = 900" /etc/security/faillock.conf

$SLEEP20s

echo "****Write to the following file /etc/security/faillock.conf to remediate the security finding****"

sed -i 's/deny = 3/deny = 5/g' /etc/security/faillock.conf

sed -i 's/^unlock_time\s*=.*/unlock_time = 600/' /etc/security/faillock.conf

echo "****Ensure password reuse is limited****"

echo "****Run the following commands and verify that the remembered password history is 5 or more****"

grep -i "pam_pwhistory.so try_first_pass local_users_only" /etc/pam.d/system-auth

grep -i "pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5" /etc/pam.d/system-auth

$SLEEP20s

echo "****writes the following values to /etc/pam.d/system-auth****"

sed -i '$apassword   requisite    pam_pwhistory.so try_first_pass local_users_only enforce_for_root retry=3 remember=5' /etc/pam.d/system-auth

sed -i '$apassword   sufficient   pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5' /etc/pam.d/system-auth

echo "****Ensure password hashing algorithm is SHA-512****"

echo "****Run the following command to verify the hashing algorithm is sha512 in /etc/libuser.conf***"

grep -i "crypt_style = sha512" /etc/libuser.conf 

echo "****Run the following command to verify the hashing algorithm is sha512 in /etc/login.defs****"

grep -i "ENCRYPT_METHOD SHA512" /etc/login.defs

echo "****Run the following command to verify the hashing algorithm is configured with pam_unix.so in /etc/pam.d/system-auth and /etc/pam.d/password-auth****"

grep -i "pam_unix.so.*sha512" /etc/pam.d/system-auth /etc/pam.d/password-auth

$SLEEP20s

echo "***Set password hashing algorithm to sha512 in /etc/libuser.conf*****"

sed -i 's/ENCRYPT_METHOD DES/ENCRYPT_METHOD SHA512/' /etc/libuser.conf

echo "****Write the following value to /etc/login.defs****"

sed -i '$a ENCRYPT_METHOD SHA512' /etc/login.defs

echo "****Run the following command to configure pam_unix.so to use the sha512 hashing algorithm****"

sed -i 's/\(password.*pam_unix.so.*\)$/\1 sha512/' /etc/pam.d/system-auth /etc/pam.d/password-auth

echo "****Ensure password expiration is 365 days or less****"

echo "****Run the following command and verify PASS_MAX_DAYS conforms to site policy no more than 365 days****"

grep PASS_MAX_DAYS /etc/login.defs

echo "****Run the following command and Review list of users and PASS_MAX_DAYS to verify that all users' PASS_MAX_DAYS conforms to site policy (no more than 365 days)****"

grep -E '^[^:]+:[^!*]' /etc/shadow | cut -d: -f1,5

$SLEEP20s

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs

echo "****Ensure minimum days between password changes is 7 or more****"

echo "****Run the following command and verify PASS_MIN_DAYS conforms to site policy (no less than 7 days****"

grep ^\s*PASS_MIN_DAYS /etc/login.defs

echo "****Run the following command and Review list of users and PASS_MIN_DAYS to Verify that all users' PASS_MIN_DAYS conforms to site policy no less than 7 days****"

grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,4

$SLEEP20s

echo "*****Write the following value PASS_MIN_DAYS parameter to 5 in /etc/login.defs*****"

sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 5/' /etc/login.defs

#echo "****Modify user parameters for a users with a password set to match****"

#chage --mindays 7 <user>

echo "****Ensure password expiration warning days is 7 or more****"

echo "****Run the following command and verify PASS_WARN_AGE conforms to site policy (No less than 7 days)****"

grep -i PASS_WARN_AGE /etc/login.defs 

echo "****Run the following command and Review list of users and PASS_WARN_AGE to verify that all users' PASS_WARN_AGE conforms to site policy (No less than 7 days)****"

grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,6 

echo "****Write the following value PASS_WARN_AGE parameter to 7 in /etc/login.defs****" 

sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 5/' /etc/login.defs

#echo "****Modify user parameters for a users with a password set to match****"

#chage --warndays 7 <user>

echo "****Ensure inactive password lock is 30 days or less****"

echo "****Run the following command and verify INACTIVE conforms to site policy (no more than 30 days)****"

useradd -D | grep INACTIVE

echo "****Verify all users with a password have Password inactive no more than 30 days after password expires****"

awk -F: '/^[^#:]+:[^\!\*:]*:[^:]*:[^:]*:[^:]*:[^:]*:(\s*|-1|3[1-9]|[4-9][0-9]|[1-9][0-9][0-9]+):[^:]*:[^:]*\s*$/ {print $1":"$7}' /etc/shadow

$SLEEP20s

echo "****Run the following command to set the default password inactivity period to 1 day****"

useradd -D -f 15

#echo "****Modify user parameters for a users with a password set to match****"

#chage --inactive 30 <user>

echo "****Ensure all users last password change date is in the past****"

echo "****If a users recorded password change date is in the future then they could bypass any set password expiration****"

echo "****Run the following command and verify nothing is returned****"

 awk -F: '/^[^:]+:[^!*]/{print $1}' /etc/shadow | while read -r usr; do change=$(date -d "$(chage --list "$usr" | grep '^Last password change' | cut -d: -f2 | grep -v 'never$')" +%s); if [[ "$change" -gt "$(date +%s)" ]]; then echo "User: \"$usr\" last password change was \"$(chage --list "$usr" | grep '^Last password change' | cut -d: -f2)\""; fi; done

echo "****Investigate any users with a password change date in the future and correct them. Locking the account, expiring the password, or resetting the password manually may be appropriate****"

echo "****Ensure system accounts are secured****"

echo "****Run the following commands and verify no results are returned****"

 awk -F: '$1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/ {print $1}' /etc/passwd

 awk -F: '$1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '$2!="L" && $2!="LK" {print $1}'

$SLEEP20s

#echo "****Set the shell for any accounts returned by the audit to nologin****"

#usermod -s $(which nologin) <user>

#echo "****Lock any non root accounts returned by the audit****"

#usermod -L <user>

echo "****The following command will set all system accounts to a non login shell****"

 awk -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { system("usermod -s $(which nologin) " $1) }' /etc/passwd

#echo "****The following command will automatically lock not root system accounts****"

# awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' sh -c 'passwd -S "$1" | awk '"'"'($2!="L" && $2!="LK") {print $1}'"'"'' - '{}' | while read user; do usermod -L "$user"; done

#In some cases this setting may cause termination of long-running scripts in a shell or automation which rely on a shell to function consult client first.

#echo "****Ensure default user shell timeout is 900 seconds or less****"

#echo "****Run the following script to verify that TMOUT is configured to: include a timeout of no more than 900 seconds, to be readonly, to be exported, and is not being changed to a longer timeout****"

#grep -i "readonly TMOUT=900 export TMOUT" /etc/bashrc

#grep -i "readonly TMOUT=900 export TMOUT" /etc/profile

#$SLEEP20s

#echo "****Write all TMOUT=_n_ entries to follow local site policy. TMOUT should not exceed 900 or be equal to 0****"

#echo 'TMOUT=900' 'readonly TMOUT' 'export TMOUT' |  tee -a /etc/profile

#echo 'TMOUT=900' 'readonly TMOUT' 'export TMOUT' |  tee -a /etc/bashrc

echo "****Ensure default group for the root account is GID 0****"

echo "****Run the following command and verify the result is 0****"

grep "^root:" /etc/passwd | cut -f4 -d:

$SLEEP20s

echo "****Run the following command to set the root account default group to GID 0****"

usermod -g 0 root 

echo "****Ensure default user umask is 027 or more restrictive****"

grep -E "^umask\s+027" /etc/profile.d/umask.sh

$SLEEP20s

echo "****configure the default user umask to 027 or more restrictive system-wide****"

echo "umask 027" | tee -a /etc/profile.d/umask.sh


#Consult the client and verift if auditing .rpm file permissions at acceptable

#echo "****Audit system file permissions****"

#echo "****The rpm -qf command can be used to determine which package a particular file belongs to****"

# rpm -qf /bin/bash

#$SLEEP20s

#"****Run the following command to review all installed packages. ****"

#rpm -Va --nomtime --nosize --nomd5 --nolinkto > /home/your_username/rpm.txt

#Let the client know that the sticky bit can cause issues when multiple users are sharing a directory



echo "****Ensure sticky bit is set on all world-writable directories****"

echo "****Run the following command to verify no world writable directories exist without the sticky bit set****"

df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null 

$SLEEP20s 

echo "****Run the following command to set the sticky bit on all world writable directories****"

df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}' 

echo "****Ensure permissions on /etc/passwd are configured****"

echo "****Run the following command and verify Uid and Gid are both 0/root and Access is 644 or more restrictive****"

stat /etc/passwd

$SLEEP20s

echo "****Run the following command to set permissions on /etc/passwd****"

chown root:root /etc/passwd

chmod 644 /etc/passwd

echo "****Ensure permissions on /etc/shadow are configured****"

echo "****Run the following command and verify Uid and Gid are 0/root , and Access is 0000****"

stat /etc/shadow

$SLEEP20s

echo "****Run the following commands to set owner, group, and permissions on /etc/shadow****"

chown root:root /etc/shadow

chmod 0000 /etc/shadow

echo "****Ensure permissions on /etc/group are configured****"

echo "****Run the following command and verify Uid and Gid are both 0/root and Access is 644 or more restrictive****"

stat /etc/group

$SLEEP20s

echo "****Run the following commands to set owner, group, and permissions on /etc/group****"

chown root:root /etc/group

chmod u-x,g-wx,o-wx /etc/group

echo "****Ensure permissions on /etc/gshadow****"

echo "****Run the following command and verify verify Uid is 0/root, Gid is 0/root or <gid>/shadow, and Access is 0000****"

stat /etc/gshadow

echo "****Run the following commands to set owner, group, and permissions on /etc/gshadow****"

chown root:root /etc/gshadow

chmod 0000 /etc/gshadow

#echo Removing write access for the "other" category ( chmod o-w <filename> ) is advisable, but always consult with the client to avoid breaking any application dependencies on a given file. 

#echo "****Ensure no world writable files exist****"

#echo "****Run the following command and verify no files are returned****"

#df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 > /var/log/world_writable_files.log

#$SLEEP20s

#echo"****finds world-writable files on the system and then execute the chmod command to remove write permission for others****"

#find / -perm -o+w -type f -exec chmod o-w {} \;

#Locate files that are owned by users or groups not listed in the system configuration files, and reset the ownership of these files to some active user on the system as appropriate

echo "****Ensure no unowned files or directories exist****"

echo "****Run the following command and verify that no unowned files or directories exist****"

df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser > /var/log/unowned_files_dirs_audit.log

echo "****Locate files that are owned by users or groups not listed in the system configuration files and reset the ownership of these files to some active user on the system as appropriate****"

echo "****Ensure no ungrouped files or directories exist****"

echo "****Runnning the following command will look for any ungrouped files to and audit.log file****"

df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup > /var/log/ungrouped_files_audit.log

echo "****Locate files that are owned by users or groups not listed in the system configuration files and reset the ownership of these files to some active user on the system as appropriate****"

echo "****Audit SUID executables****"

echo "****Run the following command to list SUID files and write the findings to /var/log/suid_audit.txt****"

# NOTE '-path ... -prune' remove the directory from the find, there were error going into /proc

find / -path /proc -prune -o -perm /4000 -type f -exec ls -la {} \; > /var/log/suid_audit.log

echo "****Audit SGID executables****"

echo "****Run the following command to list and audit SGID files****"

df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000 > /var/log/sgid_audit.log

echo "****Ensure that no rogue SGID programs have been introduced into the system. Review the files returned by the action in the Audit section and confirm the integrity of these binaries****"

echo "****Ensure password fields are not empty****"

awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow > /var/log/empty_password_fields_audit.log

echo "****If any accounts in the /etc/shadow file do not have a password, run the following command to lock the account until it can be determined why it does not have a password****"

#passwd -l <username>

echo "****Ensure all groups in /etc/passwd exist in /etc/group****"

echo "****Run the following commad to audit and verify that all groups in /etc/passwd exist in /etc/group"

for i in $(cut -d: -f4 /etc/passwd | sort -u); do grep -q "^.*:.*:$i:" /etc/group || groupadd -g $i $(getent passwd $i | cut -d: -f1); done > /var/log/passwd_grp_audit.log

echo "****Analyze the output of the Audit step above and perform the appropriate action to correct any discrepancies found****"

echo "****Ensure no duplicate UIDs exist****"

echo "The following single command is used to ensure and audit that no duplicate UIDs exist in /etc/passwd"

awk -F: '{print $3}' /etc/passwd | sort | uniq -d | while read dup_uid; do echo "Duplicate UID $dup_uid found in /etc/passwd"; done > /var/log/duplicate_uid_audit.log

echo "****Based on the results of the audit script, establish unique UIDs and review all files owned by the shared UIDs to determine which UID they are supposed to belong to****"

echo "****Ensure no duplicate GIDs exist****"

echo "The following single command is used to ensure and audit that no duplicate GIDs exist in /etc/group"

awk -F: '{print $3}' /etc/group | sort | uniq -d | while read dup_gid; do echo "Duplicate GID $dup_gid found in /etc/group"; done > /var/log/duplicate_gid_audit.log

echo "****Based on the results of the audit script, establish unique GIDs and review all files owned by the shared GID to determine which group they are supposed to belong to****"

echo "****Ensure no duplicate user names exist****"

echo "The following single command used to ensure and audit that no duplicate user names exist"

awk -F: '{print $1}' /etc/passwd | sort | uniq -d > /var/log/duplicate_users_audit.log

echo "****Ensure no duplicate group names exist****"

echo "The following single command used to ensure and audit that no duplicate groups exist"

awk -F: '{print $1}' /etc/group | sort | uniq -d > /var/log/duplicate_groups_audit.log

echo "****Ensure root PATH Integrity****"

echo "The following single command used to ensure and audit root path integrity"

echo $PATH | grep -q -E '(^|:)/usr/local/(s?bin)(:|$)' && echo "Integrity check passed" || echo "Integrity check failed"

echo "****Ensure root is the only UID 0 account****"

echo "****Run the following command and verify that only "root" is returned****"

awk -F: '($3 == 0) { print $1 }' /etc/passwd

echo "****Ensure all users' home directories exist****"

echo "****Run the following command and verify no results are returned****"

awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) {print $6}' /etc/passwd | while read -r dir; do [ -d "$dir" ] || echo "Home directory $dir does not exist."; done > /var/log/user_home_directories_present_audit.log

echo "****Ensure users own their home directories****"

find /home -mindepth 1 -maxdepth 1 -type d ! -user root -exec echo "Incorrect ownership: {}" \;

echo "****Creates missing home directories, set the owner, and set the permissions for interactive users' home directories****" 

getent passwd | awk -F: '$3 >= 1000 && $7 ~ /^\/home/ { system("mkdir -p " $7); system("chown " $1 ":" $1 " " $7); system("chmod 700 " $7) }'

echo "****Ensure users' .netrc Files are not group or world accessible****"

echo "****Run the following script and verify no results are returned****"

find /home -name .netrc -perm /go+rwx > /var/log/user_netrc_file_ww_audit.log

$SLEEP20s

"****Command that will remove .netrc files from interactive users' home directories ****"

find /home -type f -name ".netrc" -delete

echo "****Ensure no users have .forward files****"

echo "****Run the following script and verify no results are returned****"

find /home -maxdepth 2 -name ".forward" -print > /var/log/user_forward_file_audit.log

echo "****The following command remove .forward files from interactive users' home directories****"

$SLEEP20s

find /home -type f -name ".forward" -exec rm {} +

echo "****Ensure no users have .rhosts files****"

echo "****Run the following script and verify no results are returned****"

find /home -maxdepth 2 -name ".rhosts" -print > /var/log/user_rhost_file_audit.log

$SLEEP20s

echo "****To remove .rhosts files from interactive users' home directories****"

find /home -type f -name ".rhosts" -delete

echo "****Ensure SSH root login is disabled****"

echo "***Run the following command and verify that output matches***"

sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permitrootlogin 

echo "****Run the following command and verify the output****"

grep -Ei '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config

echo "****Ensure updates, patches, and additional security software are installed****"

dnf check-update 

echo "****Install security updates****"

$DNF_UPDATE --security

#Ask the client if it is even possible to make changes to /etc/fstab

#This security control may be implemented on a new system with less admin effort

#echo "****Ensure /tmp is a separate partition****"

#findmnt --kernel /tmp

#"****Ensure that systemd will mount the /tmp partition at boot time****"

#systemctl is-enabled tmp.mount

#echo "****Ensure nosuid,nodev,noexec options set on /tmp partition****"

#findmnt --kernel /tmp | grep nodev

#findmnt --kernel /tmp | grep nosuid 

#findmnt --kernel /tmp | grep noexec

#echo "****Ensure /home is a separate partition****"

#findmnt --kernel /home

#"****Ensure that systemd will mount the /home partition at boot time****"

#systemctl is-enabled home.mount

#echo "****Ensure nosuid,nodev,noexec options set on /home partition****"

#findmnt --kernel /home | grep nodev 

#findmnt --kernel /home | grep nosuid 

#findmnt --kernel /home | grep noexec

#echo "****Ensure /var is a separate partition****"

#findmnt --kernel /var

#"****Ensure that systemd will mount the /var partition at boot time****"

#systemctl is-enabled var.mount

#echo "****Ensure nosuid,nodev,noexec options set on /var partition****"

#findmnt --kernel /var | grep nodev

#findmnt --kernel /var | grep nosuid

#findmnt --kernel /var | grep noexec

#echo "****Ensure /dev/shm is a separate partition****"

#findmnt --kernel /dev/shm

#echo "****Ensure nosuid,nodev,noexec options set on /dev/shm partition****"

#findmnt --kernel /dev/shm | grep nodev

#findmnt --kernel /dev/shm | grep nosuid

#findmnt --kernel /dev/shm | grep noexec

#cp /home/your_username/script/fstab /etc/fstab

#echo "****Run the following commands to remount /tmp /home/ /var /dev/shm with the configured options****"

#mount -o remount /tmp 

#mount -o remount /home

#mount -o remount /var

#mount -o remount /dev

#Ask the client if they require a central logging server

#echo "****Ensure rsyslog is installed****"

#echo "****Verify rsyslog is installed****"

#rpm -q rsyslog

#$SLEEP20s

#echo "****Run the following command to install rsyslog****"

#$DNF_INSTALL rsyslog

#echo "****Ensure rsyslog service is enabled****"

#echo "****Run the following command to verify rsyslog is enabled****"

#systemctl is-enabled rsyslog

#$SLEEP20s

#echo "****Run the following command to enable rsyslog****"

#systemctl --now enable rsyslog

# echo "****Ensure logging is configured****"

# echo "****Run the following command and verify that the log files are logging information as expected****"

#ls -l /var/log/ 

#$SLEEP20s

#echo "****Writes the following paramaters to /etc/rsyslog.conf to set the following config****"

#*.emerg                                  :omusrmsg:*
#auth,authpriv.*                          /var/log/secure
#mail.*                                  -/var/log/mail
#mail.info                               -/var/log/mail.info
#mail.warning                            -/var/log/mail.warn
#mail.err                                 /var/log/mail.err
#cron.*                                   /var/log/cron
#*.=warning;*.=err                       -/var/log/warn
#*.crit                                   /var/log/warn
#*.*;mail.none;news.none                 -/var/log/messages
#local0,local1.*                         -/var/log/localmessages
#local2,local3.*                         -/var/log/localmessages
#local4,local5.*                         -/var/log/localmessages
#local6,local7.*                         -/var/log/localmessages

#cp /home/your_username/script/rsyslog.conf /etc/

#echo "****Ensure journald is configured to send logs to rsyslog****"

#echo "****Review /etc/systemd/journald.conf and verify that logs are forwarded to rsyslog****"

#grep ^\s*ForwardToSyslog /etc/systemd/journald.conf

#$SLEEP20s

#echo "****Write the following file to /etc/systemd/journald.conf****"

#sed -i "s/ForwardToSyslog=no/ForwardToSyslog=yes/" /etc/systemd/journald.conf

#systemctl restart rsyslog

#echo "****Ensure rsyslog default file permissions are configured****"

#echo "****Run the following command****"

#grep ^\$FileCreateMode /etc/rsyslog.conf

#$SLEEP20s

#echo "****Write the following file to /etc/rsyslog.con to set $FileCreateMode to 0640****"

#sed -i "s/FileCreateMode.*/FileCreateMode 0640/" /etc/rsyslog.conf

#****Ensure rsyslog is configured to send logs to a remote log host****"

#"****verify that logs are sent to a central host (where loghost.example.com is the name of your central log host****"

#grep "^*.*[^I][^I]*@" /etc/rsyslog.conf

#New format 

#grep -i "target" /etc/rsyslog.conf

#grep -i "action.resumeRetryCount" /etc/rsyslog.conf

#grep -i "queue.type" /etc/rsyslog.conf

#$SLEEP20s

#"Change the following settings within /etc/rsyslog.conf and save the config to /etc/rsyslog.conf"

#*.* action(type="omfwd" target="192.168.2.100" port="514" protocol="tcp"
          # action.resumeRetryCount="100"
	  # queue.type="LinkedList" queue.size="1000")

#sed -i 's/action(type="omfwd"/*.* action(type="omfwd" target="192.168.2.100" port="514" protocol="tcp"/' /etc/rsyslog.conf

#sed -i 's/action.resumeRetryCount="-1"/action.resumeRetryCount="100"/' /etc/rsyslog.conf

#sed -i 's/queue.type="LinkedList"/queue.type="LinkedList" queue.size="1000"/' /etc/rsyslog.conf

#echo "****Ensure rsyslog is not configured to recieve logs from a remote client****"

#echo "***verifies that the system is not configured to accept incoming logs****"

#Old format

#grep -i '$ModLoad imtcp' /etc/rsyslog.conf 

#grep -i '$InputTCPServerRun' /etc/rsyslog.conf

#New format

#grep -P -- '^\h*module\(load="imtcp"\)' /etc/rsyslog.conf 

#grep -P -- '^\h*input\(type="imtcp" port="514"\)' /etc/rsyslog.conf 

#$SLEEP20s

#echo "****The following values need to be uncommented from /etc/rsyslog.conf****"
#module(load="imtcp")

#input(type="imtcp" port="514")

#echo "****The config will be written to /etc/rsyslog.conf****"

#sed -i 's/\$ModLoad imtcp/module(load="imtcp")/' /etc/rsyslog.conf

#sed -i 's/\$InputTCPServerRun/input(type="imtcp" port="514")/' /etc/rsyslog.conf

#echo "****Restart the service the rsyslog service****" 

#systemctl restart rsyslog

#Ask client if they would like logfiles sent to a remote host

#echo "****Ensure systemd-journal-remote is installed****"

#rpm -q systemd-journal-remote

#$SLEEP20s

#echo "****Run the following command to install systemd-journal-remote****"

#$DNF_INSTALL systemd-journal-remote

#echo "****Ensure systemd-journal-remote is configured****"

#echo "****Verify systemd-journal-remote is configured****"

#grep -P "^ *URL=|^ *ServerKeyFile=|^ *ServerCertificateFile=|^ *TrustedCertificateFile=" /etc/systemd/journal-upload.conf

#$SLEEP20s

#echo "****Write t the etc/systemd/journal-upload.conf file and ensure the following lines are set per your environment****"

#sed -i 's/^URL=.*/URL=10.0.0.135/g' /etc/systemd/journal-upload.conf

#sed -i 's/^ServerKeyFile=.*/ServerKeyFile=\/etc\/ssl\/private\/journal-upload.pem/g' /etc/systemd/journal-upload.conf

#sed -i 's/^ServerCertificateFile=.*/ServerCertificateFile=\/etc\/ssl\/certs\/journal-upload.pem/g' /etc/systemd/journal-upload.conf

#sed -i 's/^TrustedCertificateFile=.*/TrustedCertificateFile=\/etc\/ssl\/ca\/trusted.pem/g' /etc/systemd/journal-upload.conf

#echo "****Ensure systemd-journal-remote is enabled****"

#echo "****Verify systemd-journal-remote is enabled, run the following command****"

#systemctl is-enabled systemd-journal-upload.service 

#$SLEEP20s

#echo "Run the following command to enable systemd-journal-remote"

#systemctl --now enable systemd-journal-upload.service 

#echo "Ensure journald is not configured to recieve logs from a remote client"

#echo "****Run the following command to verify systemd-journal-remote.socket is not enabled****"

#systemctl is-enabled systemd-journal-remote.socket

#$SLEEP20s

#echo "****Run the following command to verify systemd-journal-remote.socket is not enabled****"

#systemctl --now mask systemd-journal-remote.socket

#echo "****Ensure journald service is enabled****"

#echo "****Run the following command to verify systemd-journald is enabled****"

#$SLEEP20s

#systemctl is-enabled systemd-journald.service

#echo "****Ensure journald is configured to compress large log files****"

#echo "****Review /etc/systemd/journald.conf and verify that large files will be compressed****"

#grep ^\s*Compress /etc/systemd/journald.conf

#$SLEEP20s

#echo "****Write to the file /etc/systemd/journald.conf****"

#sed -i 's/^Compress=.*/Compress=yes/g' /etc/systemd/journald.conf

#echo "****Ensure journald is configured to write logfiles to persistent disk****"

#echo "****Review /etc/systemd/journald.conf and verify that logs are persisted to disk****"

#grep ^\s*Storage /etc/systemd/journald.conf

#$SLEEP20s

#echo "****Write to the file /etc/systemd/journald.conf****"

#sed -i 's/^Storage=.*/Storage=persistent/g' /etc/systemd/journald.conf

#echo "****Ensure journald is not configured to send logs to rsyslog****"

#echo "****Review /etc/systemd/journald.conf and verify that logs are not forwarded to rsyslog****"

#grep ^\s*ForwardToSyslog /etc/systemd/journald.conf 

#$SLEEP20s

#sed -i 's/^ForwardToSyslog=.*/ForwardToSyslog=no/g' /etc/systemd/journald.conf

#echo "****Ensure journald log rotation is configured per site policy****"

#echo "****Review /etc/systemd/journald.conf and verify logs are rotated according to site policy****"

#grep ^\s*SystemMaxUse /etc/systemd/journald.conf 

#grep ^\s*SystemKeepFree /etc/systemd/journald.conf

#grep ^\s*RuntimeMaxUse /etc/systemd/journald.conf

#grep ^\s*RuntimeKeepFree /etc/systemd/journald.conf

#grep ^\s*MaxFileSec /etc/systemd/journald.conf

#echo "****Write to the file /etc/systemd/journald.conf****"

#sed -i 's/^SystemMaxUse=.*/SystemMaxUse=5G/g' /etc/systemd/journald.conf

#sed -i 's/^SystemKeepFree=.*/SystemKeepFree=5G/g' /etc/systemd/journald.conf

#sed -i 's/^RuntimeMaxUse=.*/RuntimeMaxUse=5G/g' /etc/systemd/journald.conf

#sed -i 's/^RuntimeKeepFree=.*/RuntimeKeepFree=5G/g' /etc/systemd/journald.conf

#sed -i 's/^MaxFileSec=.*/MaxFileSec=3m/g' /etc/systemd/journald.conf

#echo "****Ensure journald default file permissions configured ****"

#echo "****Verify if there is an override file /etc/tmpfiles.d/systemd.conf****"

#ls -la /etc/tmpfiles.d/systemd.conf

#echo "****If there is no override file, inspect the default /usr/lib/tmpfiles.d/systemd.conf****"

#$SLEEP20s

#echo "****"Ensure that file permissions are 0640"****"

#ls -la /usr/lib/tmpfiles.d/systemd.conf

#echo "****run the following command to configure the permissions for systemd.conf****"

##chmod 0640 /usr/lib/tmpfiles.d/systemd.conf

#echo "****Ensure permissions on all logfiles are configured****"

#echo "****Run the following commands and verify that the other scope has no permissions on any files and the group scope does not have write or execute permissions on any files****"

#find /var/log/ -type f -perm /g+wx,o+rwx -exec ls -l "{}" +

#echo "****Run the following command to set permissions on all existing log files in /var/log****"

#find /var/log/ -type f -perm /g+wx,o+rwx -exec chmod --changes g-wx,o-rwx "{}" + 

#echo "****Ensure logrotate is configured****"

#echo "****Review /etc/logrotate.conf  and verify logs are rotated according to site policy****"

#grep -E "rotate" /etc/logrotate.conf

#echo "****Write the folloing file /etc/logrotate.conf to ensure logs are rotated according to site policy****"

#sh -c 'echo "/var/log/system.log {rotate 4 daily maxage 90 missingok notifempty create 0644 root root}" >> /etc/logrotate.conf'

#echo "****Restart the journal-upload service****"

#systemctl restart systemd-journal-upload 












