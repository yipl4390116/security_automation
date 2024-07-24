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

# NOTE: Remopve the '-y' if you want to run 'apt' interactively

$APT_INSTALL="apt install -y"
$APT_PURGE="apt purge -y"
$APT_UPDATE="apt update -y"

echo "****Ensure GDM disable user list option is enabled****"

echo "****Run the following script and to verify that the disable-user-list option is enabled****"

grep -i disable-user-list=true /etc/dconf/db/gdm.d/00-login-screen

$SLEEP20s

echo "****Run the following commands to implement the disable-user-list option****"

sh -c 'l_gdmprofile="gdm"; [ ! -f "/etc/dconf/profile/$l_gdmprofile" ] && echo -e "user-db:user\nsystem-db:$l_gdmprofile\nfile-db:/usr/share/$l_gdmprofile/greeter-dconf-defaults" > /etc/dconf/profile/$l_gdmprofile'

mkdir -p /etc/dconf/db/gdm.d

echo -e "[org/gnome/login-screen]\ndisable-user-list=true" | tee /etc/dconf/db/gdm.d/00-login-screen

dconf update

echo "****Removes the default ssh keys from Ubuntu server****"

rm -f /etc/ssh/*key*

echo "****Creates a fresh set of ssh keys for good measure****"

ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key

ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key

ssh-keygen -t ecdsa -f /etc/ssh/ssh_host_ecdsa_key

echo "****Setup Fail2Ban****"

apt install fail2ban -y

cp /home/your_username/uscript/jail.local /etc/fail2ban/

systemctl enable --now fail2ban

systemctl status fail2ban

echo "****Ensure mounting of cramfs filesystems is disabled****"

dpkg -l | grep cramfs

$SLEEP20s

apt remove cramfsprogs

#Ask if client is using squashfs, As Snap packages utilizes squashfs as a compressed filesystem, disabling squashfs will cause Snap packages to fail.

#echo "****Ensure mounting of squashfs filesystems is disabled****"

#echo "****Step 1 audit for squashfs****"

#dpkg -l | grep squahfs

#$SLEEP20s

#apt remove squashfs-tools

#Ask if client is using udf filesystem, As Microsoft Azure requires the usage of udf, and offloading the use of this filesystem should not be done on systems run on Microsoft Azure

echo "****Ensure mounting of the udf filesystems is disabled****"

echo "****Step 1 audit for the udf filesystem****"

lsmod | grep udf

$SLEEP20s

echo "****Ensure mounting of UDF filesystems is blacklisted****"

cp /home/your_username/uscript/blacklist.conf /etc/modprobe.d/

#echo "****Disable Automounting****"

#Check if client if Automounting of portable drives is needed for servers or workstations

#echo "****Run the following command to verify autofs is not installed****"

#systemctl is-enabled autofs 

#$SLEEP20s

#echo "****Run the following command to verify autofs is not enabled if installed****"

#systemctl is-enabled autofs

#echo "****If there are no other packages that depends on autofs remove the package with****"

#apt purge autofs

#echo "****Run the following commands to mask autofs****"

#systemctl stop autofs

#systemctl mask autofs

#Check with client if USB protable devices are used on workstations and servers

#echo "The following command verifies usb storage is enabled"

#lsusb

#echo "****Disable USB storage on an Ubuntu server****"

#echo "blacklist usb-storage" | tee /etc/modprobe.d/blacklist-usb-storage.conf

echo "****Ensure package manager repositories are configured****"

echo "****Run the following command and verify package repositories are configured correctly****"

apt-cache policy 

echo "****Ensure GPG keys are configured****"

echo "****Verify GPG keys are configured correctly for your package manager****"

apt-key list

echo "****Ensure permissions on bootloader config are configured****"

stat /boot/grub/grub.cfg

$SLEEP20s

echo "****Run the following commands to set ownership and permissions on your grub configuration files****"

chown root:root /boot/grub/grub.cfg

chmod u-wx,go-rwx /boot/grub/grub.cfg

echo "****Ensure authentication required for single user mode****"

echo "****Perform the following to determine if a password is set for the root user****"

grep -Eq '^root:\$[0-9]' /etc/shadow || echo "root is locked"

$SLEEP20s

#Consult the client if this person would like to modifiy the root user password

#echo "****Run the following command and follow the prompts to set a password for the root user****"

#passwd root

echo "****Ensure address space layout randomization (ASLR) is enabled****"

sysctl kernel.randomize_va_space

$SLEEP20s

printf "kernel.randomize_va_space = 2" >> /etc/sysctl.d/60-kernel_sysctl.conf

sysctl -w kernel.randomize_va_space=2

echo "****Ensure bootloader password is set****"

echo "****Run the following commands and verify output matches****"

grep "^set superusers" /boot/grub/grub.cfg

grep "^password" /boot/grub/grub.cfg


echo "****Ensure prelink is not installed****"

echo "****Verify prelink is not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' prelink 

$SLEEP20s

echo "Run the following command to restore binaries to normal"

prelink -ua

echo "****Uninstall prelink using the appropriate package manager ****"

apt purge prelink -y

echo "****Ensure Automatic Error Reporting is not enabled****"

echo "****Run the following command to verify that the Apport Error Reporting Service is not enabled****"

dpkg-query -s apport > /dev/null 2>&1 && grep -Psi -- '^\h*enabled\h*=\h*[^0]\b' /etc/default/apport

echo "****Run the following command to verify that the apport service is not active****"

systemctl is-active apport.service | grep '^active'

$SLEEP20s

echo "****Run the following commands to stop and disable the apport service and to remove the apport package****"

systemctl stop apport.service 

systemctl --now disable apport.service

apt purge apport -y

echo "****Ensure core dumps are restricted****"

echo "****Run the following commands and verify output matches****"

grep -Es '^(\*|\s).*hard.*core.*(\s+#.*)?$' /etc/security/limits.conf

sysctl fs.suid_dumpable

grep "fs.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*

echo "****Run the following command to check if systemd-coredump is installed****"

systemctl is-enabled coredump.service 

$SLEEP20s

echo "****Writes the following value to the limits configuration file****"

echo '* hard core 0' | tee -a /etc/security/limits.conf

echo "****Writes the following value to the sysctl configuration file****

echo 'fs.suid_dumpable = 0' | tee -a /etc/sysctl.conf

echo "****Run the following command to set the active kernel parameter****"

sysctl -w fs.suid_dumpable=0

echo "****If systemd-coredump is installed write the following values to the coredump configuration file****"

sed -i 's/#Storage=external/Storage=none/g' /etc/systemd/coredump.conf'

sed -i '/ProcessSizeMax/c\ProcessSizeMax=0' /etc/systemd/coredump.conf

echo "****Reload Systemctl****"

systemctl daemon-reload 

echo "****Ensure AppArmor is installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' apparmor

$SLEEP20s

echo "****Install AppArmor****"

echo "****Ensure AppArmor is enabled in the bootloader configuration****"

echo "****Run the following commands to verify that all linux lines have the apparmor=1 and security=apparmor parameters set****"

grep "^\s*linux" /boot/grub/grub.cfg | grep -v "apparmor=1"

grep "^\s*linux" /boot/grub/grub.cfg | grep -v "security=apparmor" 

$SLEEP20s

echo "****Writes the following value to the grug configuration file****"

sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"/' /etc/default/grub

echo "****Run the following command to update the grub2 configuration****"

update-grub 

echo "****Ensure all AppArmor Profiles are in enforce or complain mode****"

echo "****Run the following command and verify that profiles are loaded, and are in either enforce or complain mode****"

apparmor_status | grep profiles

echo "****Run the following command and verify no processes are unconfined****"

apparmor_status | grep processes 

echo "****Install AppArmor Utilities****"

apt install apparmor-utils -y

$SLEEP20s

echo "****Run the following command to set all profiles to enforce mode****"

aa-enforce /etc/apparmor.d/* 

echo "****Ensure message of the day is configured properly****"

echo "****Run the following command and verify no results are returned****" 

grep -i "/etc/os-release" /etc/motd

echo "****if the motd is not used, this file can be removed****"

rm /etc/motd

echo "****Ensure permissions on issue configuration file are setup****"

echo "****Run the following command and verify Uid and Gid are both 0 root and Access is 644****"

stat -L /etc/issue

$SLEEP20s

echo "****Run the following commands to set permissions on issue configuration file are setup****"

chown root:root $(readlink -e /etc/issue)

chmod u-x,go-wx $(readlink -e /etc/issue)

echo "****Ensure permissions on the issue dot net configuration file are setup****"

echo "****Run the following command and verify Uid and Gid are both 0 root and Access is 644****"

stat -L /etc/issue.net

$SLEEP20s

echo "****Run the following commands to set permissions on the issue dot net configuratiom file****"

chown root:root $(readlink -e /etc/issue.net) 

chmod u-x,go-wx $(readlink -e /etc/issue.net) 

#Ask client if the GNOME Display Manager is required****"

#echo "****Ensure GNOME Display Manager is removed****" 

#echo "****Run the following command and verify gdm3 is not installed****"

#dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' gdm3

#$SLEEP20s

#echo "****Run the following command to uninstall gdm3****"

#apt purge gdm3

#Does the client want a custon SSH warning banner

echo "****Setup a custon SSH warning banner****"

cp /home/your_username/uscript/sshd_config /etc/ssh/

cp /home/your_username/uscript/sec_banner /etc/sec_banner

systemctl restart sshd

echo "****Ensure GDM screen locks when the user is idle****"

echo "****Run the following commands to verify that the screen locks when the user is idle****"

gsettings get org.gnome.desktop.session idle-delay

gsettings get org.gnome.desktop.screensaver lock-delay

echo "****Set the idle delay to 300 seconds or 5 minutes run the following command****"

gsettings set org.gnome.desktop.session idle-delay 300

$SLEEP20s

echo "****Set the lock delay to 300 seconds or 5 minutes immediate lock when idle run the following command****"

gsettings set org.gnome.desktop.screensaver lock-delay 0

#echo "Ensure automatic mounting of removable media is disabled"

#"****Run the following command to verify automatic mounting is disabled****"

#"****Verify result is false****"

#gsettings get org.gnome.desktop.media-handling automount

#$SLEEP20s

# cp /home/your_username/uscript/00-media-automount /etc/dconf/db/local.d/

#dconf update 

#echo "****Ensure GDM autorun never is enabled****"

#"****Run the following script to verify that autorun-never is set to true for GDM****"

#cat /etc/gdm3/custom.conf | grep "^\\s*autorun-never=true$"

#$SLEEP20s

#echo "****Run the following script to set autorun-never to true for GDM users****"

#sed -i '/\[daemon\]/a autorun-never=true' /etc/gdm3/custom.conf

echo "****Verify that the autorun-never true setting cannot be overridden in GDM GNOME Display Manager on Ubuntu****"

echo "****Run the following command to verify that autorun-never=true cannot be overridden****"

ls -l /etc/gdm3/custom.conf

$SLEEP20s

echo "****Run the following commands to ensure that autorun-never=true cannot be overridden****"

chown root /etc/gdm3/custom.conf

chmod 644 /etc/gdm3/custom.conf

echo "****Ensure XDMCP is not enabled****"

echo "***Run the following command and verify XDMCP is not enabled*****"

grep -Eis '^\s*Enable\s*=\s*true' /etc/gdm3/custom.conf 

$SLEEP20s

echo "****The following value xdmcp #Enable=true with be written to /etc/gdm/custom.conf****"

sed -i '/\[xdmcp]/,/Enable=true/d' /etc/gdm/custom.conf

echo "****Ensure updates, patches, and additional security software are installed****"

echo "****Verify there are no updates or patches to install****"

apt -s upgrade -y

$SLEEP20s

echo "****Run the following command to update all packages following local site policy guidance on applying updates and patches****"

apt upgrade -y

apt dist-upgrade -y

echo "****Ensure a single time synchronization daemon is in use ****"

echo "****Run the following command to verify that a single time synchronization daemon is available****" 

systemctl is-active systemd-timesyncd.service

$SLEEP20s

echo "****Run the following command to install chrony****"

apt install chrony -y

echo "****Run the following commands to stop and mask the systemd-timesyncd daemon****" 

systemctl stop systemd-timesyncd.service 

systemctl --now mask systemd-timesyncd.service 

echo "****Run the following command to remove the ntp package****"

apt purge ntp -y

echo "****Ensure chrony is running as user chrony****"

echo "****IF chrony is in use on the system, run the following command to verify the chronyd service is being run as the _chrony user"

ps -ef | awk '(/[c]hronyd/ && $1!="_chrony") { print $1 }'

grep -i "user _chrony" /etc/chrony/chrony.conf

$SLEEP20s

echo "****Add the following value user line to /etc/chrony/chrony.conf****"

sed -i '$ a\user _chrony' /etc/chrony/chrony.conf

echo "****Ensure chrony is enabled and running****"

echo "****Run the following command to verify that the chrony service is enabled****"

systemctl is-enabled chrony.service 

echo "****Run the following command to verify that the chrony service is active****"

systemctl is-active chrony.service

$SLEEP20s

echo "****If chrony is in use on the system, run the following commands run the following command to unmask chrony.service****"

systemctl unmask chrony.service 

echo "****Run the following command to enable and start chrony.service****"

systemctl --now enable chrony.service 

#Ask client if they will require X Window System because some Some Linux Java packages have a dependency on specific X Windows xorg-x11-fonts.

#echo "****Verify X Windows System is not installed****"

#dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' xserver-xorg* | grep -Pi '\h+installed\b'

#$SLEEP20s

#echo "****Remove the X Windows System packages****"

#apt purge xserver-xorg*

echo "****Ensure Avahi Server is not installed****"

echo "****Run the following command to verify avahi-daemon is not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' avahi-daemon

echo "****Run the following commands to remove avahi-daemon****"

$SLEEP20s

systemctl stop avahi-daaemon.service 

systemctl stop avahi-daemon.socket 

apt purge avahi-daemon -y

echo "****Ensure CUPS is not installed****"

echo "****Run the following command to verify cups is not Installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' cups 

$SLEEP20s

echo "****Run one of the following commands to remove cups****"

apt purge cups -y

echo "****Ensure DHCP Server is not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' isc-dhcp-server

$SLEEP20s

echo "****Run the following command to remove isc-dhcp-server****"

apt purge isc-dhcp-server -y 

echo "****Ensure LDAP server is not installed****"

echo "****Run the following command to verify slapd is not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' slapd

$SLEEP20s

echo "****Run one of the following commands to remove slapd****"

apt purge slapd -y 

echo "****Ensure NFS is not installed****"

echo "****Run the following command to verify nfs is not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' nfs-kernel-server

$SLEEP20s

echo "****Run the following command to remove nfs****"

apt purge nfs-kernel-server -y 

echo "****Ensure DNS Server is not installed****"

echo "****Run the following command to verify DNS server is not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' bind9 

$SLEEP20s

echo "****Run the following commands to disable DNS server****"

apt purge bind9 -y

echo "****Ensure FTP Server is not installed ****"

echo "****Run the following command to verify vsftpd is not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' vsftpd

$SLEEP20s

echo "****Run the following command to remove vsftpd****"

apt purge vsftpd -y 

echo "****Ensure HTTP server is not installed****"

echo "****Run the following command to verify apache is not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' apache2

$SLEEP20s

echo "****Run the following command to remove apache****"

apt purge apache2 -y

echo "****Ensure IMAP and POP3 server are not installed****"

echo "****Run the following command to verify dovecot-imapd and dovecot-pop3d are not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' dovecot-imapd dovecot-pop3d

$SLEEP20s

echo "****Run one of the following commands to remove dovecot-imapd and dovecot-pop3d****"

apt purge dovecot-imapd dovecot-pop3d -y 

echo "****Ensure Samba is not installed****"

echo "****Run the following command to verify samba is not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' samba

$SLEEP20s

echo "****Run one of the following commands to remove dovecot-imapd and dovecot-pop3d****"

apt purge samba -y

echo "****Ensure HTTP Proxy Server is not installed****"

echo "****Run the following command to verify squid is not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' squid

$SLEEP20s

echo "****Run the following command to remove squid****"

apt purge squid -y

echo "****Ensure SNMP Server is not installed****"

echo "****Run the following command to verify snmpd is not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' snmp

$SLEEP20s

echo "****Run the following command to remove snmp****"

apt purge snmp -y

echo "****Ensure NIS Server is not installed****"

echo "****Run the following command to verify nis is not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' nis

$SLEEP20s

echo "****Run the following command to remove nis****"

apt purge nis -y 

echo "****Ensure mail transfer agent is configured for local-only mode****"

echo "****Run the following command to verify that the MTA is not listening on any non-loopback address****"

ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s'

$SLEEP20s

echo "****Adds the following value inet interfaces to RECEIVING MAIL section of /etc/postfix/main configuration file****"

sed -i '/^# RECEIVING MAIL/ a\inet_interfaces = loopback-only' /etc/postfix/main.cf

systemctl restart postfix

echo "****Ensure rsync service is either not installed or masked****"

echo "****Run the following command to verify rsync is not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' rsync

$SLEEP20s

echo "****Run the following command to verify rsync is not installed****"

systemctl is-active rsync 

echo "****Run the following commands to verify that rsync is inactive and masked****"

systemctl is-enabled rsync

echo "****Run the following command to remove rsync****"

apt purge rsync -y 

echo "****Run the following commands to stop and mask rsync****"

systemctl stop rsync

systemctl mask rsync

echo "****Ensure NIS Client is not installed****"

echo "****Run the following command to verify nis is not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' nis

$SLEEP20s

echo "****Run the following command to remove nis****"

apt purge nis -y 

echo "****Ensure rsh client is not installed****"

echo "****Verify rsh-client is not installed. Use the following command to provide the needed information****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' rsh-client 

$SLEEP20s

echo "****Uninstall rsh****"

apt purge rsh-client -y 

echo "****Ensure talk client is not installed****"

echo "****Verify talk is not installed. The following command may provide the needed information****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' talk

$SLEEP20s

echo "****Run the following command to remove talk****"

apt purge talk -y

echo "****Ensure telnet client is not installed****"

echo "****Verify telnet is not installed. Use the following command to provide the needed information****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' telnet

$SLEEP20s

echo "****Run the following command to Uninstall telne***"

apt purge telnet -y

echo "****Ensure LDAP client is not installed****"

echo "****Verify that ldap-utils is not installed. Use the following command to provide the needed information****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' ldap-utils 

$SLEEP20s

echo "****Run the following command to Uninstall ldap-utils****"

apt purge ldap-utils -y

echo "****Ensure RPC is not installed****"

echo "****Run the following command to verify rpcbind is not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' rpcbind
 
$SLEEP20s

echo "****Run the following command to remove rpcbind****"

apt purge rpcbind -y

#cho "****Ensure system is checked to determine if IPv6 is enabled****"

#cho "****Run the following command to checked if IPv6 is enabled****"

#at /proc/sys/net/ipv6/conf/all/disable_ipv6

#SLEEP20s

#echo "****Run the following command to enable IPV6****"

#ysctl -w net.ipv6.conf.all.disable_ipv6=0

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

echo "****Run the following command to set the active kernel parameters****"

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

sysctl net.ipv4.conf.default.secure_redirects

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

echo "****Set the following parameter in /etc/sysctl d file****"

printf "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf

echo "****Run the following command to set the active kernel parameters****"

sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1

sysctl -w net.ipv4.route.flush=1

echo "****Ensure Reverse Path Filtering is enabled****"

echo "****Run the following command to verify net ipv4 conf all rp filter is to 1****"

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

echo ****"Run the following script to verify net.ipv6 conf all accept ra is set to 0"****

sysctl -a 2>/dev/null | grep net.ipv6.conf.all.accept_ra

$SLEEP20s

echo "****Set the following parameters in /etc/sysctl.d/* file****"

printf "net.ipv6.conf.all.accept_ra = 0 net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf 

echo "****Run the following command to set the active kernel parameters****"

sysctl -w net.ipv6.conf.all.accept_ra=0 

sysctl -w net.ipv6.conf.default.accept_ra=0 

sysctl -w net.ipv6.route.flush=1

echo "****Ensure DCCP is disabled****"

echo "****Run the following command to ensure DCCP is disabled****"

grep "net.ipv4.tcp_allowed_congestion_control" /etc/sysctl.conf

$SLEEP20s

echo "****Write the folowing value in the /etc/sysctl.conf file to disable DCCP****"

sed -i '/^net.ipv4.tcp_allowed_congestion_control\s*=/d;$a\net.ipv4.tcp_allowed_congestion_control = reno cubic' /etc/sysctl.conf

echo "****Ensure SCTP is disabled****"

echo "****Run the following command to verify sctp is disabled****"

lsmod | grep sctp

grep "blacklist sctp" /etc/modprobe.d/blacklist-sctp.conf

$SLEEP20s

echo "****Run the following commands to disable sctp****"

touch /etc/modprobe.d/blacklist-sctp.conf

sh -c 'echo "blacklist sctp" >> /etc/modprobe.d/blacklist-sctp.conf'

echo "****Ensure RDS is disabled****"

echo "****Run the following command to verify rds is disabled****"

lsmod | grep rds

grep "rds" /etc/modprobe.d/blacklist-rds.conf

$SLEEP20s

echo "****Run the following commands to disable rds****"

touch /etc/modprobe.d/blacklist-rds.conf

sh -c 'echo "blacklist rds" >> /etc/modprobe.d/blacklist-rds.conf'

echo "****Ensure TIPC is disabled****"

echo "****Run the following command to verify tipc is disabled****"

lsmod | grep tipc

grep "blacklist tipc" /etc/modprobe.d/blacklist-tipc.conf

$SLEEP20s

echo "****Run the following commands to disable tipc****"

touch /etc/modprobe.d/blacklist-tipc.conf

sh -c 'echo "blacklist tipc" >> /etc/modprobe.d/blacklist-tipc.conf'

echo "****Ensure ufw is installed****"

echo "****Run the following command to verify that Uncomplicated Firewall (UFW) is installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' ufw 

$SLEEP20s

echo "****Run the following command to install Uncomplicated Firewall UFW****"

apt install ufw -y

echo "****Ensure iptables-persistent is not installed with ufw****"

echo "****Run the following command to verify that the iptables-persistent package is not installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' ufw 

$SLEEP20s

echo "****Run the following command to remove the iptables-persistent package****"

apt purge iptables-persistent -y 

echo "****Ensure ufw service is enabled****"

echo "****Run the following command to verify that the ufw daemon is enabled****"

systemctl is-enabled ufw.service

echo "****Run the following command to verify that the ufw daemon is active****"

systemctl is-active ufw

echo "****Run the following command to verify ufw is active****"

ufw status

$SLEEP20s

echo "****Run the following command to unmask the ufw daemon****"

systemctl is-enabled ufw.service

echo "****Run the following command to enable and start the ufw daemon****"

systemctl --now enable ufw.service

echo "****Run the following command to enable ufw****"

ufw enable

echo "****Ensure ufw loopback traffic is configured****"

echo "****Run the following commands and verify output includes the listed rules in order****"

ufw status verbose

$SLEEP20s

echo "****Run the following commands to implement the loopback rules****"

ufw allow in on lo 

ufw allow out on lo 

ufw deny in from 127.0.0.0/8 

ufw deny in from ::1

echo "****Ensure ufw outbound connections are configured****"

echo "****Run the following command and verify all rules for new outbound connections match site policy****"

ufw status numbered 

$SLEEP20s

echo "****The following commands will implement a policy to allow all outbound connections on all interfaces****"

ufw allow out on all

#echo "****Ensure ufw firewall rules exist for all open ports****"

#echo "****Run the following command to verify a firewall rule exists for all open ports****"

#ufw status 

#$SLEEP20s

#echo "****The following commands will implement a policy to allow all outbound connections on all interfaces****"

#echo "****For each port identified in the audit which does not have a firewall rule, add rule for accepting or denying inbound connections****"

#ufw allow in <port>/<tcp or udp protocol>

echo "****Ensure ufw default deny firewall policy****"

echo "****Any port and protocol not explicitly allowed will be blocked. The following rules should be considered before applying the default deny****"

ufw allow git 
ufw allow in http 
ufw allow in 22
ufw allow out http  
ufw allow in https 
ufw allow out https 
ufw allow out 22 
ufw allow out 53 


echo "****Run the following command and verify that the default policy for incoming outgoing and routed directions is deny reject or disabled****"

ufw status verbose | grep Default

$SLEEP20s

echo "****Run the following commands to implement a default deny policy****"

ufw default deny incoming 
ufw default deny outgoing 
ufw default deny routed 

echo "****Ensure auditd is installed****"

echo "****Run the following command and verify auditd and audispd-plugins are installed****"

dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' auditd audispd-plugins

$SLEEP20s

echo "****Run the following command to Install auditd****"

apt install auditd audispd-plugins -y

echo "****Ensure auditd service is enabled and active****"

echo "****Run the following command to verify auditd is enabled****"

systemctl is-enabled auditd

echo "****Run the following command to verify auditd is active****"

systemctl is-active auditd

$SLEEP20s

echo "****Run the following command to enable and start auditd****"

systemctl --now enable auditd 

echo "****Ensure auditing for processes that start prior to auditd is enabled****"

echo "****Run the following command****"

find /boot -type f -name 'grub.cfg' -exec grep -Ph -- '^\h*linux' {} + | grep -v 'audit=1'

$SLEEP20s

echo "****Run the following command to and add audit=1 to GRUB_CMDLINE_LINUX****"

sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 audit=1"/' /etc/default/grub

echo "****Run the following command to update the grub2 configuration****"

update-grub 

echo "****Ensure audit_backlog_limit is sufficient****"

echo "****Run the following command and verify the audit_backlog_limit= parameter is set****"

find /boot -type f -name 'grub.cfg' -exec grep -Ph -- '^\h*linux' {} + | grep -Pv 'audit_backlog_limit=\d+\b'

$SLEEP20s

echo "****Write the following value to /etc/default/grub and add audit_backlog_limit=N to GRUB_CMDLINE_LINUX****"

sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 audit_backlog_limit=8192"/' /etc/default/grub

echo "****Run the following command to update the grub2 configuration****"

update-grub 

echo "****Ensure audit log storage size is configured****"

echo "****Run the following command and ensure output is in compliance with site policy****"

grep -i "max_log_file" /etc/audit/auditd.conf

$SLEEP20s

echo "****Set the following parameter in /etc/audit/auditdconf****"

sed -i "s/max_log_file = .*/max_log_file = 16/" /etc/audit/auditd.conf

echo "****Ensure audit logs are not automatically deleted****"

echo "****Run the following command and verify output matches****"

grep "max_log_file_action = keep_logs" /etc/audit/auditd.conf

$SLEEP20s

echo "****Set the following parameter in /etc/audit/auditd conf****"

sed -i "s/max_log_file_action = .*/max_log_file_action = keep_logs/" /etc/audit/auditd.conf

echo "****Ensure system is disabled when audit logs are full ****"

echo "****Run the following commands****"

grep space_left_action /etc/audit/auditd.conf

grep action_mail_acct /etc/audit/auditd.conf

grep -E 'admin_space_left_action\s*=\s*(halt|single)' /etc/audit/auditd.conf 

$SLEEP20s

echo "****Set the following parameter in /etc/audit/auditdconf****"

sed -i "s/space_left_action.*/space_left_action = email/" /etc/audit/auditd.conf

sed -i 's/action_mail_acct.*/action_mail_acct = root/' /etc/audit/auditd.conf

sed -i 's/^admin_space_left_action.*/admin_space_left_action = halt/' /etc/audit/auditd.conf

echo "****Ensure changes to system administration sudoers is collected****"

echo "****Run the following command to check the on disk rules****"

grep -e "-w /etc/sudoers -p wa -k scope" /etc/audit/rules.d/audit.rules

grep -e "-w /etc/sudoers.d -p wa -k scope" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure actions as another user are always logged****"

echo "****Run the following command to check the on disk rules****"

grep -e "-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation" /etc/audit/rules.d/audit.rules

$SLEEP20s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure events that modify the sudo log file are collected****"

echo "****Run the following command to check the on disk rules****"

grep -e "-w /var/log/sudo.log -p wa -k sudo_log_file" /etc/audit/rules.d/audit.rules

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

grep -e "-w /etc/networks -p wa -k system-locale" /etc/audit/rules.d/audit.rules

grep -e "-w /etc/network/ -p wa -k system-locale" /etc/audit/rules.d/audit.rules

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

echo "****Monitor changes to file permissions, attributes, ownership and groups****" 

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

grep -e "-w /etc/apparmor/ -p wa -k MAC-policy" /etc/audit/rules.d/audit.rules

grep -e "-w /etc/apparmor.d/ -p wa -k MAC-policy" /etc/audit/rules.d/audit.rules

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

echo "****Run the following command to check the on disk rules****"

grep -e "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules" /etc/audit/rules.d/audit.rules

grep -e "-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules" /etc/audit/rules.d/audit.rules

$SLEEP90s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Ensure the audit configuration is immutable****"

echo "****Run the following command and verify output matches****"

grep -e "-e 2" /etc/audit/rules.d/audit.rules

$SLEEP90s

echo "****The /etc/audit/rules.d/audit.rules will be reconfigured at the end of this section****"

echo "****Check if reboot is required****"

if [[ $(auditctl -s | grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

echo "****Write the audit.rules file to /etc/audit/rules.d/audit.rules****"

cp /home/your_username/uscript/audit.rules /etc/audit/rules.d/

echo "****Write the audit.rules file to /etc/audit/audit.rules****"

cp /etc/audit/rules.d/audit.rules /etc/audit/

echo "****Ensure audit system is running and on disk configuration is the same****"

echo "****Ensure that all rules in /etc/audit/rules.d have been merged into /etc/audit/audit.rules****"

augenrules --check

echo "****Merge and load the rules into active configuration****"

augenrules --load

service auditd restart

systemctl enable auditd

echo "****List loaded rules****"

auditctl -l

service auditd status

echo "****Ensure audit log files are mode 0640 or less permissive****"

echo "****Run the following command to verify audit log files have mode 0640 or less permissive****"

sh -c "stat -Lc '%n %a' \"\$(dirname \"\$(awk -F= '/^\s*log_file\s*=\s*/ {gsub(/\\s*/, \"\", \$2); print \$2}' /etc/audit/auditd.conf)\")\"/* | grep -vE '[0,2,4,6][0,4]0'"

$SLEEP20s

echo "****Run the following command to remove more permissive mode than 0640 from audit log files****"

find /etc/audit/* -type f -perm -0640 -exec chmod 0640 {} +

echo "****Ensure only authorized users own audit log files****"

echo "****Run the following command to verify audit log files are owned by the root user****"

stat -Lc "%n %U" "$(awk -F"=" '/^\s*log_file\s*=\s*/ {print $2}' /etc/audit/auditd.conf)"/* | grep -vP '^\S+\s+root\b'

$SLEEP20s

echo "****Run the following command to configure the audit log files to be owned by the root user****"

chown root /var/log/audit/*

echo "****Ensure only authorized groups are assigned ownership of audit log files****"

echo "****Run the following command to verify log_group parameter is set to either adm or root in /etc/audit/auditd.conf****"

grep -Piw -- '^\h*log_group\h*=\h*(adm|root)\b' /etc/audit/auditd.conf

$SLEEP20s

echo "****Run the following command to configure the audit log files to be owned by the adm group****"

chgrp adm /var/log/audit/

echo "****Run the following command to set the log_group parameter in the audit configuration****"

sed -ri 's/^\s*#?\s*log_group\s*=\s*\S+(\s*#.*)?.*$/log_group = adm\1/' /etc/audit/auditd.conf

echo "****Run the following command to restart the audit daemon to reload the configuration file****"

systemctl restart auditd 

echo "****Ensure the audit log directory is 0750 or more restrictive****"

echo "****Run the following command to verify that the audit log directory has a mode of 0750 or less permissive****"

ls -la /etc/audit/

$SLEEP20s

echo "****Run the following command to configure the audit log files to be owned by the adm group****"

chmod 0750 /var/log/audit

echo "****Ensure audit configuration files are 640 or more restrictive****"

echo "****Run the following command to verify that the audit configuration files have mode 640 or more restrictive and are owned by the root user and root group****"

find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec stat -Lc "%n %a" {} + | grep -Pv -- '^\h*\H+\h*([0,2,4,6][0,4]0)\h*$'

$SLEEP20s

echo "****Run the following command to configure the audit log files to be owned by the adm group****"

find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec chmod u-x,g-wx,o-rwx {} +

echo "****Ensure audit configuration files are owned by root****"

echo "****Run the following command to verify that the audit configuration files have mode 640 or more restrictive and are owned by the root user and root group****"

find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root

$SLEEP20s

echo "****Run the following command to change ownership to root user****"

find /etc/audit/ -type f \( -name &apos;*.conf&apos; -o -name &apos;*.rules&apos; \) ! -user root -exec chown root {} +

echo "****Ensure audit configuration files belong to group root****"

echo "****Run the following command to verify that the audit configuration files have mode 640 or more restrictive and are owned by the root user and root group****"

find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root

$SLEEP20s

echo "****Ensure audit configuration files belong to group root****"

find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec chgrp root {} + 

echo "****Ensure audit tools are 755 or more restrictive****"

echo "****Run the following command to verify the audit tools have mode 755 or more restrictive re owned by the root user and group root****"

stat -c "%n %a" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h*$'

$SLEEP20s

echo "****Run the following command to remove more permissive mode from the audit tools****"

chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

echo "****Ensure audit tools are owned by root****"

echo "****Run the following command to verify the audit tools have mode 755 or more restrictive re owned by the root user and group root****"

stat -c "%n %a" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h*$'

$SLEEP20s

echo "****Run the following command to change the owner of the audit tools to the root user****"

chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

echo "****Ensure audit tools belong to group root****"

echo "****Run the following command to verify the audit tools have mode 755 or more restrictive re owned by the root user and group root****"

stat -c "%n %a %U %G" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h+root\h+root\h*$'

$SLEEP20s

echo "****Run the following command to remove more permissive mode from the audit tools****"

chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

echo "****Run the following command to change owner and group of the audit tools to root user and group****"

chown root:root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

echo "****Ensure audit tools belong to group root****"

echo "****Run the following command to verify the audit tools have mode 755 or more restrictive re owned by the root user and group root****"

stat -c "%n %a %U %G" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h+root\h+root\h*$'

$SLEEP20s

echo "****Run the following command to remove more permissive mode from the audit tools****"

chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

echo "****Run the following command to change owner and group of the audit tools to root user and group****"

chown root:root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

#Ask client if they would like logfiles sent to a remote host

#echo "****Ensure systemd-journal-remote is installed****"

#echo "****Run the following command to verify systemd-journal-remote is installed****"

#dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' ystemd-journal-remote 

#$SLEEP20s

#echo "****Run the following command to install systemd-journal-remote****"

#apt install systemd-journal-remote -y

#echo "****Ensure systemd-journal-remote is configured****"

#echo "****Verify systemd-journal-remote is configured, Run the following command****"

#grep -P "^ *URL=|^ *ServerKeyFile=|^ *ServerCertificateFile=|^*TrustedCertificateFile=" /etc/systemd/journal-upload.conf

#$SLEEP20s

#echo "****Write for following value to /etc/systemd/journal-upload.conf****"

#cp /home/your_username/uscript/journald.conf /etc/systemd/

#echo "****Ensure systemd-journal-remote is enabled****"

#echo "****Verify systemd-journal-remote is enabled, run the following command****"

#systemctl is-enabled systemd-journal-upload.service  

#$SLEEP20s

#echo "****Run the following command to enable systemd-journal-remote****"

#systemctl --now enable systemd-journal-upload.service

#echo "****Ensure journald is not configured to recieve logs from a remote client****"

#echo "****Run the following command to verify systemd-journal-remote.socket is not enabled****"

#systemctl is-enabled systemd-journal-upload.service  

#$SLEEP20s

#echo "****Run the following command to disable systemd-journal-remote.socket****"

#systemctl --now disable systemd-journal-remote.socket 

#echo "****Ensure journald service is enabled****"

#echo "****Run the following command to verify systemd-journald is enabled****"

#systemctl is-enabled systemd-journal-upload.service  

#Verify the output matches static 

#echo "****Ensure journald is configured to compress large log files****"

#echo "****Review /etc/systemd/journald.conf and verify that large files will be compressed****"

#grep ^\s*Compress /etc/systemd/journald.conf 

#$SLEEP20s

#echo "****Write for following value Compress=yes to /etc/systemd/journal-upload.conf****"

#cp /home/your_username/uscript/journald.conf /etc/systemd/

#echo "****Restart the service****"

#systemctl restart systemd-journald

#echo "****Ensure journald is configured to write logfiles to persistent disk****"

#echo "****Review /etc/systemd/journald.conf and verify that logs are persisted to disk****"

#grep ^\s*Storage /etc/systemd/journald.conf 

#$SLEEP20s

#echo "****Write for following value Storage=persistent to /etc/systemd/journald.conf****"

#cp /home/your_username/uscript/journad.conf /etc/systemd/

#echo "****Restart the service****"

#systemctl restart systemd-journald

#echo "****Ensure journald is not configured to send logs to rsyslog****"

#echo "****Review /etc/systemd/journald.conf and verify that logs are not forwarded to rsyslog****"

#grep ^\s*ForwardToSyslog /etc/systemd/journald.conf

#$SLEEP20s

#echo "****Write for following value to ensure that ForwardToSyslog=yes is removed****"

#cp /home/your_username/uscript/journad.conf /etc/systemd/

#echo "****Restart the service****"

#systemctl restart systemd-journald

#echo "****Ensure journald log rotation is configured per site policy****"

#echo "****Review /etc/systemd/journald.conf and verify that logs are not forwarded to rsyslog****"

#echo "****Ensure journald log rotation is configured per site policy****"

#echo "****Review /etc/systemd/journald.conf and verify logs are rotated according to site policy****"

#grep ^\s*SystemMaxUse /etc/systemd/journald.conf 

#grep ^\s*SystemKeepFree /etc/systemd/journald.conf

#grep ^\s*RuntimeMaxUse /etc/systemd/journald.conf

#grep ^\s*RuntimeKeepFree /etc/systemd/journald.conf

#grep ^\s*MaxFileSec /etc/systemd/journald.conf

#$SLEEP20s

#echo "****Write to the file /etc/systemd/journald.conf****"

#cp /home/your_username/uscript/journad.conf /etc/systemd/

#echo "****Restart the service****"

#systemctl restart systemd-journald

#echo "****Ensure journald default file permissions configured****"

#echo "****Review Ensure that file permissions for systemd.conf are 640****"

#ls -la /usr/lib/tmpfiles.d/systemd.conf 

#$SLEEP20s

#echo "****Write to the file /etc/systemd/journald.conf****"

#cp /usr/lib/tmpfiles.d/systemd.conf /etc/tmpfiles.d/

#chmod 640 /etc/tmpfiles.d/systemd.conf

#echo "****Ensure rsyslog is installed****"

#echo "****Verify rsyslog is installed****"

#dpkg-query -W -f='${binary:Package}\t${Status}\t${db:Status-Status}\n' rsyslog

#$SLEEP20s

#echo "****Run the following command to install rsyslog****"

#apt install rsyslog -y

#echo "****Ensure rsyslog service is enabled****"

#echo "****Run the following command to verify rsyslog is enabled****"

#systemctl is-enabled rsyslog

#$SLEEP20s

#echo "****Run the following command to enable rsyslog****"

#systemctl --now enable rsyslog

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

#systemctl restart rsyslog 

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

#cp /home/your_username/uscript/rsyslog.conf /etc/

#systemctl restart rsyslog

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

#echo "****Ensure all logfiles have appropriate permissions and ownership****"

#echo "****Run the following script to verify that files in /var/log/ have appropriate permissions and ownership****"

#ls -la /var/log/*

#$SLEEP20s

#"****If permissions are not correct look at the permissions on a different system and adjust the permissions based on your specific requirements and security considerations****"

echo "****Ensure cron daemon is enabled****"

echo "****Run the the following command to verify cron is enabled****"

systemctl is-enabled cron

echo "****Run the following command to enable cron****"

$SLEEP20s

systemctl --now enable cron

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

$SLEEP20s

echo "****Run the following commands to set ownership and permissions on /etc/cron.d****"

chown root:root /etc/cron.d

chmod og-rwx /etc/cron.d

echo "****Ensure cron is restricted to authorized users****"

echo "****Run the following command and verify that /etc/cron.deny does not exist****"

stat /etc/cron.deny

echo "****Run the following command and verify Uid and Gid are both 0/root****"

stat /etc/cron.allow

$SLEEP20s

echo "****Run the following commands to remove /etc/cron.deny****"

rm -f /etc/cron.deny

echo "****Run the following command to create /etc/cron.allow****"
	
touch /etc/cron.allow

echo "****Run the following commands to set permissions and ownership for /etc/cron.allow****"
	
chown root:root /etc/cron.allow
	
chmod u-x,go-rwx /etc/cron.allow

echo "****Ensure is at restricted to authorized users****"

echo "****Run the following command and verify that /etc/at.deny does not exist****"

stat /etc/at.deny

echo "****Run the following command and verify Uid and Gid are both 0/root****"

stat /etc/at.allow

$SLEEP20s

echo "****Run the following commands to remove /etc/at.deny****"

rm -f /etc/at.deny

echo "****Run the following command to create /etc/at.allow****"
	
touch /etc/at.allow

echo "****Run the following commands to set permissions and ownership for /etc/cron.allow****"
	
chown root:root /etc/at.allow
	
chmod u-x,go-rwx /etc/at.allow

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

find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;

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

#cp /home/your_username/uscript/sshd_config /etc/ssh/

echo "****Ensure SSH LogLevel is appropriate****"

echo "****Run the following command and verify that output matches loglevel VERBOSE or loglevel INFO****"

grep -i "LogLevel" /etc/ssh/sshd_config

$SLEEP20s

echo "Write the following file to /etc/ssh/sshd_config"

sed -i 's/#LogLevel INFO/LogLevel VERBOSE/g' /etc/ssh/sshd_config

echo "****Ensure SSH PAM is enabled****"

echo "****Run the following command and verify that output matches****"

grep -i "UsePAM" /etc/ssh/sshd_config

$SLEEP20s

echo "Write the following file to /etc/ssh/sshd_config"

sed -i 's/#UsePAM no/UsePAM yes/g' /etc/ssh/sshd_config

echo "****Ensure SSH HostbasedAuthentication is disabled****"

echo "****Run the following command and verify that output matches****"

grep -i "HostbasedAuthentication" /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/#HostbasedAuthentication yes/HostbasedAuthentication no/g' /etc/ssh/sshd_config

echo "****Ensure SSH PermitEmptyPasswords is disabled****"

echo "Run the following command and verify that output matches"

grep -i "PermitEmptyPasswords" /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/#PermitEmptyPasswords yes/PermitEmptyPasswords no/g' /etc/ssh/sshd_config

echo "****Ensure SSH PermitUserEnvironment is disabled****"

echo "Run the following command and verify that output matches"

grep -i "PermitUserEnvironment" /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/#PermitUserEnvironment yes/PermitUserEnvironment no/g' /etc/ssh/sshd_config

echo "****Ensure SSH IgnoreRhosts is enabled****"

echo "****Run the following command and verify that output matches****"

grep -i "IgnoreRhosts" /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/#IgnoreRhosts no/IgnoreRhosts yes/g' /etc/ssh/sshd_config

#Ask client if X11Forwarding is utilized by admins per site policy

echo "****Ensure SSH X11 forwarding is disabled****"

echo "****Run the following command and verify that the output matches****"

grep -i "X11Forwarding" /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/#X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config

echo "****Ensure SSH AllowTcpForwarding is disabled****"

echo "****Run the following command and verify the output****"

grep -i "AllowTcpForwarding" /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding no/g' /etc/ssh/sshd_config

echo "****Ensure only strong Ciphers are used****"

echo "****Run the following commands and verify the output****"

grep -i "3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc" /etc/ssh/sshd_config

grep -i "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i '/Ciphers/a Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' /etc/ssh/sshd_config

echo "****Ensure only strong MAC algorithms are used****"

echo "****Run the following commands and verify the output****"

grep -i "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" /etc/ssh/sshd_config


$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i '$aMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256' /etc/ssh/sshd_config

echo "****Ensure only strong Key Exchange algorithms are used****"

echo "****Run the following commands and verify the output****"

grep -i "diffie-hellman-group1" /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i '$aKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256' /etc/ssh/sshd_config

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

echo "****Ensure sudo is installed****"

echo "****Run the following command to verify that either sudo or sudo-ldap is installed****"

dpkg-query -l sudo

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

apt install sudo -y

echo "****Ensure sudo commands use pty****"

echo "****Verify that sudo can only run other commands from a pseudo terminal****"

grep -rPi '^\h*Defaults\h+([^#\n\r]+,)?use_pty(,\h*\h+\h*)*\h*(#.*)?$' /etc/sudoers* 

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i '/Defaults    use_pty/c\Defaults use_pty' /etc/sudoers

echo "****Ensure sudo log file exists****"

echo "****Run the following command to verify that sudo has a custom log file configured****"

grep -i "/var/log/sudo.log" /etc/sudoers
 
$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i '$ a\Defaults    logfile="/var/log/sudo.log"' /etc/sudoers

echo "****Ensure users must provide password for privilege escalation****"

echo "****Check the configuration of the /etc/sudoers file with the following command****"

grep -i "NOPASSWD" /etc/sudoers
 
$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i '/NOPASSWD/d' /etc/sudoers

echo "****Ensure re-authentication for privilege escalation is not disabled globally****"

echo "****Verify the operating system requires users to re-authenticate for privilege escalation****"

grep -i "authenticate" /etc/sudoers
 
$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i '/authenticate/d' /etc/sudoers

echo "****Ensure sudo authentication timeout is configured correctly****"

echo "****Ensure that the caching timeout is no more than 15 minutes****"

grep -i "timestamp_timeout=15" /etc/sudoers 
 
$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i '$ a\Defaults    env_reset, timestamp_timeout=15' /etc/sudoers

sed -i '$ a\Defaults    timestamp_timeout=15' /etc/sudoers

sed -i '$ a\Defaults    env_reset' /etc/sudoers

echo "****Ensure password creation requirements are configured****" 

echo "****Run the following commands and verify password length requirements conform to organization policy****"

grep -i "minlen" /etc/security/pwquality.conf

echo "****Run one of the following commands and verify that password complexity conforms to organization policy****"

grep -i "minclass" /etc/security/pwquality.conf

$SLEEP20s

echo "****Write to the following command for password length to conform to site policy****"

sed -i 's/^#*\s*minlen\s*=.*/minlen = 14/' /etc/security/pwquality.conf

echo "****Write to the following command for password length to conform to site policy****"

sed -i 's/^#*\s*minclass\s*=.*/minclass = 4/' /etc/security/pwquality.conf

echo "****Ensure password reuse is limited****" 

echo "****Run the following commands and verify password length requirements conform to organization policy****"

grep -i "minlen" /etc/security/pwquality.conf

echo "****Run one of the following commands and verify that password complexity conforms to organization policy****"

grep -i "minclass" /etc/security/pwquality.conf

$SLEEP20s

echo "****Write to the following command for password length to conform to site policy****"

sed -i 's/^#*\s*minlen\s*=.*/minlen = 14/' /etc/security/pwquality.conf

echo "****Write to the following command for password length to conform to site policy****"

sed -i 's/^#*\s*minclass\s*=.*/minclass = 4/' /etc/security/pwquality.conf

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

echo "****Ensure password expiration is 365 days or less****"

echo "****Run the following command and verify PASS_MAX_DAYS conforms to site policy no more than 365 days****"

grep PASS_MAX_DAYS /etc/login.defs

echo "****Run the following command and Review list of users and PASS_MAX_DAYS to verify that all users' PASS_MAX_DAYS conforms to site policy (no more than 365 days)****"

grep -E '^[^:]+:[^!*]' /etc/shadow | cut -d: -f1,5

$SLEEP20s

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs

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

echo "****Ensure SSH root login is disabled****"

echo "***Run the following command and verify that output matches***"

sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep permitrootlogin 

echo "****Run the following command and verify the output****"

grep -Ei '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config

$SLEEP20s

echo "****Run the following command to remediate the security finding****"

sed -i 's/^#*\s*PermitRootLogin\s\+.*/PermitRootLogin no/' /etc/ssh/sshd_config

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

echo "****Ensure default group for the root account is GID 0****"

echo "****Run the following command and verify the result is 0****"

grep "^root:" /etc/passwd | cut -f4 -d:

$SLEEP20s

echo "****Run the following command to set the root account default group to GID 0****"

usermod -g 0 root 

echo "****Ensure default user umask is 027 or more restrictive****"

grep -E '^umask\s+027' /etc/profile /etc/bash.bashrc /etc/profile.d/*.sh

touch test_file && mkdir test_dir

echo "test_file permissions: $(stat -c '%a' test_file)"

echo "test_dir permissions: $(stat -c '%a' test_dir)"

$SLEEP20s

rm -rf /home/your_username/uscript/test_dir

echo "****configure the default user umask to 027 or more restrictive system-wide****"

sed -i 's/^UMASK\s\+[0-9]\+$/UMASK 027/' /etc/login.defs

sed -i '$ a\USERGROUPS_ENAB no' /etc/login.defs

cp /home/your_username/uscript/common-session /etc/pam.d/

#echo "****Ensure default user shell timeout is 900 seconds or less****"

#echo "****Run the following script to verify that TMOUT is configured to: include a timeout of no more than 900 seconds, to be readonly, to be exported, and is not being changed to a longer timeout****"

#grep -i "readonly TMOUT=900 export TMOUT" /etc/bash.bashrc

#grep -i "readonly TMOUT=900 export TMOUT" /etc/profile

#$SLEEP20s

#echo "****Write all TMOUT=_n_ entries to follow local site policy. TMOUT should not exceed 900 or be equal to 0****"

#echo 'TMOUT=900' 'readonly TMOUT' 'export TMOUT' |  tee -a /etc/bash.bashrc

#echo 'TMOUT=900' 'readonly TMOUT' 'export TMOUT' |  tee -a /etc/profile

echo "****Ensure permissions on /etc/passwd are configured****"

echo "****Run the following command and verify Uid and Gid are both 0/root and Access is 644 or more restrictive****"

stat /etc/passwd

$SLEEP20s

echo "****Run the following command to set permissions on /etc/passwd****"

chown root:root /etc/passwd

chmod 644 /etc/passwd

cho "****Ensure permissions on /etc/shadow are configured****"

echo "****Run the following command and verify Uid and Gid are 0/root , and Access is 0000****"

stat /etc/shadow

$SLEEP20s

echo "****Run the following commands to set owner, group, and permissions on /etc/shadow****"

chown root:root /etc/shadow

chmod 0000 /etc/shadow

echo "****Run the following command to remove excess permissions form /etc/shadow****" 

chmod u-x,g-wx,o-rwx /etc/shadow 

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

echo "****Run the following command to remove excess permissions form /etc/gshadow****"

chmod u-x,g-wx,o-rwx /etc/gshadow  

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

echo "****Ensure accounts in /etc/passwd use shadowed passwords****"

echo "****Run the following command and verify that no output is returned****"

awk -F: '($2 != "x" ) { print $1 " is not set to shadowed passwords "}' /etc/passwd 

$SLEEP20s

echo "****Run the following command to set accounts to use shadowed passwords****"

sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd 

echo "****Ensure /etc/shadow password fields are not empty****"

echo "****Run the following command and verify that no output is returned****"

awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow 

$SLEEP20s

echo "****The follwing command checks the /etc/shadow file for user accounts do not have a password.  Run the following command to lock these accounts until it can be determined why it does not have a password****"

awk -F: 'length($2) == 0 {print $1}' /etc/shadow | xargs -I{} passwd -l {}

#passwd -l <username> 

echo "****Ensure all groups in /etc/passwd exist in /etc/group****"

echo "****Run the following commad to audit and verify that all groups in /etc/passwd exist in /etc/group"

for i in $(cut -d: -f4 /etc/passwd | sort -u); do grep -q "^.*:.*:$i:" /etc/group || groupadd -g $i $(getent passwd $i | cut -d: -f1); done > /var/log/passwd_grp_audit.log

echo "****Analyze the output of the Audit step above and perform the appropriate action to correct any discrepancies found****"

echo "****Ensure shadow group is empty****"

echo "****Run the following commands and verify that no output is returned****"

awk -F: '($1=="shadow") {print $NF}' /etc/group

awk -F: -v GID="$(awk -F: '($1=="shadow") {print $3}' /etc/group)" '($4==GID) {print $1}' /etc/passwd
 
$SLEEP20s

echo "****Run the following command to remove all users from the shadow group****"

sed -ri 's/(^shadow:[^:]*:[^:]*:)([^:]+$)/\1/' /etc/group

#echo "****Change the primary group of any users with shadow as their primary group"****

#Usermod -g <primary group> <user> 

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

echo "****Ensure root is the only UID 0 account****"

echo "****Run the following command and verify that only "root" is returned****"

awk -F: '($3 == 0) { print $1 }' /etc/passwd

$SLEEP20s

echo "****Remove any users other than root with UID 0 or assign them a new UID if appropriate****"

echo "****Ensure local interactive user home directories exist****"

echo "****Run the following script to verify all local interactive user home directories exist****"

for user in $(getent passwd | awk -F: '$3 >= 1000 && $7 != "/usr/sbin/nologin" { print $1 }'); do if [ -d "/home/$user" ]; then echo "Home directory for user $user exists."; else echo "Home directory for user $user does not exist."; fi done

echo "****Run the following script to  to create home directories for users with interactive shells whose home directories don't exist****"

for user in $(getent passwd | awk -F: '$3 >= 1000 && $7 != "/usr/sbin/nologin" && $6 == "/nonexistent" { print $1 }'); do mkdir -p "/home/$user"; chown $user:$user "/home/$user"; done

echo "****Ensure users own their home directories****"

find /home -mindepth 1 -maxdepth 20 -type d ! -user root -exec echo "Incorrect ownership: {}" \;

echo "****Creates missing home directories, set the owner, and set the permissions for interactive users' home directories****" 

getent passwd | awk -F: '$3 >= 1000 && $7 ~ /^\/home/ { system("mkdir -p " $7); system("chown " $1 ":" $1 " " $7); system("chmod 700 " $7) }'

echo "****Ensure users' .netrc Files are not group or world accessible****"

echo "****Run the following script and verify no results are returned****"

find /home -maxdepth 20 -name .netrc -perm /go+rwx > /var/log/user_netrc_file_ww_audit.log

$SLEEP20s

"****Command that will remove .netrc files from interactive users' home directories ****"

find /home -type f -name ".netrc" -delete

echo "****Ensure no users have .forward files****"

echo "****Run the following script and verify no results are returned****"

find /home -maxdepth 20 -name ".forward" -print > /var/log/user_forward_file_audit.log

echo "****The following command remove .forward files from interactive users' home directories****"

$SLEEP20s

find /home -type f -name ".forward" -exec rm {} +

echo "****Ensure no users have .rhosts files****"

echo "****Run the following script and verify no results are returned****"

find /home -maxdepth 20 -name ".rhosts" -print > /var/log/user_rhost_file_audit.log

$SLEEP20s

echo "****To remove .rhosts files from interactive users' home directories****"

find /home -type f -name ".rhosts" -delete

echo "****Ensure no users have dot files****"

echo "****Run the following script and verify no results are returned****"

find /home -maxdepth 20 -name ".dfile" -print > /var/log/user_dfile_audit.log

$SLEEP20s

echo "****To remove .rhosts files from interactive users' home directories****"

find /home -type f -name ".dfile" -delete

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

#cp /home/your_username/uscript/fstab /etc/fstab

#echo "****Run the following commands to remount /tmp /home/ /var /dev/shm with the configured options****"

#mount -o remount /tmp 

#mount -o remount /home

#mount -o remount /var

#mount -o remount /dev






















































 







































































































  




















































 




































 




















 







 




















 











 























































































 


























































 















