#!/bin/bash

# Install epel
yum -y install epel-release

# Install open-vm-tools
yum -y install open-vm-tools perl yum-utils net-tools
systemctl enable vmtoolsd

# Cleanup steps
#Stop logging
service rsyslog stop
service auditd stop

#Cleanup old kernels
/bin/package-cleanup --oldkernels --count=1 -y

#Cleanup yum
/usr/bin/yum clean all

#Remove logs
logrotate -f /etc/logrotate.conf
rm -f /var/log/*-?????? /var/log/*.gz
rm -f /var/log/dmesg.log
rm -rf /var/log/anaconda/
cat /dev/null > /var/log/audit/audit.log
cat /dev/null > /var/log/wtmp
cat /dev/null > /var/log/lastlog
cat /dev/null > /var/log/grubby

#Remove old hardware
rm -f /etc/udev/rules.d/70*
#sed –i ‘/UUID/d’ /etc/sysconfig/network-scripts/ifcfg-eno16777984

#Remove ssh keys
rm -f /etc/ssh/*key*

#Remove bash history
rm -f ~root/.bash_history 
unset HISTFILE

#Remove root ssh keys
rm -rf ~root/.ssh/

# Zero out the rest of the free space using dd, then delete the written file.
dd if=/dev/zero of=/EMPTY bs=1M
rm -f /EMPTY

# Add `sync` so Packer doesn't quit too early, before the large file is deleted.
sync
