#!/bin/bash
# Script to check student's work
# Practical Test 1, S2 2020

# init
function next_task(){
	read -p "$*"
}

# Double check student's identity
echo " COMPUTING TOPICS - SEMESTER 2, 2020"
echo " PRACTICAL 1 - MARKING "
echo " *** DOUBLE CHECK STUDENT'S IDENTITY ***"
cat /home/student/INFO_STUDENT_TO_COMPLETE.txt |grep name
next_task 'Press [Enter] key to continue...'

# PART 1
echo "PART 1"

# check UMASK value
echo "  "
echo "Checking UMASK from /etc/login.defs"
echo "==> Is UMASK=077? |" $(cat /etc/login.defs | egrep '^UMASK.*077')
next_task 'Press [Enter] key to continue...'

# check /etc/passwd and /etc/shadow
echo "  "
echo "Checking /etc/passwd and /etc/shadow file permissions"
echo "==> Is /etc/passwd 644? |" $(stat -c "%n %a" /etc/passwd)
echo "==> Is /etc/passwd 640? |" $(stat -c "%n %a" /etc/shadow)
next_task 'Press [Enter] key to continue...'

# check ww files under /etc
echo "  "
echo "Checking ww files under /etc"
echo "==> Is /etc/ssh/sshd_config 644? |" $(stat -c "%n %a" /etc/ssh/sshd_config)
echo "==> Is /etc/sysctl.conf 644? |" $(stat -c "%n %a" /etc/sysctl.conf)
echo "==> Is /home/student/quarantine/sshd_config? |" $(ls /home/student/quarantine/sshd_config 2>/dev/null)
echo "==> Is /home/student/quarantine/sysctl.conf? |" $(ls /home/student/quarantine/sysctl.conf 2>/dev/null)
next_task 'Press [Enter] key to continue...'

# check /etc/fstab
echo "  "
echo "Checking /etc/fstab -home"
echo "==> Is /home nosuid shown? |"  $(cat /etc/fstab | egrep '/home.*ext4'|grep nosuid)
echo "==> Is /home nodev  shown? |"  $(cat /etc/fstab | egrep '/home.*ext4'|grep nodev)
next_task 'Press [Enter] key to continue...'

echo "  "
echo "Checking /etc/fstab -/tmp"
echo "==> Is /tmp nosuid  shown? |" $(cat /etc/fstab |grep -v /var | egrep ' /tmp.*ext4'|grep nosuid)
echo "==> Is /tmp nodev   shown? |" $(cat /etc/fstab |grep -v /var | egrep ' /tmp.*ext4'|grep nodev)
echo "==> Is /tmp noexec  shown? |" $(cat /etc/fstab |grep -v /var | egrep ' /tmp.*ext4'|grep noexec)
next_task 'Press [Enter] key to continue...'

echo "  "
echo "Checking /etc/fstab -/var/tmp"
echo "==> Is /tmp nosuid  shown? |" $(cat /etc/fstab | egrep '/var/tmp.*ext4'|grep nosuid)
echo "==> Is /tmp nodev   shown? |" $(cat /etc/fstab | egrep '/var/tmp.*ext4'|grep nodev)
echo "==> Is /tmp noexec  shown? |"  $(cat /etc/fstab | egrep '/var/tmp.*ext4'|grep noexec)
next_task 'Press [Enter] key to continue...'

# check sticky bit
echo "  "
echo "Checking sticky bits"
echo "==> Is /tmp        =1777? |" $(stat -c "%n %a" /tmp)
echo "==> Is /var/tmp    =1777? |" $(stat -c "%n %a" /var/tmp)
echo "==> Is /home/shared=1777? |" $(stat -c "%n %a" /home/shared)
next_task 'Press [Enter] key to continue...'

# check root-owned ww files
echo "  "
echo "Checking root-owned ww files"
echo "==> Is tpircs present in quarantine?     |" $(ls -la /home/student/quarantine/tpircs 2>/dev/null)
echo "==> Is tpircs NOT present in   /var/tmp? |" $(ls -la /var/tmp/tpircs 2>/dev/null)
next_task 'Press [Enter] key to continue...'

# check SUID/SGID files
echo "  "
echo "Checking SUID/SGID files"
echo "==> Is nwodtuhs present in quarantine?     |" $(ls -la /home/student/quarantine/nwodtuhs 2>/dev/null)
echo "==> Is nwodtuhs NOT present in   /var/tmp? |" $(ls -la /var/tmp/nwodtuhs 2>/dev/null)
next_task 'Press [Enter] key to continue...'

# check unowned files
echo "  "
echo "Checking unowned files"
echo "==> Is pmt present in quarantine?          |" $(ls -la /home/student/quarantine/pmt 2>/dev/null)
echo "==> Is pmt NOT present in /home/shared/tmp?|" $(ls -la /home/shared/pmt 2>/dev/null)
echo "==> Is rekcah present in quarantine?       |" $(ls -la /home/student/quarantine/rekcah 2>/dev/null)
echo "==> Is rekcah NOT present in /etc/reckah?  |" $(ls -la /etc/rekcah 2>/dev/null)
next_task 'Press [Enter] key to continue...'

# PART 2
echo "PART 2"

# check password usage policy
echo "  "
echo "Checking PASS_MAX_DAYS and PASS_WARN_AGE"
echo "==> Is PASS_MAX_DAYS=120?     |" $(cat /etc/login.defs |egrep '^PASS_MAX_DAYS')
echo "==> Is PASS_WARN_AGE_DAYS=10? |" $(cat /etc/login.defs |egrep '^PASS_WARN_AGE')
next_task 'Press [Enter] key to continue...'

# check password strength policy
echo "  "
echo "Checking password complexity"
echo "==> Is minlen=8?  |" $(cat /etc/pam.d/common-password | grep -o minlen=-*[0-9]*)
echo "==> Is lcredit=-1? |" $(cat /etc/pam.d/common-password | grep -o lcredit=-*[0-9]*)
echo "==> Is ucredit=-1? |" $(cat /etc/pam.d/common-password | grep -o ucredit=-*[0-9]*)
echo "==> Is dcredit=-1? |" $(cat /etc/pam.d/common-password | grep -o dcredit=-*[0-9]*)
echo "==> Is difok=6?    |" $(cat /etc/pam.d/common-password | grep -o difok=-*[0-9]*)
echo "==> Is remember=9? |" $(cat /etc/pam.d/common-password | grep -o remember=-*[0-9]*)
echo "==> Is retry=4?    |" $(cat /etc/pam.d/common-password | grep -o retry=-*[0-9]*)
echo "==> Is sha512?     |" $(cat /etc/pam.d/common-password | grep -o pam_unix.*sha512)
next_task 'Press [Enter] key to continue...'

# check service account login shell
echo "  "
echo "Checking service acc login shell"
echo "==> Is games    /nologin or /false?  |" $(cat /etc/passwd | grep games |cut -d: -f 1,7)
echo "==> Is man      /nologin or /false?  |" $(cat /etc/passwd | grep man |cut -d: -f 1,7)
echo "==> Is lp       /nologin or /false?  |" $(cat /etc/passwd | grep lp |cut -d: -f 1,7)
echo "==> Is mail     /nologin or /false?  |" $(cat /etc/passwd | grep mail |cut -d: -f 1,7)
echo "==> Is news     /nologin or /false?  |" $(cat /etc/passwd | grep news |cut -d: -f 1,7)
echo "==> Is uucp     /nologin or /false?  |" $(cat /etc/passwd | grep uucp |cut -d: -f 1,7)
echo "==> Is proxy    /nologin or /false?  |" $(cat /etc/passwd | grep proxy |cut -d: -f 1,7)
echo "==> Is www-data /nologin or /false?  |" $(cat /etc/passwd | grep www-data |cut -d: -f 1,7)
echo "==> Is backup   /nologin or /false?  |" $(cat /etc/passwd | grep backup |cut -d: -f 1,7)
echo "==> Is list     /nologin or /false?  |" $(cat /etc/passwd | grep list |cut -d: -f 1,7)
echo "==> Is irc      /nologin or /false?  |" $(cat /etc/passwd | grep irc |cut -d: -f 1,7)
echo "==> Is gnats    /nologin or /false?  |" $(cat /etc/passwd | grep gnats |cut -d: -f 1,7)
next_task 'Press [Enter] key to continue...'

# check usable root password
echo "  "
echo "Checking root's password usable"
echo "==> Is root P (usable)?  |" $(sudo passwd -S root |cut -d" " -f 1,2)
next_task 'Press [Enter] key to continue...'

# check acc melbourne inactivity time
echo "  "
echo "Checking perth lock time due to inactivity"
echo "==> Is perth 20 (usable)?  |" $(sudo passwd -S perth |cut -d" " -f 1,7)
next_task 'Press [Enter] key to continue...'

# check acc sydney unlocked and 90 days
echo "  "
echo "Checking account sydney"
echo "==> Is sydney P 120?  |" $(sudo passwd -S sydney |cut -d" " -f 1,2,5)
next_task 'Press [Enter] key to continue...'

# PART 3
echo "PART 3"

# check if telnet is removed
echo "  "
echo "Checking if telnet is removed"
echo "==> Is inetutils-telnetd not installed?  |" $(aptitude show inetutils-telnetd |grep State)
next_task 'Press [Enter] key to continue...'

# check if bluetooth is removed
echo "  "
echo "Checking if bluetooth is removed"
echo "==> Is bluetooth not installed?  |" $(aptitude show bluetooth |grep State)
next_task 'Press [Enter] key to continue...'

# check if biosdevname is removed
echo "  "
echo "Checking if biosdevname is removed"
echo "==> Is biosdevname not installed?  |" $(aptitude show biosdevname |grep State)
next_task 'Press [Enter] key to continue...'

# check if rsync is removed
echo "  "
echo "Checking if rsync is removed"
echo "==> Is rsync not installed?  |" $(aptitude show rsync |grep State)
next_task 'Press [Enter] key to continue...'

# check if SNMP is removed
echo "  "
echo "Checking if snmpd is removed"
echo "==> Is snmpd not installed?  |" $(aptitude show snmpd |grep State)
next_task 'Press [Enter] key to continue...'

# check if HTTP Proxy is removed
echo "  "
echo "Checking if HTTP Proxy is removed"
echo "==> Is squid3 not installed?  |" $(aptitude show squid3 |grep State)
next_task 'Press [Enter] key to continue...'


# check if apport is disabled
echo "  "
echo "Checking if apport is disabled"
echo "==> Is apport stop/waiting?  |" $(initctl list |grep apport)
next_task 'Press [Enter] key to continue...'

# check if whoopsie is disabled
echo "  "
echo "Checking if whoopsie is disabled"
echo "==> Is whoopsie stop/waiting?  |" $(initctl list |grep whoopsie)
next_task 'Press [Enter] key to continue...'

# check if cups is disabled
echo "  "
echo "Checking if cups is disabled"
echo "==> Is cups stop/waiting?  |" $(initctl list |grep cups)
next_task 'Press [Enter] key to continue...'

# check if DNS server is disabled
echo "  "
echo "Checking if bind9 is disabled"
echo "==> Is bind9 [-] ?  |" $(service --status-all 2>/dev/null |grep bind9)
next_task 'Press [Enter] key to continue...'

# check if Samba nameservice intergration server is disabled
echo "  "
echo "Checking if winbind is disabled"
echo "==> Is winbind [-] ?  |" $(service --status-all 2>/dev/null |grep winbind)
next_task 'Press [Enter] key to continue...'

# check if openBSD Internet Superserver is disabled
echo "  "
echo "Checking if openbsd-inetd is disabled"
echo "==> Is openbsd-inetd [-] ?  |" $(service --status-all 2>/dev/null |grep openbsd-inetd)
next_task 'Press [Enter] key to continue...'

# check unattended-upgrades
echo "  "
echo "Checking unattended-upgrades"
echo "==> Is security uncommented (no #) ?   |" $(cat /etc/apt/apt.conf.d/50unattended-upgrades |grep security)
echo "==> Is Update-Package-Lists 1 ?        |" $(cat /etc/apt/apt.conf.d/10periodic |grep Update-Package-Lists)
echo "==> Is Download-Upgradeable-Packages 1?|" $(cat /etc/apt/apt.conf.d/10periodic |grep Download-Upgradeable-Packages)
echo "==> Is Unattended-Upgrade 1 ?          |" $(cat /etc/apt/apt.conf.d/10periodic |grep Unattended-Upgrade)
next_task 'Press [Enter] key to continue...'

# check sshd_config
echo "  "
echo "Checking ssh remote access config"
echo "==> PermitRootLogin no?         |" $(cat /etc/ssh/sshd_config|grep ^PermitRootLogin)
echo "==> X11Forwarding no?           |" $(cat /etc/ssh/sshd_config|grep ^X11Forwarding)
echo "==> IgnoreRhosts yes?           |" $(cat /etc/ssh/sshd_config|grep ^IgnoreRhosts)
echo "==> PermitEmptyPasswords no?    |" $(cat /etc/ssh/sshd_config|grep ^PermitEmptyPasswords)
echo "==> UsePrivilegeSeparation yes? |" $(cat /etc/ssh/sshd_config|grep ^UsePrivilegeSeparation)
echo "==> LoginGraceTime 60 ?         |" $(cat /etc/ssh/sshd_config|grep ^LoginGraceTime)
echo "==> MaxAuthTries 3 ?            |" $(cat /etc/ssh/sshd_config|grep ^MaxAuthTries)
echo "==> UsePAM yes ?                |" $(cat /etc/ssh/sshd_config|grep ^UsePAM)
echo "==> UseDNS yes ?                |" $(cat /etc/ssh/sshd_config|grep ^UseDNS)
echo "==> MaxSessions 10 ?            |" $(cat /etc/ssh/sshd_config|grep ^MaxSessions)
next_task 'Press [Enter] key to continue...'

# check virtual consoles
echo "  "
echo "Checking virtual consoles tty - ACCEPT either 3 or 4 tty's"
echo "==> Is #tty start/running=3/4 ?   |" $(initctl list |grep tty |grep start |wc -l)
next_task 'Press [Enter] key to continue...'

# check jail
echo "  "
echo "Checking jail"
echo "==> jail/bin/bash present?         |" $(ls -l /home/student/jail/bin |grep bash)
echo "==> jail/bin/cat  present?         |" $(ls -l /home/student/jail/bin |grep cat)
echo "==> jail/bin/cp   present?         |" $(ls -l /home/student/jail/bin |grep cp)
echo "==> jail/bin/ls   present?         |" $(ls -l /home/student/jail/bin |grep ls)
echo "==> jail/lib/ld-linux.so.2   present?   |" $(ls -l /home/student/jail/lib |grep ld-linux.so.2)
echo "==> jail/lib/i386-linux-gnu/libacl.so.1 present?     |" $(ls -l /home/student/jail/lib/i386-linux-gnu |grep libacl.so.1)
echo "==> jail/lib/i386-linux-gnu/libattr.so.1 present?    |" $(ls -l /home/student/jail/lib/i386-linux-gnu |grep libattr.so.1)
echo "==> jail/lib/i386-linux-gnu/libc.so.6 present?       |" $(ls -l /home/student/jail/lib/i386-linux-gnu |grep libc.so.6)
echo "==> jail/lib/i386-linux-gnu/libdl.so.2 present?      |" $(ls -l /home/student/jail/lib/i386-linux-gnu |grep libdl.so.2)
echo "==> jail/lib/i386-linux-gnu/libpthread.so.0 present? |" $(ls -l /home/student/jail/lib/i386-linux-gnu |grep libpthread.so.0)
echo "==> jail/lib/i386-linux-gnu/librt.so.1 present?      |" $(ls -l /home/student/jail/lib/i386-linux-gnu |grep librt.so.1)
echo "==> jail/lib/i386-linux-gnu/libselinux.so.1 present? |" $(ls -l /home/student/jail/lib/i386-linux-gnu |grep libselinux.so.1)
echo "==> jail/lib/i386-linux-gnu/libtinfo.so.5 present?   |" $(ls -l /home/student/jail/lib/i386-linux-gnu |grep libtinfo.so.5)

# PART 4
echo "PART 4"
echo "NOTE THAT THIS PART MAY REQUIRE MANUAL INSPECTION OF THE SCRIPT"
echo "AND/OR SCREENSHOTS (IF SERVER BROKEN)"
next_task 'Press [Enter] key to continue...'

# check flush & default
echo "  "
echo "Checking flush and default"
echo "==> check flush ?   |" $(cat /home/student/firewall.sh |egrep '^iptables[[:print:]]*(--flush|-F)')
echo "==> check INPUT ?   |" $(cat /home/student/firewall.sh |egrep '^iptables[[:print:]]*(--policy|-P)[[:print:]]*INPUT[[:print:]]*DROP')
echo "==> check OUTPUT ?  |" $(cat /home/student/firewall.sh |egrep '^iptables[[:print:]]*(--policy|-P)[[:print:]]*OUTPUT[[:print:]]*DROP')
echo "==> check FORWARD ? |" $(cat /home/student/firewall.sh |egrep '^iptables[[:print:]]*(--policy|-P)[[:print:]]*FORWARD[[:print:]]*DROP')
next_task 'Press [Enter] key to continue...'

# check loopback
echo "  "
echo "Checking loopback"
echo "==> check INPUT lo ?  |" $(cat /home/student/firewall.sh |egrep '^iptables[[:print:]]*INPUT[[:print:]]*(-i)[[:print:]]*lo[[:print:]]*ACCEPT')
echo "==> check OUTPUT lo ? |" $(cat /home/student/firewall.sh |egrep '^iptables[[:print:]]*OUTPUT[[:print:]]*(-o)[[:print:]]*lo[[:print:]]*ACCEPT')
next_task 'Press [Enter] key to continue...'

# output status to a text file for each chain
sudo iptables -L INPUT > iptblin
sudo iptables -L INPUT > iptblout

# check iprange
echo "  "
echo "Checking  block iprange"
echo "==> check iprange source IP range 192.168.1.20-100?  |" $(cat iptblin |egrep 'source\ IP\ range[[:print:]]*100')
next_task 'Press [Enter] key to continue...'

# check incoming SSH
echo "  "
echo "Checking INCOMING SSH"
echo "==> check incoming SSH - INPUT chain?  |" $(cat iptblin |egrep 'tcp\ dpt:ssh\ state NEW,ESTABLISHED')
echo "==> check incoming SSH - OUTPUT chain? |" $(cat iptblout|egrep 'tcp\ spt:ssh\ state ESTABLISHED')
next_task 'Press [Enter] key to continue...'

# check outgoing SSH
echo "  "
echo "Checking OUTGOING SSH"
echo "==> check outgoing SSH - OUPUT chain? |" $(cat iptblout |egrep 'tcp\ dpt:ssh\ state NEW,ESTABLISHED')
echo "==> check outgoing SSH - INPUT chain? |" $(cat iptblin  |egrep 'tcp\ spt:ssh\ state ESTABLISHED')
next_task 'Press [Enter] key to continue...'

# check incoming HTTP
echo "  "
echo "Checking INCOMING HTTP"
echo "==> check incoming HTTP - INPUT chain?  |" $(cat iptblin |egrep 'tcp\ dpt:http\ state NEW,ESTABLISHED')
echo "==> check incoming HTTP - OUTPUT chain? |" $(cat iptblout|egrep 'tcp\ spt:http\ state ESTABLISHED')
next_task 'Press [Enter] key to continue...'

# check outgoing HTTPS
echo "  "
echo "Checking OUTGOING HTTPS"
echo "==> check outgoing HTTPS - OUPUT chain? |" $(cat iptblout |egrep 'tcp\ dpt:https\ state NEW,ESTABLISHED')
echo "==> check outgoing HTTPS - INPUT chain? |" $(cat iptblin  |egrep 'tcp\ spt:https\ state ESTABLISHED')
next_task 'Press [Enter] key to continue...'

# check incoming ftp
echo "  "
echo "Checking INCOMING FTP"
echo "==> check incoming FTP from 192.168.0.0/24 ctl port 21 INPUT  chain? |" $(cat iptblin  |egrep 'tcp\ dpt:ftp\ state NEW,ESTABLISHED')
echo "==> check incoming FTP to   192.168.0.0/24 ctl port 21 OUTPUT chain? |" $(cat iptblout |egrep 'tcp\ spt:ftp\ state ESTABLISHED')
echo "==> check incoming FTP from 192.168.0.0/24 data port 20 INPUT  chain? |" $(cat iptblin  |egrep 'tcp\ dpt:ftp-data\ state RELATED,ESTABLISHED')
echo "==> check incoming FTP to   192.168.0.0/24 data port 20 OUTPUT chain? |" $(cat iptblout |egrep 'tcp\ spt:ftp-data\ state ESTABLISHED')
echo "==> check incoming FTP from 192.168.0.0/24 data port 1024+ INPUT  chain? |" $(cat iptblin  |egrep 'dpts:1024.*state\ RELATED,ESTABLISHED')
echo "==> check incoming FTP to   192.168.0.0/24 data port 1024+ OUTPUT chain? |" $(cat iptblout |egrep 'spts:1024.*state\ ESTABLISHED')

# check outgoing DNS
echo "  "
echo "Checking OUTGOING DNS"
echo "==> check outgoing DNS/tcp - OUPUT chain? |" $(cat iptblout |egrep 'tcp\ dpt:domain\ state\ NEW,ESTABLISHED')
echo "==> check outgoing DNS/tcp - INPUT chain? |" $(cat iptblin  |egrep 'tcp\ spt:domain\ state ESTABLISHED')
echo "==> check outgoing DNS/udp - OUPUT chain? |" $(cat iptblout |egrep 'udp\ dpt:domain\ state\ NEW,ESTABLISHED')
echo "==> check outgoing DNS/udp - INPUT chain? |" $(cat iptblin  |egrep 'udp\ spt:domain\ state ESTABLISHED')
next_task 'Press [Enter] key to continue...'

# check incoming LDAP
echo "  "
echo "Checking INCOMING LDAP"
echo "==> check incoming LDAP - INPUT chain?  |" $(cat iptblin |egrep '\ dpt:ldap\ state NEW,ESTABLISHED')
echo "==> check incoming LDAP - OUTPUT chain? |" $(cat iptblout|egrep '\ spt:ldap\ state ESTABLISHED')
next_task 'Press [Enter] key to continue...'

# check persistence
echo "  "
echo "Checking persistence"
echo "if sudo iptables -L shows all the rules: GOOD"
echo "if sudo iptables -L does not show any rule: ZERO MARK for persistence"
next_task 'Press [Enter] key to continue...'


