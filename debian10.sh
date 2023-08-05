#!/bin/bash
##################
# Script name
MyScriptName='Nil'

# OpenSSH Ports
SSH_Port1='22'
SSH_Port2='143'

# Your SSH Banner
SSH_Banner='https://raw.githubusercontent.com/NiLphreakz/script/master/issue.net'

# Dropbear Ports
Dropbear_Port1='80'
Dropbear_Port2='442'

# Stunnel Ports
Stunnel_Port1='443' # through Dropbear
Stunnel_Port2='444' # through OpenSSH

# Privoxy Ports
Privoxy_Port1='3129'
Privoxy_Port2='8081'

# Squid Ports
Squid_Port1='3128'
Squid_Port2='8080'

# Server local time
MyVPS_Time='Asia/Kuala Lumpur'

function InstUpdates(){
 export DEBIAN_FRONTEND=noninteractive
 apt-get update
 apt-get upgrade -y
 
 # Removing some firewall tools that may affect other services
 apt-get remove --purge ufw firewalld -y

 
 # Installing some important machine essentials
 apt-get install nano wget curl zip unzip tar gzip p7zip-full bc rc openssl cron net-tools dnsutils dos2unix screen bzip2 ccrypt -y
 
 # Now installing all our wanted services
 apt-get install dropbear stunnel4 privoxy ca-certificates nginx ruby apt-transport-https lsb-release squid -y

 # Installing all required packages to install Webmin
 apt-get install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python dbus libxml-parser-perl -y
 apt-get install shared-mime-info jq fail2ban -y

 
 # Installing a text colorizer
 gem install lolcat

 # Trying to remove obsolette packages after installation
 apt-get autoremove -y
}

function InstWebmin(){
 # Download the webmin .deb package
 # You may change its webmin version depends on the link you've loaded in this variable(.deb file only, do not load .zip or .tar.gz file):
 WebminFile='https://raw.githubusercontent.com/NiLphreakz/script/master/webmin_1.920_all.deb'
 wget -qO webmin.deb "$WebminFile"
 
 # Installing .deb package for webmin
 dpkg --install webmin.deb
 
 rm -rf webmin.deb
 
 # Configuring webmin server config to use only http instead of https
 sed -i 's|ssl=1|ssl=0|g' /etc/webmin/miniserv.conf
 
 # Then restart to take effect
 systemctl restart webmin
}

function InstSSH(){
 # Removing some duplicated sshd server configs
 rm -f /etc/ssh/sshd_config*
 
 # Creating a SSH server config using cat eof tricks
 cat <<'MySSHConfig' > /etc/ssh/sshd_config
# My OpenSSH Server config
Port myPORT1
Port myPORT2
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
Banner /etc/issue.net
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig

 # Now we'll put our ssh ports inside of sshd_config
 sed -i "s|myPORT1|$SSH_Port1|g" /etc/ssh/sshd_config
 sed -i "s|myPORT2|$SSH_Port2|g" /etc/ssh/sshd_config

 # Download our SSH Banner
 rm -f /etc/issue.net
 wget -qO /etc/issue.net "$SSH_Banner"
 dos2unix -q /etc/issue.net

 # My workaround code to remove `BAD Password error` from passwd command, it will fix password-related error on their ssh accounts.
 sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
 sed -i 's/use_authtok //g' /etc/pam.d/common-password

 # Some command to identify null shells when you tunnel through SSH or using Stunnel, it will fix user/pass authentication error on HTTP Injector, KPN Tunnel, eProxy, SVI, HTTP Proxy Injector etc ssh/ssl tunneling apps.
 sed -i '/\/bin\/false/d' /etc/shells
 sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 echo '/usr/sbin/nologin' >> /etc/shells
 
 # Restarting openssh service
 systemctl restart ssh
 
 # Removing some duplicate config file
 rm -rf /etc/default/dropbear*
 
 # creating dropbear config using cat eof tricks
 cat <<'MyDropbear' > /etc/default/dropbear
# My Dropbear Config
NO_START=0
DROPBEAR_PORT=PORT01
DROPBEAR_EXTRA_ARGS="-p PORT02"
DROPBEAR_BANNER="/etc/issue.net"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear

 # Now changing our desired dropbear ports
 sed -i "s|PORT01|$Dropbear_Port1|g" /etc/default/dropbear
 sed -i "s|PORT02|$Dropbear_Port2|g" /etc/default/dropbear
 
 # Restarting dropbear service
 systemctl restart dropbear
}

function InsStunnel(){
 StunnelDir=$(ls /etc/default | grep stunnel | head -n1)

 # Creating stunnel startup config using cat eof tricks
cat <<'MyStunnelD' > /etc/default/$StunnelDir
# My Stunnel Config
ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
BANNER="/etc/issue.net"
PPP_RESTART=0
# RLIMITS="-n 4096 -d unlimited"
RLIMITS=""
MyStunnelD

 # Removing all stunnel folder contents
 rm -rf /etc/stunnel/*
 
 # Creating stunnel certifcate using openssl
 openssl req -new -x509 -days 9999 -nodes -subj "/C=ID/ST=Jawa Timur/L=Lamongan/O=$MyScriptName/OU=$MyScriptName/CN=$MyScriptName" -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem &> /dev/null
##  > /dev/null 2>&1

 # Creating stunnel server config
 cat <<'MyStunnelC' > /etc/stunnel/stunnel.conf
# My Stunnel Config
pid = /var/run/stunnel.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[dropbear]
accept = Stunnel_Port1
connect = 127.0.0.1:80

[openssh]
accept = Stunnel_Port2
connect = 127.0.0.1:22
MyStunnelC

 # setting stunnel ports
 sed -i "s|Stunnel_Port1|$Stunnel_Port1|g" /etc/stunnel/stunnel.conf
 sed -i "s|dropbear_port_c|$(netstat -tlnp | grep -i dropbear | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf
 sed -i "s|Stunnel_Port2|$Stunnel_Port2|g" /etc/stunnel/stunnel.conf
 sed -i "s|openssh_port_c|$(netstat -tlnp | grep -i ssh | awk '{print $4}' | cut -d: -f2 | xargs | awk '{print $2}' | head -n1)|g" /etc/stunnel/stunnel.conf

 # Restarting stunnel service
 systemctl restart $StunnelDir
}

function InsProxy(){

 # Removing Duplicate privoxy config
 rm -rf /etc/privoxy/config*
 
 # Creating Privoxy server config using cat eof tricks
 cat <<'myPrivoxy' > /etc/privoxy/config
# My Privoxy Server Config
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 0.0.0.0:Privoxy_Port1
listen-address 0.0.0.0:Privoxy_Port2
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
keep-alive-timeout 5
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 IP-ADDRESS
myPrivoxy

 # Setting machine's IP Address inside of our privoxy config(security that only allows this machine to use this proxy server)
 sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/privoxy/config
 
 # Setting privoxy ports
 sed -i "s|Privoxy_Port1|$Privoxy_Port1|g" /etc/privoxy/config
 sed -i "s|Privoxy_Port2|$Privoxy_Port2|g" /etc/privoxy/config

 # Removing Duplicate Squid config
 rm -rf /etc/squid/squid.con*
 
 # Creating Squid server config using cat eof tricks
 cat <<'mySquid' > /etc/squid/squid.conf
# My Squid Proxy Server Config
acl VPN dst IP-ADDRESS/32
http_access allow VPN
http_access deny all 
http_port 0.0.0.0:Squid_Port1
http_port 0.0.0.0:Squid_Port2
coredump_dir /var/spool/squid
dns_nameservers 8.8.8.8 8.8.4.4
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname Nil
mySquid

 # Setting machine's IP Address inside of our Squid config(security that only allows this machine to use this proxy server)
 sed -i "s|IP-ADDRESS|$IPADDR|g" /etc/squid/squid.conf
 
 # Setting squid ports
 sed -i "s|Squid_Port1|$Squid_Port1|g" /etc/squid/squid.conf
 sed -i "s|Squid_Port2|$Squid_Port2|g" /etc/squid/squid.conf

 # Starting Proxy server
 echo -e "Restarting proxy server..."
 systemctl restart squid
}

function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipv4.icanhazip.com )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
} 
IPADDR="$(ip_address)"

function ConfStartup(){
 # Daily reboot time of our machine
 # For cron commands, visit https://crontab.guru
 echo -e "0 4\t* * *\troot\treboot" > /etc/cron.d/b_reboot_job

 # Creating directory for startup script
 rm -rf /etc/Nil
 mkdir -p /etc/Nil
 chmod -R 755 /etc/Nil
 
 # Creating startup script using cat eof tricks
 cat <<'EOFSH' > /etc/Nil/startup.sh
#!/bin/bash
# Setting server local time
ln -fs /usr/share/zoneinfo/MyVPS_Time /etc/localtime

# Prevent DOS-like UI when installing using APT (Disabling APT interactive dialog)
export DEBIAN_FRONTEND=noninteractive

# Allowing ALL TCP ports for our machine (Simple workaround for policy-based VPS)
iptables -A INPUT -s $(wget -4qO- http://ipinfo.io/ip) -p tcp -m multiport --dport 1:65535 -j ACCEPT

# Allowing OpenVPN to Forward traffic
/bin/bash /etc/openvpn/openvpn.bash

# Deleting Expired SSH Accounts
/usr/local/sbin/delete_expired &> /dev/null
exit 0
EOFSH
 chmod +x /etc/Nil/startup.sh
 
 # Setting server local time every time this machine reboots
 sed -i "s|MyVPS_Time|$MyVPS_Time|g" /etc/Nil/startup.sh

 # 
 rm -rf /etc/sysctl.d/99*

 # Setting our startup script to run every machine boots 
 cat <<'FordServ' > /etc/systemd/system/Nil.service
[Unit]
Description=Nil
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/Nil/startup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
FordServ
 chmod +x /etc/systemd/system/Nil.service
 systemctl daemon-reload
 systemctl start Nil
 systemctl enable Nil &> /dev/null
 systemctl enable fail2ban &> /dev/null
 systemctl start fail2ban &> /dev/null

 # Rebooting cron service
 systemctl restart cron
 systemctl enable cron
}


function ConfMenu(){
echo -e " Creating Menu scripts.."

cd /usr/local/sbin/
rm -rf {accounts,base-ports,base-ports-wc,base-script,bench-network,clearcache,connections,create,create_random,create_trial,delete_expired,diagnose,edit_dropbear,edit_openssh,edit_openvpn,edit_ports,edit_squid3,edit_stunnel4,locked_list,menu,options,ram,reboot_sys,reboot_sys_auto,restart_services,server,set_multilogin_autokill,set_multilogin_autokill_lib,show_ports,speedtest,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock}

wget -O menu "https://raw.githubusercontent.com/NiLphreakz/script/master/menu.sh"
	wget -O user-add "https://raw.githubusercontent.com/NiLphreakz/script/master/user-add.sh"
	wget -O trial "https://raw.githubusercontent.com/NiLphreakz/script/master/trial.sh"
	wget -O user-del "https://raw.githubusercontent.com/NiLphreakz/script/master/hapus.sh"
	wget -O user-login "https://raw.githubusercontent.com/NiLphreakz/script/master/user-login.sh"
	wget -O user-list "https://raw.githubusercontent.com/NiLphreakz/script/master/user-list.sh"
	wget -O expdel "https://raw.githubusercontent.com/NiLphreakz/script/master/delexp.sh"
	wget -O resvis "https://raw.githubusercontent.com/NiLphreakz/script/master/resvis.sh"
	wget -O speedtest "https://raw.githubusercontent.com/NiLphreakz/script/master/speedtest_cli.py"
	wget -O info "https://raw.githubusercontent.com/NiLphreakz/script/master/info.sh"
	wget -O about "https://raw.githubusercontent.com/NiLphreakz/script/master/about.sh"
chmod +x ./*
dos2unix ./* &> /dev/null
sed -i 's|/etc/squid/squid.conf|/etc/privoxy/config|g' ./*
sed -i 's|http_port|listen-address|g' ./*
cd ~
}

function ScriptMessage(){
 echo -e " $MyScriptName VPS Installer"
 echo -e ""
 echo -e ""
 echo -e ""
}

 # First thing to do is check if this machine is Debian
 source /etc/os-release
if [[ "$ID" != 'debian' ]]; then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script is for Debian only, exting..." 
 exit 1
fi

 # Now check if our machine is in root user, if not, this script exits
 # If you're on sudo user, run `sudo su -` first before running this script
 if [[ $EUID -ne 0 ]];then
 ScriptMessage
 echo -e "[\e[1;31mError\e[0m] This script must be run as root, exiting..."
 exit 1
fi

 # Begin Installation by Updating and Upgrading machine and then Installing all our wanted packages/services to be install.
 ScriptMessage
 sleep 2
 InstUpdates
 
 # Configure OpenSSH and Dropbear
 echo -e "Configuring ssh..."
 InstSSH
 
 # Configure Stunnel
 echo -e "Configuring stunnel..."
 InsStunnel
 
 # Configure Webmin
 echo -e "Configuring webmin..."
 InstWebmin
 
 # Configure Squid
 echo -e "Configuring proxy..."
 InsProxy
 
 # Some assistance and startup scripts
 ConfStartup

 # VPS Menu script v1.0
 ConfMenu
 
 # Setting server local time
 ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime
 
 clear
 cd ~
 
  # Running screenfetch
 wget -O /usr/bin/screenfetch "https://raw.githubusercontent.com/NiLphreakz/script/master/screenfetch"
 chmod +x /usr/bin/screenfetch
 echo "/bin/bash /etc/openvpn/openvpn.bash" >> .profile
 echo "clear" >> .profile
 echo "screenfetch" >> .profile

 # info
	echo "~Nil~"
	echo "Autoscript Include:" | tee log-install.txt
	echo "===========================================" | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "Service"  | tee -a log-install.txt
	echo "-------"  | tee -a log-install.txt
	echo "OpenSSH  : 22, 143"  | tee -a log-install.txt
	echo "Dropbear : 80, 442"  | tee -a log-install.txt
	echo "SSL      : 443, 444"  | tee -a log-install.txt
	echo "Squid3   : 8080, 3128 (limit to IP SSH)"  | tee -a log-install.txt
	echo "badvpn   : badvpn-udpgw port 7300"  | tee -a log-install.txt
	echo "nginx    : 81"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "Script"  | tee -a log-install.txt
	echo "------"  | tee -a log-install.txt
	echo "menu         (Menampilkan daftar perintah yang tersedia)"  | tee -a log-install.txt
	echo "user-add     (Membuat Akaun SSH)"  | tee -a log-install.txt
	echo "trial        (Membuat Akaun Trial)"  | tee -a log-install.txt
	echo "user-del     (Menghapus Akaun SSH)"  | tee -a log-install.txt
	echo "user-login   (Cek User Login)"  | tee -a log-install.txt
	echo "user-list    (Cek Member SSH)"  | tee -a log-install.txt
	echo "expdel       (Delete User expired)"  | tee -a log-install.txt
	echo "resvis       (Restart Service Dropbear, Webmin, Squid3, OpenVPN dan SSH)"  | tee -a log-install.txt
	echo "reboot       (Reboot VPS)"  | tee -a log-install.txt
	echo "speedtest    (Speedtest VPS)"  | tee -a log-install.txt
	echo "info         (Menampilkan Informasi Sistem)"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "Fitur lain"  | tee -a log-install.txt
	echo "----------"  | tee -a log-install.txt
	echo "Webmin   : http://$MYIP:10000/"  | tee -a log-install.txt
	echo "Timezone : Asia/Kuala Lumpur (GMT +8)"  | tee -a log-install.txt
	echo "IPv6     : [off]"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "Thanks To"  | tee -a log-install.txt
	echo "---------"  | tee -a log-install.txt
	echo "Allah"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "Goup"  | tee -a log-install.txt
	echo "----"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "VPS AUTO REBOOT SETIAP JAM 00.00 UTC"  | tee -a log-install.txt
	echo "Log Installation --> /root/log-install.txt"  | tee -a log-install.txt
	echo ""  | tee -a log-install.txt
	echo "==========================================="  | tee -a log-install.txt
	cd


echo " Please Reboot your VPS"

 # Clearing all logs from installation
 rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog

rm -f debian10.sh
cd
