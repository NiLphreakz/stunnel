● Feature script Auto-Install :

* OpenSSH, port : 22, 143
* Dropbear, port : 80, 444
* SSL/TLS SSH, port : 443
* Squid3, port : 8080, 3128 (limit to IP SSH)
* Badvpn : badvpn-udpgw port 7300
* Webmin : http://IPVPS:10000/
* Nginx : 81
* Script menu : untuk menampilkan menu
* Script user-add : membuat akaun SSH
* Script trial : membuat akaun trial
* Script user-del : menghapus akaun SSH
* Script user-login : mengecek user login
* Script user-list : mengecek member
* Script resvis : restart service dropbear, webmin, squid3, openvpn dan ssh
* Script speedtest : speedtest VPS
* Script about : informasi tentang script auto install
* Sebelum script Auto Install berikut diinstall, pastikan bahwa VPS Anda mempunyai OS Debian 10 64 Bit. Pastikan juga VPS masih fresh.

● Cooy paste perintah berikut lalu tekan enter
* apt-get install ca-certificates
* wget https://raw.githubusercontent.com/NiLphreakz/stunnel/master/debian10.sh && chmod +x debian10.sh && ./debian10.sh
